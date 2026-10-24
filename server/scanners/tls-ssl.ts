import tls from 'tls';
import { ScannerFinding } from './types.js';

interface TlsScanResult {
  findings: Omit<ScannerFinding, 'id' | 'scanJobId' | 'scannerRunId' | 'firstSeenAt' | 'createdAt'>[];
  certDetails?: {
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    daysRemaining: number;
    protocol: string;
    cipher: string;
    authorized: boolean;
  };
}

export async function scanTlsSsl(hostname: string, port = 443): Promise<TlsScanResult> {
  const findings: TlsScanResult['findings'] = [];

  return new Promise<TlsScanResult>((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: port,
        servername: hostname, // SNI support
        rejectUnauthorized: false, // Allow inspection of expired/untrusted certs to report them
        timeout: 9000,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol() || 'Unknown';
          const cipher = socket.getCipher();
          const authorized = socket.authorized;
          const authError = socket.authorizationError;

          if (!cert || !cert.subject) {
            findings.push({
              scannerName: 'TLS/SSL Certificate Inspector (testssl)',
              title: 'No TLS Certificate Presented by Server',
              category: 'SSL/TLS',
              severity: 'HIGH',
              originalSeverity: 'HIGH',
              confidence: 'CERTAIN',
              verificationStatus: 'CONFIRMED',
              description: `The server at ${hostname}:${port} accepted a TLS connection but did not supply a readable peer certificate.`,
              affectedUrl: `https://${hostname}:${port}`,
              evidence: { details: { protocol, port } },
              remediation: 'Ensure an active X.509 TLS certificate is bound to the server configuration.',
              fingerprint: `tls_no_cert_${hostname}`,
              cwe: 'CWE-295: Improper Certificate Validation',
              owaspCategory: 'A02:2021-Cryptographic Failures',
            });
            socket.destroy();
            resolve({ findings });
            return;
          }

          const validToDate = new Date(cert.valid_to);
          const now = new Date();
          const msRemaining = validToDate.getTime() - now.getTime();
          const daysRemaining = Math.floor(msRemaining / (1000 * 60 * 60 * 24));

          const formatCertField = (field: any): string => {
            if (!field) return '';
            if (typeof field === 'string') return field;
            if (Array.isArray(field)) return field.join(', ');
            if (typeof field === 'object') {
              if (field.CN) return Array.isArray(field.CN) ? field.CN.join(', ') : String(field.CN);
              if (field.O) return Array.isArray(field.O) ? field.O.join(', ') : String(field.O);
              return Object.values(field).flat().join(', ');
            }
            return String(field);
          };

          const certSubject: string = formatCertField(cert.subject);
          const certIssuer: string = formatCertField(cert.issuer);

          // 1. Certificate Validity / Expiry Check
          if (daysRemaining < 0) {
            findings.push({
              scannerName: 'TLS/SSL Certificate Inspector (testssl)',
              title: 'Expired TLS Certificate in Use',
              category: 'SSL/TLS',
              severity: 'CRITICAL',
              originalSeverity: 'CRITICAL',
              confidence: 'CERTAIN',
              verificationStatus: 'CONFIRMED',
              description: `The TLS certificate for ${hostname} expired on ${cert.valid_to} (${Math.abs(daysRemaining)} days ago). All major web browsers block user access with severe security warnings.`,
              affectedUrl: `https://${hostname}:${port}`,
              evidence: {
                details: { validTo: cert.valid_to, daysRemaining, issuer: certIssuer },
              },
              remediation: 'Immediately renew and deploy an updated valid TLS certificate.',
              fingerprint: `tls_expired_cert_${hostname}`,
              cwe: 'CWE-298: Improper Validation of Certificate Expiration',
              owaspCategory: 'A02:2021-Cryptographic Failures',
            });
          } else if (daysRemaining < 15) {
            findings.push({
              scannerName: 'TLS/SSL Certificate Inspector (testssl)',
              title: `TLS Certificate Imminently Expiring (${daysRemaining} Days Left)`,
              category: 'SSL/TLS',
              severity: 'HIGH',
              originalSeverity: 'HIGH',
              confidence: 'CERTAIN',
              verificationStatus: 'CONFIRMED',
              description: `The TLS certificate expires in ${daysRemaining} days on ${cert.valid_to}. Immediate action is needed to prevent service downtime.`,
              affectedUrl: `https://${hostname}:${port}`,
              evidence: {
                details: { validTo: cert.valid_to, daysRemaining, issuer: certIssuer },
              },
              remediation: 'Renew and reload certificate on the server before expiry.',
              fingerprint: `tls_expiring_soon_${hostname}`,
              cwe: 'CWE-298: Improper Validation of Certificate Expiration',
              owaspCategory: 'A02:2021-Cryptographic Failures',
            });
          } else if (daysRemaining < 45) {
            findings.push({
              scannerName: 'TLS/SSL Certificate Inspector (testssl)',
              title: `TLS Certificate Renewal Recommended (${daysRemaining} Days Left)`,
              category: 'SSL/TLS',
              severity: 'MEDIUM',
              originalSeverity: 'MEDIUM',
              confidence: 'CERTAIN',
              verificationStatus: 'CONFIRMED',
              description: `The certificate is valid for another ${daysRemaining} days. Routine renewal should be verified.`,
              affectedUrl: `https://${hostname}:${port}`,
              evidence: {
                details: { validTo: cert.valid_to, daysRemaining, issuer: certIssuer },
              },
              remediation: 'Verify ACME / Certbot automated renewal pipeline is operational.',
              fingerprint: `tls_renewal_window_${hostname}`,
              cwe: 'CWE-298: Certificate Expiration Window',
              owaspCategory: 'A02:2021-Cryptographic Failures',
            });
          }

          // 2. Trust & Authorization Validation
          if (!authorized && authError) {
            const errString = typeof authError === 'string' ? authError : (authError as Error)?.message || String(authError);
            const isSelfSigned = errString.toLowerCase().includes('self signed') || errString.toLowerCase().includes('depth_zero_self_signed');
            findings.push({
              scannerName: 'TLS/SSL Certificate Inspector (testssl)',
              title: isSelfSigned ? 'Self-Signed TLS Certificate Detected' : 'Untrusted Certificate Chain Authority',
              category: 'SSL/TLS',
              severity: isSelfSigned ? 'HIGH' : 'HIGH',
              originalSeverity: 'HIGH',
              confidence: 'CERTAIN',
              verificationStatus: 'CONFIRMED',
              description: `The certificate trust verification failed: "${errString}". Browsers will display security interstitial warnings and block requests unless manually bypassed.`,
              affectedUrl: `https://${hostname}:${port}`,
              evidence: {
                details: { authError: errString, issuer: certIssuer, subject: certSubject },
              },
              remediation: 'Replace with an authorized certificate issued by a recognized Certificate Authority (CA) such as Let\'s Encrypt, DigiCert, or Google Trust Services.',
              fingerprint: `tls_untrusted_ca_${hostname}`,
              cwe: 'CWE-295: Improper Certificate Validation',
              owaspCategory: 'A02:2021-Cryptographic Failures',
            });
          }

          // 3. Subject Alternative Name (SAN) Host Matching
          if (cert.subjectaltname) {
            const sans = cert.subjectaltname.split(',').map(s => s.trim().replace(/^DNS:/i, ''));
            const matchesSan = sans.some(san => {
              if (san === hostname) return true;
              if (san.startsWith('*.')) {
                const domainSuffix = san.slice(2);
                return hostname.endsWith(domainSuffix);
              }
              return false;
            });

            if (!matchesSan && certSubject !== hostname) {
              findings.push({
                scannerName: 'TLS/SSL Certificate Inspector (testssl)',
                title: 'Certificate Common Name (CN) / SAN Mismatch',
                category: 'SSL/TLS',
                severity: 'HIGH',
                originalSeverity: 'HIGH',
                confidence: 'CERTAIN',
                verificationStatus: 'CONFIRMED',
                description: `Certificate does not match host "${hostname}". Listed SANs: [${sans.slice(0, 4).join(', ')}]. This produces ERR_CERT_COMMON_NAME_INVALID errors.`,
                affectedUrl: `https://${hostname}:${port}`,
                evidence: {
                  details: { hostname, sans, cn: certSubject },
                },
                remediation: `Reissue the certificate including "${hostname}" in the Subject Alternative Name (SAN) list.`,
                fingerprint: `tls_san_mismatch_${hostname}`,
                cwe: 'CWE-297: Improper Validation of Certificate with Host Mismatch',
                owaspCategory: 'A02:2021-Cryptographic Failures',
              });
            }
          }

          // 4. Protocol & Cipher Checks
          if (protocol.includes('TLSv1.0') || protocol.includes('TLSv1.1') || protocol.includes('SSL')) {
            findings.push({
              scannerName: 'TLS/SSL Certificate Inspector (testssl)',
              title: `Deprecated Insecure Protocol Version Negotiated (${protocol})`,
              category: 'SSL/TLS',
              severity: 'HIGH',
              originalSeverity: 'HIGH',
              confidence: 'CERTAIN',
              verificationStatus: 'CONFIRMED',
              description: `Negotiated ${protocol}. Legacy TLS 1.0, 1.1 and SSL 2.0/3.0 have proven cryptographic flaws (POODLE, BEAST) and are deprecated across NIST, PCI-DSS, and browser vendors.`,
              affectedUrl: `https://${hostname}:${port}`,
              evidence: { details: { protocol, cipher: cipher?.name } },
              remediation: 'Disable TLS 1.0 and TLS 1.1 in web server configs. Require TLS 1.2 and TLS 1.3 only.',
              fingerprint: `tls_deprecated_proto_${hostname}`,
              cwe: 'CWE-326: Inadequate Encryption Strength',
              owaspCategory: 'A02:2021-Cryptographic Failures',
            });
          }

          // Check for weak ciphers
          const cipherName = cipher?.name || '';
          const isWeakCipher = /RC4|DES|3DES|MD5|EXPORT|NULL|anon/i.test(cipherName);
          if (isWeakCipher) {
            findings.push({
              scannerName: 'TLS/SSL Certificate Inspector (testssl)',
              title: `Weak or Broken Cipher Suite Negotiated (${cipherName})`,
              category: 'SSL/TLS',
              severity: 'HIGH',
              originalSeverity: 'HIGH',
              confidence: 'CERTAIN',
              verificationStatus: 'CONFIRMED',
              description: `The cipher suite "${cipherName}" uses legacy or compromised primitives. Attackers can decrypt recorded traffic or conduct plaintext recovery attacks.`,
              affectedUrl: `https://${hostname}:${port}`,
              evidence: { details: { cipher: cipherName, standard: cipher?.standardName } },
              remediation: 'Enforce modern AEAD cipher suites (ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384, CHACHA20-POLY1305).',
              fingerprint: `tls_weak_cipher_${hostname}`,
              cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
              owaspCategory: 'A02:2021-Cryptographic Failures',
            });
          }

          socket.destroy();
          resolve({
            findings,
            certDetails: {
              subject: certSubject,
              issuer: certIssuer,
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              daysRemaining,
              protocol,
              cipher: cipherName,
              authorized,
            },
          });
        } catch (err: any) {
          socket.destroy();
          resolve({ findings });
        }
      }
    );

    socket.on('error', (err) => {
      // If port 443 didn't respond or rejected TLS
      findings.push({
        scannerName: 'TLS/SSL Certificate Inspector (testssl)',
        title: 'TLS Handshake Failed or Unsupported on Target Port',
        category: 'SSL/TLS',
        severity: 'MEDIUM',
        originalSeverity: 'MEDIUM',
        confidence: 'CERTAIN',
        verificationStatus: 'POTENTIAL',
        description: `Failed to complete TLS handshake with ${hostname}:${port}: ${err.message}`,
        affectedUrl: `https://${hostname}:${port}`,
        evidence: { details: { error: err.message, port } },
        remediation: 'Ensure the endpoint is properly configured to terminate HTTPS/TLS.',
        fingerprint: `tls_handshake_error_${hostname}`,
        cwe: 'CWE-319: Cleartext Transmission',
        owaspCategory: 'A02:2021-Cryptographic Failures',
      });
      socket.destroy();
      resolve({ findings });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ findings });
    });
  });
}
