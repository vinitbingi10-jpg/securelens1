import http from 'http';
import https from 'https';
import { ScannerFinding } from './types.js';

interface HeaderScanResult {
  findings: Omit<ScannerFinding, 'id' | 'scanJobId' | 'scannerRunId' | 'firstSeenAt' | 'createdAt'>[];
  headers: Record<string, string>;
  statusCode: number;
}

export async function scanHttpHeaders(targetUrl: string): Promise<HeaderScanResult> {
  const urlObj = new URL(targetUrl);
  const client = urlObj.protocol === 'https:' ? https : http;

  const findings: HeaderScanResult['findings'] = [];

  const headers = await new Promise<Record<string, string>>((resolve, reject) => {
    const req = client.request(
      targetUrl,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'SecureLens-Security-Auditor/1.0 (+https://securelens.local/bot)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        timeout: 10000,
      },
      (res) => {
        const rawHeaders: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (Array.isArray(value)) {
            rawHeaders[key.toLowerCase()] = value.join(', ');
          } else if (value) {
            rawHeaders[key.toLowerCase()] = value;
          }
        }
        res.resume(); // discard body
        resolve(rawHeaders);
      }
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Connection timed out while fetching HTTP response headers'));
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.end();
  });

  const hsts = headers['strict-transport-security'];
  const csp = headers['content-security-policy'];
  const xfo = headers['x-frame-options'];
  const xcto = headers['x-content-type-options'];
  const referrer = headers['referrer-policy'];
  const permissions = headers['permissions-policy'] || headers['feature-policy'];
  const server = headers['server'];
  const poweredBy = headers['x-powered-by'];
  const setCookie = headers['set-cookie'];

  // 1. HSTS Check (Only relevant for HTTPS targets)
  if (urlObj.protocol === 'https:') {
    if (!hsts) {
      findings.push({
        scannerName: 'HTTP Security Headers Inspector',
        title: 'Missing HTTP Strict Transport Security (HSTS)',
        category: 'Headers & Policy',
        severity: 'HIGH',
        originalSeverity: 'HIGH',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'The target host is served over HTTPS but does not return a Strict-Transport-Security header. This exposes visitors to man-in-the-middle SSL-stripping attacks on subsequent connections.',
        affectedUrl: targetUrl,
        evidence: {
          rawHeader: 'Strict-Transport-Security: [Absent]',
        },
        remediation: 'Configure the server to return: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        fingerprint: `hsts_missing_${urlObj.host}`,
        cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
        owaspCategory: 'A05:2021-Security Misconfiguration',
      });
    } else {
      // Check if max-age is sufficiently long (> 6 months / 15768000s)
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 15768000) {
        findings.push({
          scannerName: 'HTTP Security Headers Inspector',
          title: 'HSTS Max-Age Duration Too Short',
          category: 'Headers & Policy',
          severity: 'LOW',
          originalSeverity: 'LOW',
          confidence: 'CERTAIN',
          verificationStatus: 'CONFIRMED',
          description: `Strict-Transport-Security max-age is set to ${maxAge} seconds (less than the recommended 180 days / 15768000s).`,
          affectedUrl: targetUrl,
          evidence: { rawHeader: `Strict-Transport-Security: ${hsts}` },
          remediation: 'Increase max-age to at least 31536000 (1 year).',
          fingerprint: `hsts_short_maxage_${urlObj.host}`,
          cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
          owaspCategory: 'A05:2021-Security Misconfiguration',
        });
      }
    }
  }

  // 2. CSP Check
  if (!csp) {
    findings.push({
      scannerName: 'HTTP Security Headers Inspector',
      title: 'Missing Content Security Policy (CSP)',
      category: 'Headers & Policy',
      severity: 'HIGH',
      originalSeverity: 'HIGH',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: 'The HTTP response is missing a Content-Security-Policy header. CSP provides defense-in-depth against Cross-Site Scripting (XSS), clickjacking, and unauthorized resource injection.',
      affectedUrl: targetUrl,
      evidence: { rawHeader: 'Content-Security-Policy: [Absent]' },
      remediation: "Deploy a Content-Security-Policy header defining trusted sources for scripts, styles, objects, and frame-ancestors.",
      fingerprint: `csp_missing_${urlObj.host}`,
      cwe: 'CWE-1021: Improper Restriction of Rendered UI Layers or Scripts',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  } else if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'") || csp.includes('*')) {
    findings.push({
      scannerName: 'HTTP Security Headers Inspector',
      title: 'Permissive Content Security Policy Directives Detected',
      category: 'Headers & Policy',
      severity: 'MEDIUM',
      originalSeverity: 'MEDIUM',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: "The Content-Security-Policy contains wildcard '*' or permissive keywords ('unsafe-inline' or 'unsafe-eval'), significantly weakening XSS defense.",
      affectedUrl: targetUrl,
      evidence: { rawHeader: `Content-Security-Policy: ${csp.substring(0, 200)}...` },
      remediation: 'Migrate to nonce-based or hash-based CSP and eliminate unsafe-inline/unsafe-eval keywords.',
      fingerprint: `csp_weak_${urlObj.host}`,
      cwe: 'CWE-1021: Weak Policy Configuration',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  // 3. X-Content-Type-Options Check
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    findings.push({
      scannerName: 'HTTP Security Headers Inspector',
      title: 'Missing X-Content-Type-Options: nosniff Header',
      category: 'Headers & Policy',
      severity: 'LOW',
      originalSeverity: 'LOW',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: 'The X-Content-Type-Options header is missing or not set to "nosniff". Without this header, older and MIME-sniffing browsers may execute non-executable MIME types as HTML/JavaScript.',
      affectedUrl: targetUrl,
      evidence: { rawHeader: `X-Content-Type-Options: ${xcto || '[Absent]'}` },
      remediation: 'Add header: X-Content-Type-Options: nosniff',
      fingerprint: `xcto_missing_${urlObj.host}`,
      cwe: 'CWE-693: Protection Mechanism Failure',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  // 4. X-Frame-Options Check (Clickjacking)
  if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
    findings.push({
      scannerName: 'HTTP Security Headers Inspector',
      title: 'Missing Clickjacking Defense (X-Frame-Options or frame-ancestors)',
      category: 'Headers & Policy',
      severity: 'MEDIUM',
      originalSeverity: 'MEDIUM',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: 'Neither X-Frame-Options (DENY or SAMEORIGIN) nor CSP frame-ancestors directive was detected. Third-party sites could frame this page to orchestrate Clickjacking / UI Redressing attacks.',
      affectedUrl: targetUrl,
      evidence: { rawHeader: `X-Frame-Options: ${xfo || '[Absent]'}` },
      remediation: "Set 'X-Frame-Options: SAMEORIGIN' and declare 'Content-Security-Policy: frame-ancestors \\'self\\''",
      fingerprint: `xfo_missing_${urlObj.host}`,
      cwe: 'CWE-1021: Improper Restriction of Rendered UI Layers or Frames',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  // 5. Referrer-Policy Check
  if (!referrer) {
    findings.push({
      scannerName: 'HTTP Security Headers Inspector',
      title: 'Missing Referrer-Policy Header',
      category: 'Headers & Policy',
      severity: 'LOW',
      originalSeverity: 'LOW',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: 'No Referrer-Policy header is declared. Browsers may send full query parameters and URLs containing sensitive tokens in the Referer request header when navigating to external links.',
      affectedUrl: targetUrl,
      evidence: { rawHeader: 'Referrer-Policy: [Absent]' },
      remediation: 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
      fingerprint: `referrer_missing_${urlObj.host}`,
      cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  // 6. Permissions-Policy Check
  if (!permissions) {
    findings.push({
      scannerName: 'HTTP Security Headers Inspector',
      title: 'Missing Permissions-Policy Header',
      category: 'Headers & Policy',
      severity: 'INFO',
      originalSeverity: 'INFO',
      confidence: 'CERTAIN',
      verificationStatus: 'INFORMATIONAL',
      description: 'The Permissions-Policy header is absent. Declaring this header allows administrators to restrict access to sensitive browser features (e.g., camera, microphone, geolocation, usb).',
      affectedUrl: targetUrl,
      evidence: { rawHeader: 'Permissions-Policy: [Absent]' },
      remediation: 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()',
      fingerprint: `permissions_missing_${urlObj.host}`,
      cwe: 'CWE-693: Protection Mechanism Failure',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  // 7. Information Leaking Headers (Server, X-Powered-By)
  if (server && (/\d/.test(server) || server.toLowerCase().includes('apache') || server.toLowerCase().includes('nginx') || server.toLowerCase().includes('microsoft'))) {
    findings.push({
      scannerName: 'HTTP Security Headers Inspector',
      title: 'Web Server Version Disclosure in Server Header',
      category: 'Information Disclosure',
      severity: 'LOW',
      originalSeverity: 'LOW',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: `The Server response header discloses backend software information: "${server}". Attackers use exact version strings to target known unpatched CVEs.`,
      affectedUrl: targetUrl,
      evidence: { rawHeader: `Server: ${server}` },
      remediation: 'Configure server to suppress or tokenize the Server banner (e.g. server_tokens off in Nginx, ServerTokens Prod in Apache).',
      fingerprint: `server_banner_${urlObj.host}`,
      cwe: 'CWE-200: Exposure of Sensitive Information',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  if (poweredBy) {
    findings.push({
      scannerName: 'HTTP Security Headers Inspector',
      title: 'Application Framework Disclosure (X-Powered-By)',
      category: 'Information Disclosure',
      severity: 'LOW',
      originalSeverity: 'LOW',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: `The X-Powered-By header discloses underlying backend framework: "${poweredBy}".`,
      affectedUrl: targetUrl,
      evidence: { rawHeader: `X-Powered-By: ${poweredBy}` },
      remediation: 'Remove the X-Powered-By header in application configuration.',
      fingerprint: `x_powered_by_${urlObj.host}`,
      cwe: 'CWE-200: Exposure of Sensitive Information',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  // 8. Cookie Security Attributes (if set-cookie present)
  if (setCookie) {
    const isSecure = setCookie.toLowerCase().includes('secure');
    const isHttpOnly = setCookie.toLowerCase().includes('httponly');
    const hasSameSite = setCookie.toLowerCase().includes('samesite');

    if (!isSecure && urlObj.protocol === 'https:') {
      findings.push({
        scannerName: 'HTTP Security Headers Inspector',
        title: 'Cookie Missing Secure Flag',
        category: 'Headers & Policy',
        severity: 'MEDIUM',
        originalSeverity: 'MEDIUM',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'Set-Cookie header does not specify the Secure attribute. The cookie may be transmitted over unencrypted HTTP connections in plain text.',
        affectedUrl: targetUrl,
        evidence: { rawHeader: `Set-Cookie: ${setCookie.substring(0, 100)}...` },
        remediation: 'Append the "; Secure" flag to all cookies set over HTTPS.',
        fingerprint: `cookie_insecure_${urlObj.host}`,
        cwe: 'CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute',
        owaspCategory: 'A05:2021-Security Misconfiguration',
      });
    }

    if (!isHttpOnly) {
      findings.push({
        scannerName: 'HTTP Security Headers Inspector',
        title: 'Cookie Missing HttpOnly Flag',
        category: 'Headers & Policy',
        severity: 'LOW',
        originalSeverity: 'LOW',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'Set-Cookie does not specify the HttpOnly attribute. Client-side scripts can access this cookie value via document.cookie, increasing session hijack risk during XSS.',
        affectedUrl: targetUrl,
        evidence: { rawHeader: `Set-Cookie: ${setCookie.substring(0, 100)}...` },
        remediation: 'Append "; HttpOnly" to all authentication and session identifiers.',
        fingerprint: `cookie_no_httponly_${urlObj.host}`,
        cwe: 'CWE-1004: Sensitive Cookie Without HttpOnly Flag',
        owaspCategory: 'A05:2021-Security Misconfiguration',
      });
    }

    if (!hasSameSite) {
      findings.push({
        scannerName: 'HTTP Security Headers Inspector',
        title: 'Cookie Missing SameSite Attribute',
        category: 'Headers & Policy',
        severity: 'LOW',
        originalSeverity: 'LOW',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'Set-Cookie does not explicitly define SameSite (Strict, Lax, or None). Explicit SameSite protects against Cross-Site Request Forgery (CSRF).',
        affectedUrl: targetUrl,
        evidence: { rawHeader: `Set-Cookie: ${setCookie.substring(0, 100)}...` },
        remediation: 'Append "; SameSite=Lax" or "; SameSite=Strict" to Set-Cookie headers.',
        fingerprint: `cookie_no_samesite_${urlObj.host}`,
        cwe: 'CWE-1275: Sensitive Cookie with Improper SameSite Attribute',
        owaspCategory: 'A01:2021-Broken Access Control',
      });
    }
  }

  return {
    findings,
    headers,
    statusCode: 200,
  };
}
