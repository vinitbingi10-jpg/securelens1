import http from 'http';
import https from 'https';
import { ScannerFinding } from './types.js';

interface ZapResult {
  findings: Omit<ScannerFinding, 'id' | 'scanJobId' | 'scannerRunId' | 'firstSeenAt' | 'createdAt'>[];
}

async function probeUrl(url: string, timeoutMs = 6000): Promise<{ statusCode: number; body: string; headers: Record<string, string> } | null> {
  const urlObj = new URL(url);
  const client = urlObj.protocol === 'https:' ? https : http;

  return new Promise((resolve) => {
    const req = client.request(
      url,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'SecureLens-OWASP-ZAP-AuditEngine/2.14 (+https://securelens.local)',
          'Accept': '*/*',
        },
        timeout: timeoutMs,
      },
      (res) => {
        let body = '';
        res.setEncoding('utf-8');
        res.on('data', (chunk) => {
          if (body.length < 100000) body += chunk;
        });
        res.on('end', () => {
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (v) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
          }
          resolve({ statusCode: res.statusCode || 0, body, headers });
        });
      }
    );

    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });

    req.end();
  });
}

export async function scanOwaspZap(targetUrl: string): Promise<ZapResult> {
  const urlObj = new URL(targetUrl);
  const baseUrl = `${urlObj.protocol}//${urlObj.host}`;
  const findings: ZapResult['findings'] = [];

  // 1. Fetch main page body and analyze HTML for OWASP passive rules
  const mainPage = await probeUrl(targetUrl, 8000);
  if (mainPage && mainPage.statusCode >= 200 && mainPage.statusCode < 400) {
    const html = mainPage.body;

    // A. Anti-CSRF Token Missing in HTML Forms
    const formMatches = html.match(/<form[^>]*>[\s\S]*?<\/form>/gi) || [];
    for (const formHtml of formMatches) {
      const isPost = /method=["']post["']/i.test(formHtml);
      if (isPost) {
        const hasCsrfToken = /name=["'](?:csrf|_csrf|authenticity_token|token|csrf_token|__RequestVerificationToken)["']/i.test(formHtml);
        if (!hasCsrfToken) {
          findings.push({
            scannerName: 'OWASP ZAP Passive Rules Engine',
            title: 'HTML Form Without Anti-CSRF Token Detected',
            category: 'OWASP Top 10',
            severity: 'MEDIUM',
            originalSeverity: 'MEDIUM',
            confidence: 'FIRM',
            verificationStatus: 'POTENTIAL',
            description: 'A POST form on the target page does not include a hidden anti-CSRF token input field. If requests are authenticated via session cookies without SameSite=Strict, this may permit Cross-Site Request Forgery.',
            affectedUrl: targetUrl,
            evidence: {
              snippet: formHtml.substring(0, 180) + '...',
            },
            remediation: 'Implement anti-CSRF token validation (synchronizer token pattern or double-submit cookie) on all state-changing POST forms.',
            fingerprint: `zap_csrf_missing_${urlObj.host}`,
            cwe: 'CWE-352: Cross-Site Request Forgery (CSRF)',
            owaspCategory: 'A01:2021-Broken Access Control',
          });
          break; // Report once per page
        }
      }
    }

    // B. Mixed Content Check (if HTTPS)
    if (urlObj.protocol === 'https:') {
      const insecureResourceMatch = html.match(/src=["']http:\/\/[^"']+["']/i);
      if (insecureResourceMatch) {
        findings.push({
          scannerName: 'OWASP ZAP Passive Rules Engine',
          title: 'Passive Mixed Content (HTTP Resource on HTTPS Page)',
          category: 'OWASP Top 10',
          severity: 'MEDIUM',
          originalSeverity: 'MEDIUM',
          confidence: 'CERTAIN',
          verificationStatus: 'CONFIRMED',
          description: `An unencrypted HTTP resource was loaded over an HTTPS page: ${insecureResourceMatch[0]}. Browsers may block or trigger mixed content warnings, and traffic can be intercepted.`,
          affectedUrl: targetUrl,
          evidence: { matchedPattern: insecureResourceMatch[0] },
          remediation: 'Update all external script, image, and style asset URLs to use HTTPS or relative paths.',
          fingerprint: `zap_mixed_content_${urlObj.host}`,
          cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
          owaspCategory: 'A05:2021-Security Misconfiguration',
        });
      }
    }

    // C. Password input without autocomplete="current-password" or "off"
    if (html.includes('type="password"') && !html.includes('autocomplete=')) {
      findings.push({
        scannerName: 'OWASP ZAP Passive Rules Engine',
        title: 'Password Input Field Without Autocomplete Attribute',
        category: 'OWASP Top 10',
        severity: 'LOW',
        originalSeverity: 'LOW',
        confidence: 'CERTAIN',
        verificationStatus: 'INFORMATIONAL',
        description: 'Password input field does not define an explicit autocomplete attribute (e.g. autocomplete="current-password" or autocomplete="new-password").',
        affectedUrl: targetUrl,
        evidence: { snippet: 'type="password" without autocomplete attribute' },
        remediation: 'Add explicit autocomplete attributes according to WHATWG HTML specs to assist credential managers and prevent caching misbehavior.',
        fingerprint: `zap_password_autocomplete_${urlObj.host}`,
        cwe: 'CWE-522: Insufficiently Protected Credentials',
        owaspCategory: 'A07:2021-Identification and Authentication Failures',
      });
    }
  }

  // 2. Safe Sensitive Path Probes (Passive/Non-Destructive)

  // A. Public Git Repository Check (/.git/HEAD)
  const gitHeadRes = await probeUrl(`${baseUrl}/.git/HEAD`, 5000);
  if (gitHeadRes && gitHeadRes.statusCode === 200 && gitHeadRes.body.startsWith('ref: refs/')) {
    findings.push({
      scannerName: 'OWASP ZAP Passive Rules Engine',
      title: 'CRITICAL: Exposed Git Repository (/.git/HEAD)',
      category: 'Information Disclosure',
      severity: 'CRITICAL',
      originalSeverity: 'CRITICAL',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: 'The root .git directory is publicly accessible over HTTP. Attackers can reconstruct the complete source code, commit history, and potential embedded secrets/credentials.',
      affectedUrl: `${baseUrl}/.git/HEAD`,
      evidence: { snippet: gitHeadRes.body.substring(0, 100) },
      remediation: 'Block access to the /.git directory immediately at the web server layer (e.g. location ~ /\\.git { deny all; } in Nginx).',
      fingerprint: `zap_exposed_git_${urlObj.host}`,
      cwe: 'CWE-538: Insertion of Sensitive Information into Externally-Accessible File',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  // B. Exposed .env Check
  const envRes = await probeUrl(`${baseUrl}/.env`, 5000);
  if (envRes && envRes.statusCode === 200 && (envRes.body.includes('DB_PASSWORD') || envRes.body.includes('API_KEY') || envRes.body.includes('SECRET='))) {
    findings.push({
      scannerName: 'OWASP ZAP Passive Rules Engine',
      title: 'CRITICAL: Exposed Environment Secrets File (/.env)',
      category: 'Information Disclosure',
      severity: 'CRITICAL',
      originalSeverity: 'CRITICAL',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: 'The server serves a .env configuration file containing database credentials, secrets, or API tokens in plain text to unauthenticated visitors.',
      affectedUrl: `${baseUrl}/.env`,
      evidence: { snippet: 'Environment configuration file contents exposed with key/value credentials' },
      remediation: 'Block access to all .* hidden files and relocate .env outside the web document root.',
      fingerprint: `zap_exposed_env_${urlObj.host}`,
      cwe: 'CWE-552: Files or Directories Accessible to External Parties',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  // C. robots.txt Analysis
  const robotsRes = await probeUrl(`${baseUrl}/robots.txt`, 5000);
  if (robotsRes && robotsRes.statusCode === 200 && robotsRes.body.includes('Disallow:')) {
    const disallows = robotsRes.body.match(/Disallow:\s*([^\r\n]+)/gi) || [];
    const sensitiveEntries = disallows.filter(d => /admin|login|backup|api|secret|private|internal/i.test(d));

    if (sensitiveEntries.length > 0) {
      findings.push({
        scannerName: 'OWASP ZAP Passive Rules Engine',
        title: 'Sensitive Endpoints Disclosed in robots.txt',
        category: 'Information Disclosure',
        severity: 'INFO',
        originalSeverity: 'INFO',
        confidence: 'CERTAIN',
        verificationStatus: 'INFORMATIONAL',
        description: `robots.txt reveals paths that administrators intended to hide: [${sensitiveEntries.slice(0, 5).join(', ')}]. Attackers systematically parse robots.txt for hidden administrative areas.`,
        affectedUrl: `${baseUrl}/robots.txt`,
        evidence: { snippet: sensitiveEntries.slice(0, 5).join('\n') },
        remediation: 'Do not use robots.txt for security through obscurity. Rely on strict authentication and IP whitelisting.',
        fingerprint: `zap_robots_disclosure_${urlObj.host}`,
        cwe: 'CWE-200: Exposure of Sensitive Information',
        owaspCategory: 'A01:2021-Broken Access Control',
      });
    }
  }

  // D. security.txt Missing (RFC 9116)
  const securityTxtRes = await probeUrl(`${baseUrl}/.well-known/security.txt`, 4000);
  if (!securityTxtRes || securityTxtRes.statusCode !== 200 || !securityTxtRes.body.includes('Contact:')) {
    findings.push({
      scannerName: 'OWASP ZAP Passive Rules Engine',
      title: 'Missing security.txt Vulnerability Disclosure Policy (RFC 9116)',
      category: 'Information Disclosure',
      severity: 'INFO',
      originalSeverity: 'INFO',
      confidence: 'CERTAIN',
      verificationStatus: 'INFORMATIONAL',
      description: 'The site does not publish a security.txt file at /.well-known/security.txt. RFC 9116 defines this standard for security researchers to responsibly report vulnerabilities.',
      affectedUrl: `${baseUrl}/.well-known/security.txt`,
      evidence: { details: { status: securityTxtRes ? securityTxtRes.statusCode : 'Unavailable' } },
      remediation: 'Publish a /.well-known/security.txt file containing Contact: mailto:security@yourdomain.com and Expires: date.',
      fingerprint: `zap_missing_security_txt_${urlObj.host}`,
      cwe: 'CWE-16: Configuration',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  return { findings };
}
