import http from 'http';
import https from 'https';
import { ScannerFinding } from './types.js';

interface NucleiResult {
  findings: Omit<ScannerFinding, 'id' | 'scanJobId' | 'scannerRunId' | 'firstSeenAt' | 'createdAt'>[];
}

async function fetchWithHeaders(url: string, requestHeaders: Record<string, string>): Promise<{ status: number; headers: Record<string, string>; body: string } | null> {
  const urlObj = new URL(url);
  const client = urlObj.protocol === 'https:' ? https : http;

  return new Promise((resolve) => {
    const req = client.request(
      url,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'SecureLens-Nuclei-TemplateEngine/3.2.0 (+https://securelens.local)',
          ...requestHeaders,
        },
        timeout: 5000,
      },
      (res) => {
        let body = '';
        res.setEncoding('utf-8');
        res.on('data', (chunk) => {
          if (body.length < 50000) body += chunk;
        });
        res.on('end', () => {
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (v) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
          }
          resolve({ status: res.statusCode || 0, headers, body });
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

export async function scanNucleiNonIntrusive(targetUrl: string): Promise<NucleiResult> {
  const urlObj = new URL(targetUrl);
  const baseUrl = `${urlObj.protocol}//${urlObj.host}`;
  const findings: NucleiResult['findings'] = [];

  // Template 1: CORS Misconfiguration with Arbitrary Origin Reflection & Credentials
  try {
    const evilOrigin = 'https://attacker-controlled-origin.com';
    const corsRes = await fetchWithHeaders(targetUrl, { Origin: evilOrigin });

    if (corsRes && corsRes.headers['access-control-allow-origin']) {
      const acao = corsRes.headers['access-control-allow-origin'];
      const acac = corsRes.headers['access-control-allow-credentials'];

      if ((acao === evilOrigin || acao === '*') && acac === 'true') {
        findings.push({
          scannerName: 'Nuclei Non-Intrusive Engine',
          title: 'CRITICAL: Insecure CORS Policy (Arbitrary Origin with Credentials)',
          category: 'OWASP Top 10',
          severity: 'CRITICAL',
          originalSeverity: 'CRITICAL',
          confidence: 'CERTAIN',
          verificationStatus: 'CONFIRMED',
          description: `The application dynamically reflects untrusted request Origins (${acao}) while permitting credentials (Access-Control-Allow-Credentials: true). Malicious websites can read private user data and session responses via XMLHttpRequest.`,
          affectedUrl: targetUrl,
          evidence: {
            rawHeader: `Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
            matchedPattern: 'nuclei-template: cors-arbitrary-origin-credentials',
          },
          remediation: 'Restrict Access-Control-Allow-Origin to an explicit whitelist of trusted domain names. Never reflect arbitrary Origin headers with credentials.',
          fingerprint: `nuclei_cors_vuln_${urlObj.host}`,
          cwe: 'CWE-942: Permissive Cross-Domain Policy with Untrusted Domains',
          owaspCategory: 'A01:2021-Broken Access Control',
        });
      } else if (acao === '*') {
        findings.push({
          scannerName: 'Nuclei Non-Intrusive Engine',
          title: 'Permissive Wildcard CORS Header (Access-Control-Allow-Origin: *)',
          category: 'Misconfiguration',
          severity: 'LOW',
          originalSeverity: 'LOW',
          confidence: 'CERTAIN',
          verificationStatus: 'CONFIRMED',
          description: 'The API returns Access-Control-Allow-Origin: *. If this endpoint serves sensitive user data, any external origin can read response contents.',
          affectedUrl: targetUrl,
          evidence: {
            rawHeader: 'Access-Control-Allow-Origin: *',
            matchedPattern: 'nuclei-template: cors-wildcard',
          },
          remediation: 'If the resource is public, this may be intended. For private API endpoints, bind CORS to specific origin hostnames.',
          fingerprint: `nuclei_cors_wildcard_${urlObj.host}`,
          cwe: 'CWE-942: Permissive Cross-Domain Policy',
          owaspCategory: 'A05:2021-Security Misconfiguration',
        });
      }
    }
  } catch (e) {
    // ignore
  }

  // Template 2: Open Directory Listing Check
  try {
    const dirRes = await fetchWithHeaders(targetUrl, {});
    if (dirRes && (dirRes.body.includes('Index of /') || dirRes.body.includes('<title>Directory listing for /</title>'))) {
      findings.push({
        scannerName: 'Nuclei Non-Intrusive Engine',
        title: 'Open Directory Listing Enabled',
        category: 'Information Disclosure',
        severity: 'MEDIUM',
        originalSeverity: 'MEDIUM',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'Web server directory indexing is active, exposing file hierarchies, backup files, and unlinked scripts.',
        affectedUrl: targetUrl,
        evidence: {
          matchedPattern: 'nuclei-template: directory-listing-detect',
          snippet: 'Index of / detected in response body',
        },
        remediation: 'Disable directory browsing in web server configuration (autoindex off; in Nginx, Options -Indexes in Apache).',
        fingerprint: `nuclei_dir_listing_${urlObj.host}`,
        cwe: 'CWE-548: Exposure of Information Through Directory Listing',
        owaspCategory: 'A05:2021-Security Misconfiguration',
      });
    }
  } catch (e) {
    // ignore
  }

  // Template 3: Exposed Swagger / OpenAPI Documentation
  try {
    const swaggerRes = await fetchWithHeaders(`${baseUrl}/swagger.json`, {});
    if (swaggerRes && swaggerRes.status === 200 && (swaggerRes.body.includes('"swagger":') || swaggerRes.body.includes('"openapi":'))) {
      findings.push({
        scannerName: 'Nuclei Non-Intrusive Engine',
        title: 'Exposed Swagger/OpenAPI Specification File (/swagger.json)',
        category: 'Information Disclosure',
        severity: 'LOW',
        originalSeverity: 'LOW',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'Publicly readable Swagger JSON schema discovered. This maps internal API endpoints, parameters, and authentication schemas.',
        affectedUrl: `${baseUrl}/swagger.json`,
        evidence: {
          matchedPattern: 'nuclei-template: swagger-json-exposed',
          snippet: swaggerRes.body.substring(0, 150),
        },
        remediation: 'Restrict API documentation schemas behind authenticated gates in production environments.',
        fingerprint: `nuclei_swagger_exposed_${urlObj.host}`,
        cwe: 'CWE-200: Exposure of Sensitive Information',
        owaspCategory: 'A05:2021-Security Misconfiguration',
      });
    }
  } catch (e) {
    // ignore
  }

  // Template 4: Spring Boot / Actuator Debug Exposure
  try {
    const actuatorRes = await fetchWithHeaders(`${baseUrl}/actuator/health`, {});
    if (actuatorRes && actuatorRes.status === 200 && actuatorRes.body.includes('"status"')) {
      findings.push({
        scannerName: 'Nuclei Non-Intrusive Engine',
        title: 'Exposed Spring Boot Actuator Endpoint (/actuator/health)',
        category: 'Information Disclosure',
        severity: 'LOW',
        originalSeverity: 'LOW',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'Spring Boot Actuator health endpoint is publicly accessible without authentication.',
        affectedUrl: `${baseUrl}/actuator/health`,
        evidence: {
          matchedPattern: 'nuclei-template: springboot-actuator-detect',
          snippet: actuatorRes.body.substring(0, 120),
        },
        remediation: 'Ensure management.endpoints.web.exposure.include does not expose internal endpoints publicly.',
        fingerprint: `nuclei_actuator_health_${urlObj.host}`,
        cwe: 'CWE-200: Exposure of Sensitive Information',
        owaspCategory: 'A05:2021-Security Misconfiguration',
      });
    }
  } catch (e) {
    // ignore
  }

  return { findings };
}
