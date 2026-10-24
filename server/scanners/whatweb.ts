import http from 'http';
import https from 'https';
import { ScannerFinding } from './types.js';

interface WhatWebResult {
  findings: Omit<ScannerFinding, 'id' | 'scanJobId' | 'scannerRunId' | 'firstSeenAt' | 'createdAt'>[];
  detectedTech: string[];
}

export async function scanWhatWeb(targetUrl: string): Promise<WhatWebResult> {
  const urlObj = new URL(targetUrl);
  const client = urlObj.protocol === 'https:' ? https : http;
  const findings: WhatWebResult['findings'] = [];
  const detectedTech = new Set<string>();

  return new Promise<WhatWebResult>((resolve) => {
    const req = client.request(
      targetUrl,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SecureLens/1.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        timeout: 10000,
      },
      (res) => {
        let body = '';
        res.setEncoding('utf-8');

        res.on('data', (chunk) => {
          if (body.length < 500000) { // Limit buffer to 500KB to prevent memory exhaustion
            body += chunk;
          }
        });

        res.on('end', () => {
          const headers = res.headers;

          // Header inspection
          if (headers['server']) {
            detectedTech.add(`Server: ${headers['server']}`);
          }
          if (headers['x-powered-by']) {
            detectedTech.add(`Engine: ${headers['x-powered-by']}`);
          }
          if (headers['cf-ray']) {
            detectedTech.add('CDN: Cloudflare');
          }
          if (headers['x-cache']?.toString().includes('Akamai') || headers['x-akamai-transformed']) {
            detectedTech.add('CDN: Akamai');
          }
          if (headers['via']?.toString().includes('cloudfront') || headers['x-amz-cf-id']) {
            detectedTech.add('CDN: AWS CloudFront');
          }
          if (headers['x-aspnet-version']) {
            detectedTech.add(`Framework: ASP.NET ${headers['x-aspnet-version']}`);
          }

          // HTML inspection
          const metaGenMatch = body.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
          if (metaGenMatch && metaGenMatch[1]) {
            detectedTech.add(`Generator: ${metaGenMatch[1]}`);
          }

          // Script & Framework markers
          if (body.includes('_next/static') || body.includes('__NEXT_DATA__')) {
            detectedTech.add('Framework: Next.js (React)');
          } else if (body.includes('data-reactroot') || body.includes('react-dom') || body.includes('react.production.min.js')) {
            detectedTech.add('Library: React.js');
          }

          if (body.includes('data-v-') || body.includes('vue.global.js') || body.includes('__VUE__')) {
            detectedTech.add('Framework: Vue.js');
          }

          if (body.includes('ng-version') || body.includes('angular.js') || body.includes('ng-app')) {
            detectedTech.add('Framework: Angular');
          }

          if (body.includes('wp-content') || body.includes('wp-includes')) {
            detectedTech.add('CMS: WordPress');
          }

          if (body.includes('/sites/default/files') || body.includes('Drupal.settings')) {
            detectedTech.add('CMS: Drupal');
          }

          if (body.includes('cdn.shopify.com')) {
            detectedTech.add('Platform: Shopify');
          }

          // Generate normalized Informational findings for detected technologies
          const techList = Array.from(detectedTech);
          if (techList.length > 0) {
            findings.push({
              scannerName: 'WhatWeb Technology Fingerprinter',
              title: 'Public Web Stack & Fingerprints Disclosed',
              category: 'Information Disclosure',
              severity: 'INFO',
              originalSeverity: 'INFO',
              confidence: 'FIRM',
              verificationStatus: 'INFORMATIONAL',
              description: `Public HTML and response headers disclosed the following application stack components: ${techList.join(', ')}. While informational, revealing technologies narrows attacker exploration.`,
              affectedUrl: targetUrl,
              evidence: {
                details: { detectedTechnologies: techList },
              },
              remediation: 'Ensure all identified libraries, frameworks, and web server runtimes are up to date with vendor security patches.',
              fingerprint: `whatweb_tech_${urlObj.host}`,
              cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
              owaspCategory: 'A05:2021-Security Misconfiguration',
            });
          }

          // Check if outdated jQuery or insecure library signatures are present
          const jqueryMatch = body.match(/jquery[-.]([0-9.]+)(?:\.min)?\.js/i);
          if (jqueryMatch && jqueryMatch[1]) {
            const version = jqueryMatch[1];
            if (version.startsWith('1.') || version.startsWith('2.')) {
              findings.push({
                scannerName: 'WhatWeb Technology Fingerprinter',
                title: `Legacy jQuery Version in Use (${version})`,
                category: 'Vulnerable Components',
                severity: 'MEDIUM',
                originalSeverity: 'MEDIUM',
                confidence: 'FIRM',
                verificationStatus: 'POTENTIAL',
                description: `Detected legacy jQuery version ${version}. Versions prior to 3.5.0 contain known Cross-Site Scripting (XSS) vulnerabilities (CVE-2020-11022, CVE-2020-11023).`,
                affectedUrl: targetUrl,
                evidence: {
                  matchedPattern: jqueryMatch[0],
                  details: { detectedVersion: version },
                },
                remediation: 'Upgrade to jQuery 3.7.1 or eliminate direct jQuery usage in favor of modern vanilla DOM APIs or framework abstractions.',
                fingerprint: `jquery_legacy_${urlObj.host}_${version}`,
                cwe: 'CWE-1035: Vulnerable Third Party Component',
                owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
              });
            }
          }

          resolve({
            findings,
            detectedTech: techList,
          });
        });
      }
    );

    req.on('error', () => {
      resolve({ findings, detectedTech: [] });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ findings, detectedTech: [] });
    });

    req.end();
  });
}
