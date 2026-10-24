import { ToolMetadata } from './types.js';

export interface ScannerEngineStatus extends ToolMetadata {
  installed: boolean;
  activeEngine: string;
  configStatus: 'configured' | 'opt_in_required' | 'ready';
  lastExecutionAt?: string;
  setupGuide: {
    prerequisites: string;
    cliCommand: string;
    docsUrl: string;
    description: string;
  };
}

export const SCANNER_REGISTRY: ScannerEngineStatus[] = [
  {
    id: 'http_headers',
    name: 'HTTP Security Headers Inspector',
    version: 'v2.4.1 (Embedded Engine)',
    category: 'Headers & Policy',
    description: 'Inspects HTTP response headers, HSTS, CSP directives, X-Frame-Options, Cookie security flags (Secure, HttpOnly, SameSite), and Server banners.',
    status: 'active_node_engine',
    installed: true,
    activeEngine: 'SecureLens Node.js HTTP/2 Client Engine',
    configStatus: 'ready',
    isSafePassive: true,
    setupGuide: {
      prerequisites: 'Node.js runtime with built-in http/https client modules.',
      cliCommand: 'curl -I -s https://target.example.com',
      docsUrl: 'https://owasp.org/www-project-secure-headers/',
      description: 'Built directly into Secure Lens. Evaluates response headers in real-time according to OWASP Secure Headers Project guidelines.',
    },
  },
  {
    id: 'tls_ssl',
    name: 'testssl.sh & TLS Certificate Inspector',
    version: 'v3.2.0 (TLS Native Adapter)',
    category: 'Cryptographic Security',
    description: 'Evaluates X.509 certificate chains, expiration date windows, Subject Alternative Names (SAN), negotiated TLS protocol versions, and weak cipher detection.',
    status: 'active_node_engine',
    installed: true,
    activeEngine: 'SecureLens OpenSSL/Node TLS Client Adapter',
    configStatus: 'ready',
    isSafePassive: true,
    setupGuide: {
      prerequisites: 'OpenSSL / TLS 1.3 cryptographic libraries.',
      cliCommand: 'testssl.sh --quiet --color 0 https://target.example.com',
      docsUrl: 'https://testssl.sh/',
      description: 'Performs non-disruptive TLS handshakes with SNI to inspect peer certificates, trust chains, expiration windows, and protocol security.',
    },
  },
  {
    id: 'whatweb',
    name: 'WhatWeb Technology Fingerprinter',
    version: 'v0.5.6 (Fingerprint Engine)',
    category: 'Reconnaissance & Fingerprinting',
    description: 'Identifies content management systems (CMS), front-end frameworks (React, Vue, Next.js), web server banners, and JavaScript library versions.',
    status: 'active_node_engine',
    installed: true,
    activeEngine: 'SecureLens DOM & Header Fingerprinter',
    configStatus: 'ready',
    isSafePassive: true,
    setupGuide: {
      prerequisites: 'Ruby / WhatWeb packages or embedded regex rule-base.',
      cliCommand: 'whatweb -v -a 1 https://target.example.com',
      docsUrl: 'https://github.com/urbanadventurer/WhatWeb',
      description: 'Parses DOM headers, meta tags, and script references to detect technology components without executing active payloads.',
    },
  },
  {
    id: 'owasp_zap',
    name: 'OWASP ZAP Passive Rules Engine',
    version: 'v2.14.0 (Core Passive Ruleset)',
    category: 'Application Vulnerabilities',
    description: 'Evaluates forms for missing anti-CSRF tokens, detects mixed content leaks, verifies sensitive repository exposure (/.git/HEAD), and inspects robots.txt.',
    status: 'active_node_engine',
    installed: true,
    activeEngine: 'SecureLens ZAP Passive Audit Core',
    configStatus: 'ready',
    isSafePassive: true,
    setupGuide: {
      prerequisites: 'Java 17+ or Docker for full OWASP ZAP daemon API integration.',
      cliCommand: 'docker run -u zap -p 8080:8080 -i ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080',
      docsUrl: 'https://www.zaproxy.org/docs/api/',
      description: 'Performs passive, non-destructive evaluations of web application responses and checks public paths for exposed source repositories.',
    },
  },
  {
    id: 'nuclei',
    name: 'Nuclei Non-Intrusive Engine',
    version: 'v3.2.0 (Curated Safe Ruleset)',
    category: 'Vulnerability Detection',
    description: 'Executes curated non-destructive templates: CORS origin reflection vulnerabilities, exposed swagger specifications, directory listing, and debug endpoints.',
    status: 'active_node_engine',
    installed: true,
    activeEngine: 'SecureLens Nuclei Template Runtime',
    configStatus: 'ready',
    isSafePassive: true,
    setupGuide: {
      prerequisites: 'Go runtime or ProjectDiscovery Nuclei binary.',
      cliCommand: 'nuclei -u https://target.example.com -tags config,exposure -silent',
      docsUrl: 'https://github.com/projectdiscovery/nuclei',
      description: 'Executes verified non-intrusive templates with strict rate limiting to detect configuration weaknesses.',
    },
  },
  {
    id: 'network_nmap',
    name: 'Nmap Safe Network Port Scanner',
    version: 'v7.94 (Conservative Socket Adapter)',
    category: 'Network & Perimeter',
    description: 'Probes common standard web ports (80, 443, 8080, 8443, 3000, 8000) using restricted TCP timeouts. Requires explicit user authorization checkbox.',
    status: 'active_node_engine',
    installed: true,
    activeEngine: 'SecureLens TCP Socket Network Probe',
    configStatus: 'opt_in_required',
    isSafePassive: false,
    requiresExplicitNetworkConsent: true,
    setupGuide: {
      prerequisites: 'Raw socket permissions or Nmap CLI utility.',
      cliCommand: 'nmap -sT -p 80,443,8080,8443 -T3 target.example.com',
      docsUrl: 'https://nmap.org/',
      description: 'Runs lightweight TCP connect handshakes against approved web ports with strict 1200ms connection timeouts and no exploit probes.',
    },
  },
];
