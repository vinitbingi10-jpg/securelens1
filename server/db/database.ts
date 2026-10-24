import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { ScanJob, ScannerRun, ScannerFinding, AIAnalysisResult } from '../scanners/types.js';

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  passwordSalt: string;
  displayName: string;
  role: 'owner' | 'analyst' | 'viewer';
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
}

export interface AuditLog {
  id: string;
  userId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  safeMetadata: Record<string, any>;
  createdAt: string;
}

interface DBState {
  users: User[];
  scanJobs: ScanJob[];
  scannerRuns: ScannerRun[];
  findings: ScannerFinding[];
  aiAnalyses: AIAnalysisResult[];
  auditLogs: AuditLog[];
}

const DATA_DIR = path.resolve(process.cwd(), '.data');
const DB_FILE = path.join(DATA_DIR, 'secure_lens_store.json');

// Password utility
export function hashPassword(password: string, salt = crypto.randomBytes(16).toString('hex')): { hash: string; salt: string } {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}

export function verifyPassword(password: string, hash: string, salt: string): boolean {
  const checkHash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(checkHash, 'hex'));
}

class Database {
  private state: DBState = {
    users: [],
    scanJobs: [],
    scannerRuns: [],
    findings: [],
    aiAnalyses: [],
    auditLogs: [],
  };

  constructor() {
    this.init();
  }

  private init() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }

      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        this.state = JSON.parse(raw);
      } else {
        this.seedInitialData();
        this.save();
      }
    } catch (err) {
      console.error('Error initializing database, starting fresh in-memory:', err);
      this.seedInitialData();
    }
  }

  public save() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      fs.writeFileSync(DB_FILE, JSON.stringify(this.state, null, 2), 'utf-8');
    } catch (err) {
      console.error('Failed to persist database to disk:', err);
    }
  }

  private seedInitialData() {
    const adminPass = hashPassword('SecurityLens2026!');
    const adminUser: User = {
      id: 'usr_sec_analyst_01',
      email: 'analyst@securelens.local',
      passwordHash: adminPass.hash,
      passwordSalt: adminPass.salt,
      displayName: 'Senior Security Analyst',
      role: 'owner',
      isActive: true,
      createdAt: new Date(Date.now() - 7 * 86400000).toISOString(),
      updatedAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    };

    this.state.users = [adminUser];

    // Seed baseline initial audit scan for realistic dashboard preview
    const sampleScanId = 'scan_sample_owasp_demo';
    const sampleScan: ScanJob = {
      id: sampleScanId,
      userId: adminUser.id,
      targetUrl: 'https://demo-banking-portal.internal-test.dev',
      targetHost: 'demo-banking-portal.internal-test.dev',
      resolvedIp: '93.184.216.34',
      scanProfile: 'owasp_standard',
      selectedTools: ['http_headers', 'tls_ssl', 'whatweb', 'owasp_zap'],
      enableNetworkChecks: false,
      authorizationConfirmedAt: new Date(Date.now() - 2 * 3600000).toISOString(),
      status: 'completed',
      startedAt: new Date(Date.now() - 2 * 3600000).toISOString(),
      completedAt: new Date(Date.now() - 2 * 3600000 + 42000).toISOString(),
      durationSeconds: 42,
      grade: 'C',
      securityScore: 5.6,
      metrics: {
        criticalCount: 0,
        highCount: 2,
        mediumCount: 2,
        lowCount: 1,
        infoCount: 2,
        totalFindings: 7,
      },
      createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
    };

    const sampleFindings: ScannerFinding[] = [
      {
        id: 'fnd_01_hsts_missing',
        scanJobId: sampleScanId,
        scannerName: 'HTTP Security Headers Inspector',
        title: 'Missing HTTP Strict Transport Security (HSTS) Header',
        category: 'Headers & Policy',
        severity: 'HIGH',
        originalSeverity: 'HIGH',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'The target server does not supply a Strict-Transport-Security header. Browsers accessing the site over plain HTTP will not be forced to automatically upgrade to HTTPS, leaving users vulnerable to Man-In-The-Middle (MITM) downgrade attacks and SSL stripping.',
        affectedUrl: 'https://demo-banking-portal.internal-test.dev/',
        evidence: {
          rawHeader: 'Strict-Transport-Security: null',
          details: { expected: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' },
        },
        remediation: 'Implement the Strict-Transport-Security header with a minimum max-age of 31536000 (1 year) and includeSubDomains parameter.',
        fingerprint: 'hsts_missing_demo_banking',
        cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
        owaspCategory: 'A05:2021-Security Misconfiguration',
        firstSeenAt: new Date(Date.now() - 2 * 3600000).toISOString(),
        createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
      },
      {
        id: 'fnd_02_csp_missing',
        scanJobId: sampleScanId,
        scannerName: 'HTTP Security Headers Inspector',
        title: 'Missing Content Security Policy (CSP)',
        category: 'Headers & Policy',
        severity: 'HIGH',
        originalSeverity: 'HIGH',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'Content Security Policy (CSP) header is absent. Without a restrictive CSP, user sessions are at elevated risk of Cross-Site Scripting (XSS), data injection, and rogue script execution.',
        affectedUrl: 'https://demo-banking-portal.internal-test.dev/',
        evidence: {
          rawHeader: 'Content-Security-Policy: null',
        },
        remediation: "Deploy a defense-in-depth Content-Security-Policy header restricting script-src, default-src, and object-src to authorized origins.",
        fingerprint: 'csp_missing_demo_banking',
        cwe: 'CWE-1021: Improper Restriction of Rendered UI Layers or Scripts',
        owaspCategory: 'A05:2021-Security Misconfiguration',
        firstSeenAt: new Date(Date.now() - 2 * 3600000).toISOString(),
        createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
      },
      {
        id: 'fnd_03_x_powered_by',
        scanJobId: sampleScanId,
        scannerName: 'WhatWeb Technology Fingerprinter',
        title: 'Server Technology Disclosure via X-Powered-By Header',
        category: 'Information Disclosure',
        severity: 'LOW',
        originalSeverity: 'LOW',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: "The HTTP response leaks 'X-Powered-By: Express'. Revealing precise backend frameworks assists adversaries in selecting targeted known vulnerability exploits.",
        affectedUrl: 'https://demo-banking-portal.internal-test.dev/',
        evidence: {
          rawHeader: 'X-Powered-By: Express',
        },
        remediation: 'Disable the X-Powered-By banner in application server configuration (e.g., app.disable("x-powered-by")).',
        fingerprint: 'x_powered_by_express',
        cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
        owaspCategory: 'A05:2021-Security Misconfiguration',
        firstSeenAt: new Date(Date.now() - 2 * 3600000).toISOString(),
        createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
      },
      {
        id: 'fnd_04_tls_cert',
        scanJobId: sampleScanId,
        scannerName: 'TLS/SSL Certificate Inspector (testssl)',
        title: 'TLS Certificate Valid but Approaching Expiration (< 45 Days)',
        category: 'SSL/TLS',
        severity: 'MEDIUM',
        originalSeverity: 'MEDIUM',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'The X.509 certificate expires in 34 days. Automated renewal or manual reissue should be scheduled to prevent service outage or browser untrusted certificate security warnings.',
        affectedUrl: 'https://demo-banking-portal.internal-test.dev/',
        evidence: {
          details: { daysRemaining: 34, validTo: '2026-11-27T12:00:00Z', issuer: "Let's Encrypt Authority R3" },
        },
        remediation: 'Trigger automated ACME renewal (Certbot, Let\'s Encrypt) or install an updated certificate.',
        fingerprint: 'tls_cert_expiry_34days',
        cwe: 'CWE-295: Improper Certificate Validation',
        owaspCategory: 'A02:2021-Cryptographic Failures',
        firstSeenAt: new Date(Date.now() - 2 * 3600000).toISOString(),
        createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
      },
      {
        id: 'fnd_05_clickjacking',
        scanJobId: sampleScanId,
        scannerName: 'OWASP ZAP Passive Rules Engine',
        title: 'Clickjacking Protection Incomplete (Missing X-Frame-Options)',
        category: 'OWASP Top 10',
        severity: 'MEDIUM',
        originalSeverity: 'MEDIUM',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'The page can be embedded in an <iframe> on external domains because neither X-Frame-Options: DENY/SAMEORIGIN nor frame-ancestors CSP directive was declared.',
        affectedUrl: 'https://demo-banking-portal.internal-test.dev/login',
        evidence: {
          rawHeader: 'X-Frame-Options: null',
        },
        remediation: "Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors \\'self\\'' on all HTML endpoints.",
        fingerprint: 'clickjacking_xfo_missing',
        cwe: 'CWE-1021: Improper Restriction of Rendered UI Layers or Frames',
        owaspCategory: 'A05:2021-Security Misconfiguration',
        firstSeenAt: new Date(Date.now() - 2 * 3600000).toISOString(),
        createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
      },
      {
        id: 'fnd_06_robots_txt',
        scanJobId: sampleScanId,
        scannerName: 'OWASP ZAP Passive Rules Engine',
        title: 'Sensitive Administrative Paths Disclosed in robots.txt',
        category: 'Information Disclosure',
        severity: 'INFO',
        originalSeverity: 'INFO',
        confidence: 'CERTAIN',
        verificationStatus: 'CONFIRMED',
        description: 'robots.txt contains Disallow directives for internal paths (/admin-portal, /internal-api/v1). While intended for search crawlers, robots.txt is public and frequently inspected by attackers.',
        affectedUrl: 'https://demo-banking-portal.internal-test.dev/robots.txt',
        evidence: {
          snippet: "Disallow: /admin-portal/\nDisallow: /internal-api/v1/",
        },
        remediation: 'Do not rely on robots.txt for security. Ensure strong authentication and network access controls guard administrative paths.',
        fingerprint: 'robots_txt_admin_disclosure',
        cwe: 'CWE-200: Exposure of Sensitive Information',
        owaspCategory: 'A01:2021-Broken Access Control',
        firstSeenAt: new Date(Date.now() - 2 * 3600000).toISOString(),
        createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
      },
      {
        id: 'fnd_07_tech_stack',
        scanJobId: sampleScanId,
        scannerName: 'WhatWeb Technology Fingerprinter',
        title: 'Web Application Stack Fingerprint Identified',
        category: 'Information Disclosure',
        severity: 'INFO',
        originalSeverity: 'INFO',
        confidence: 'FIRM',
        verificationStatus: 'INFORMATIONAL',
        description: 'Public assets and HTML structure indicate the application is built using React 19, Tailwind CSS, and Node.js.',
        affectedUrl: 'https://demo-banking-portal.internal-test.dev/',
        evidence: {
          details: { detected: ['React 19', 'Tailwind CSS', 'Node.js Express'] },
        },
        remediation: 'Ensure third-party dependencies are kept updated against known CVE databases.',
        fingerprint: 'tech_stack_detected_demo',
        cwe: 'CWE-200: Information Exposure',
        owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
        firstSeenAt: new Date(Date.now() - 2 * 3600000).toISOString(),
        createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
      },
    ];

    const sampleAI: AIAnalysisResult = {
      id: 'ai_01_hsts_analysis',
      findingId: 'fnd_01_hsts_missing',
      provider: 'Google AI (Gemini)',
      model: 'gemini-3.8-flash',
      title: 'Actionable Remediation for HSTS Missing Header',
      explanation: 'HSTS instructs compliant web browsers that the website must only be accessed over HTTPS encrypted channels. When missing, an adversary on a public Wi-Fi or compromised router can intercept the initial unencrypted HTTP request and downgrade communication to plaintext.',
      impact: {
        businessImpact: 'Heightened liability of customer credential interception, regulatory non-compliance with PCI-DSS 4.0 and GDPR requirements.',
        technicalImpact: 'Enables active man-in-the-middle (MITM) attacks and cookie interception via SSL-stripping proxies.',
      },
      recommendedSeverity: 'HIGH',
      remediation: {
        overview: 'Add the Strict-Transport-Security HTTP header to all HTTPS responses at the reverse proxy or web server layer.',
        codeFixes: [
          {
            platform: 'Nginx',
            code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
          },
          {
            platform: 'Apache',
            code: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
          },
          {
            platform: 'Express.js (Helmet)',
            code: 'app.use(helmet.hsts({\n  maxAge: 31536000,\n  includeSubDomains: true,\n  preload: true\n}));',
          },
        ],
        verificationSteps: [
          'curl -s -D - https://demo-banking-portal.internal-test.dev | grep -i "strict-transport-security"',
          'Verify header response includes max-age>=31536000 and includeSubDomains.',
        ],
      },
      confidence: 'High confidence based on direct HTTP response header analysis',
      references: [
        { title: 'OWASP HSTS Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html' },
        { title: 'MDN Strict-Transport-Security', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security' },
      ],
      createdAt: new Date(Date.now() - 2 * 3600000 + 5000).toISOString(),
    };

    this.state.scanJobs = [sampleScan];
    this.state.findings = sampleFindings;
    this.state.aiAnalyses = [sampleAI];
    this.state.auditLogs = [
      {
        id: 'aud_init_01',
        userId: adminUser.id,
        action: 'SCAN_COMPLETED',
        resourceType: 'scan_job',
        resourceId: sampleScanId,
        safeMetadata: { target: sampleScan.targetUrl, findings: 7 },
        createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
      },
    ];
  }

  // User queries
  public findUserByEmail(email: string): User | undefined {
    return this.state.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  }

  public findUserById(id: string): User | undefined {
    return this.state.users.find(u => u.id === id);
  }

  public createUser(user: User): User {
    this.state.users.push(user);
    this.save();
    return user;
  }

  public updateUser(id: string, updates: Partial<User>): User | undefined {
    const user = this.findUserById(id);
    if (!user) return undefined;
    Object.assign(user, updates, { updatedAt: new Date().toISOString() });
    this.save();
    return user;
  }

  // Scan Jobs
  public getScanJobs(userId?: string): ScanJob[] {
    const list = userId ? this.state.scanJobs.filter(j => j.userId === userId) : this.state.scanJobs;
    return [...list].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  public getScanJobById(id: string): ScanJob | undefined {
    return this.state.scanJobs.find(j => j.id === id);
  }

  public createScanJob(job: ScanJob): ScanJob {
    this.state.scanJobs.push(job);
    this.save();
    return job;
  }

  public updateScanJob(id: string, updates: Partial<ScanJob>): ScanJob | undefined {
    const job = this.getScanJobById(id);
    if (!job) return undefined;
    Object.assign(job, updates);
    this.save();
    return job;
  }

  public deleteScanJob(id: string): boolean {
    const initialLen = this.state.scanJobs.length;
    this.state.scanJobs = this.state.scanJobs.filter(j => j.id !== id);
    this.state.findings = this.state.findings.filter(f => f.scanJobId !== id);
    this.state.scannerRuns = this.state.scannerRuns.filter(r => r.scanJobId !== id);
    this.save();
    return this.state.scanJobs.length < initialLen;
  }

  // Scanner Runs
  public createScannerRun(run: ScannerRun): ScannerRun {
    this.state.scannerRuns.push(run);
    this.save();
    return run;
  }

  public updateScannerRun(id: string, updates: Partial<ScannerRun>): ScannerRun | undefined {
    const run = this.state.scannerRuns.find(r => r.id === id);
    if (!run) return undefined;
    Object.assign(run, updates);
    this.save();
    return run;
  }

  public getScannerRunsByScanId(scanJobId: string): ScannerRun[] {
    return this.state.scannerRuns.filter(r => r.scanJobId === scanJobId);
  }

  // Findings
  public getFindings(scanJobId?: string): ScannerFinding[] {
    if (scanJobId) {
      return this.state.findings.filter(f => f.scanJobId === scanJobId);
    }
    return this.state.findings;
  }

  public getFindingById(id: string): ScannerFinding | undefined {
    return this.state.findings.find(f => f.id === id);
  }

  public addFindings(newFindings: ScannerFinding[]): ScannerFinding[] {
    this.state.findings.push(...newFindings);
    this.save();
    return newFindings;
  }

  // AI Analyses
  public getAiAnalysisByFindingId(findingId: string): AIAnalysisResult | undefined {
    return this.state.aiAnalyses.find(a => a.findingId === findingId);
  }

  public saveAiAnalysis(analysis: AIAnalysisResult): AIAnalysisResult {
    const existingIndex = this.state.aiAnalyses.findIndex(a => a.findingId === analysis.findingId);
    if (existingIndex >= 0) {
      this.state.aiAnalyses[existingIndex] = analysis;
    } else {
      this.state.aiAnalyses.push(analysis);
    }
    this.save();
    return analysis;
  }

  // Audit Logs
  public addAuditLog(log: Omit<AuditLog, 'id' | 'createdAt'>): AuditLog {
    const fullLog: AuditLog = {
      ...log,
      id: `aud_${crypto.randomBytes(8).toString('hex')}`,
      createdAt: new Date().toISOString(),
    };
    this.state.auditLogs.unshift(fullLog);
    // Keep max 200 logs
    if (this.state.auditLogs.length > 200) {
      this.state.auditLogs = this.state.auditLogs.slice(0, 200);
    }
    this.save();
    return fullLog;
  }

  public getAuditLogs(userId?: string): AuditLog[] {
    if (userId) {
      return this.state.auditLogs.filter(l => l.userId === userId);
    }
    return this.state.auditLogs;
  }

  // Statistics Summary
  public getDashboardSummary(userId?: string) {
    const scans = this.getScanJobs(userId);
    const completedScans = scans.filter(s => s.status === 'completed');
    const failedScans = scans.filter(s => s.status === 'failed');

    const scanIds = new Set(scans.map(s => s.id));
    const userFindings = this.state.findings.filter(f => scanIds.has(f.scanJobId));

    const critical = userFindings.filter(f => f.severity === 'CRITICAL').length;
    const high = userFindings.filter(f => f.severity === 'HIGH').length;
    const medium = userFindings.filter(f => f.severity === 'MEDIUM').length;
    const low = userFindings.filter(f => f.severity === 'LOW').length;
    const info = userFindings.filter(f => f.severity === 'INFO').length;

    // Severity by category
    const categoryMap: Record<string, { count: number; highOrCrit: number }> = {};
    for (const f of userFindings) {
      if (!categoryMap[f.category]) {
        categoryMap[f.category] = { count: 0, highOrCrit: 0 };
      }
      categoryMap[f.category].count += 1;
      if (f.severity === 'CRITICAL' || f.severity === 'HIGH') {
        categoryMap[f.category].highOrCrit += 1;
      }
    }

    return {
      totalScans: scans.length,
      completedScans: completedScans.length,
      failedScans: failedScans.length,
      totalFindings: userFindings.length,
      criticalFindings: critical,
      highFindings: high,
      mediumFindings: medium,
      lowFindings: low,
      infoFindings: info,
      categories: Object.entries(categoryMap).map(([category, stats]) => ({
        category,
        count: stats.count,
        highOrCrit: stats.highOrCrit,
      })),
      recentScans: scans.slice(0, 5),
      recentFindings: userFindings.slice(0, 6),
    };
  }
}

export const db = new Database();
