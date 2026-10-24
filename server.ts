import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { db, hashPassword, verifyPassword, User } from './server/db/database.js';
import { authMiddleware, requireAuth, generateToken, revokeToken, AuthenticatedRequest } from './server/auth/auth.js';
import { validateScanTarget } from './server/security/ssrf.js';
import { SCANNER_REGISTRY } from './server/scanners/registry.js';
import { executeScanJobAsync, cancelScanJob } from './server/scanners/orchestrator.js';
import { getAiStatus, testAiConnection, analyzeFindingWithAI, askSecurityCopilot } from './server/ai/gemini-adapter.js';
import { generateHtmlReport } from './server/reports/report-generator.js';
import { ScanJob, ScannerFinding } from './server/scanners/types.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(authMiddleware);

// ==========================================
// 1. AUTHENTICATION ENDPOINTS
// ==========================================

app.post('/api/auth/register', (req, res) => {
  try {
    const { email, password, displayName, role } = req.body;

    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      res.status(400).json({ error: 'Valid email and password are required.' });
      return;
    }

    if (password.length < 8) {
      res.status(400).json({ error: 'Password must be at least 8 characters long.' });
      return;
    }

    const existing = db.findUserByEmail(email);
    if (existing) {
      res.status(409).json({ error: 'An account with this email address already exists.' });
      return;
    }

    const { hash, salt } = hashPassword(password);
    const newUser: User = {
      id: `usr_${crypto.randomBytes(8).toString('hex')}`,
      email: email.trim().toLowerCase(),
      passwordHash: hash,
      passwordSalt: salt,
      displayName: displayName?.trim() || email.split('@')[0],
      role: role === 'owner' || role === 'analyst' || role === 'viewer' ? role : 'analyst',
      isActive: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    };

    db.createUser(newUser);
    const token = generateToken(newUser.id);

    db.addAuditLog({
      userId: newUser.id,
      action: 'USER_REGISTERED',
      resourceType: 'user',
      resourceId: newUser.id,
      safeMetadata: { email: newUser.email, role: newUser.role },
    });

    res.status(201).json({
      token,
      user: {
        id: newUser.id,
        email: newUser.email,
        displayName: newUser.displayName,
        role: newUser.role,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Internal registration error' });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400).json({ error: 'Email and password are required.' });
      return;
    }

    const user = db.findUserByEmail(email);
    if (!user || !user.isActive) {
      res.status(401).json({ error: 'Invalid email or password.' });
      return;
    }

    const valid = verifyPassword(password, user.passwordHash, user.passwordSalt);
    if (!valid) {
      res.status(401).json({ error: 'Invalid email or password.' });
      return;
    }

    db.updateUser(user.id, { lastLoginAt: new Date().toISOString() });
    const token = generateToken(user.id);

    db.addAuditLog({
      userId: user.id,
      action: 'USER_LOGIN',
      resourceType: 'user',
      resourceId: user.id,
      safeMetadata: { email: user.email },
    });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        role: user.role,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Internal login error' });
  }
});

app.post('/api/auth/logout', requireAuth, (req: AuthenticatedRequest, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    revokeToken(authHeader.substring(7));
  }
  res.json({ success: true, message: 'Logged out successfully.' });
});

app.get('/api/auth/me', (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    // If not authenticated, return null user so frontend can offer demo login or custom login
    res.json({ user: null });
    return;
  }
  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      displayName: req.user.displayName,
      role: req.user.role,
    },
  });
});

// ==========================================
// 2. DASHBOARD SUMMARY ENDPOINTS
// ==========================================

app.get('/api/dashboard/summary', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const summary = db.getDashboardSummary(req.user!.id);
    res.json(summary);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dashboard/recent-scans', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const scans = db.getScanJobs(req.user!.id).slice(0, 10);
    res.json(scans);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dashboard/recent-findings', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const scans = db.getScanJobs(req.user!.id);
    const scanIds = new Set(scans.map(s => s.id));
    const findings = db.getFindings().filter(f => scanIds.has(f.scanJobId)).slice(0, 15);
    res.json(findings);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 3. SCANNING & TARGET VALIDATION ENDPOINTS
// ==========================================

app.post('/api/scans/validate-target', async (req, res) => {
  try {
    const { targetUrl } = req.body;
    if (!targetUrl) {
      res.status(400).json({ valid: false, error: 'Target URL is required.' });
      return;
    }
    const val = await validateScanTarget(targetUrl, false);
    res.json(val);
  } catch (err: any) {
    res.status(500).json({ valid: false, error: err.message || 'Validation error' });
  }
});

app.post('/api/scans', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const {
      targetUrl,
      scanProfile = 'owasp_standard',
      selectedTools = ['http_headers', 'tls_ssl', 'whatweb', 'owasp_zap', 'nuclei'],
      enableNetworkChecks = false,
      authorizationConfirmed = false,
    } = req.body;

    if (!targetUrl) {
      res.status(400).json({ error: 'Target URL is required.' });
      return;
    }

    if (!authorizationConfirmed) {
      res.status(403).json({
        error: 'Target authorization declaration must be explicitly accepted prior to executing security audits.',
      });
      return;
    }

    // SSRF & target resolution check
    const validation = await validateScanTarget(targetUrl, false);
    if (!validation.valid) {
      res.status(400).json({
        error: `Target rejected by SSRF guard: ${validation.error}`,
      });
      return;
    }

    const scanId = `scan_${crypto.randomBytes(8).toString('hex')}`;
    const newJob: ScanJob = {
      id: scanId,
      userId: req.user!.id,
      targetUrl: validation.sanitizedUrl,
      targetHost: validation.hostname,
      resolvedIp: validation.resolvedIp,
      scanProfile,
      selectedTools,
      enableNetworkChecks: Boolean(enableNetworkChecks),
      authorizationConfirmedAt: new Date().toISOString(),
      status: 'queued',
      metrics: {
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        totalFindings: 0,
      },
      createdAt: new Date().toISOString(),
    };

    db.createScanJob(newJob);

    db.addAuditLog({
      userId: req.user!.id,
      action: 'SCAN_INITIATED',
      resourceType: 'scan_job',
      resourceId: scanId,
      safeMetadata: {
        target: newJob.targetUrl,
        profile: scanProfile,
        tools: selectedTools,
      },
    });

    // Launch background asynchronous scan worker
    setTimeout(() => {
      executeScanJobAsync(scanId).catch(err => {
        console.error('Asynchronous scan job execution encountered error:', err);
      });
    }, 100);

    res.status(202).json({
      message: 'Scan job successfully initialized and queued for background execution.',
      scan: newJob,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to initialize scan' });
  }
});

app.get('/api/scans', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const scans = db.getScanJobs(req.user!.id);
    res.json(scans);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/scans/:scan_id', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const job = db.getScanJobById(req.params.scan_id);
    if (!job) {
      res.status(404).json({ error: 'Scan job not found.' });
      return;
    }

    if (job.userId !== req.user!.id && req.user!.role !== 'owner') {
      res.status(403).json({ error: 'You are not authorized to view this scan.' });
      return;
    }

    const runs = db.getScannerRunsByScanId(job.id);
    const findings = db.getFindings(job.id);

    res.json({
      scan: job,
      runs,
      findings,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/scans/:scan_id/cancel', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const job = db.getScanJobById(req.params.scan_id);
    if (!job) {
      res.status(404).json({ error: 'Scan job not found.' });
      return;
    }

    if (job.userId !== req.user!.id && req.user!.role !== 'owner') {
      res.status(403).json({ error: 'Unauthorized to modify this scan.' });
      return;
    }

    const cancelled = cancelScanJob(job.id);
    if (cancelled) {
      res.json({ success: true, message: 'Scan cancellation requested.' });
    } else {
      res.status(400).json({ error: 'Scan job is not in a cancellable state.' });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/scans/:scan_id', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const job = db.getScanJobById(req.params.scan_id);
    if (!job) {
      res.status(404).json({ error: 'Scan job not found.' });
      return;
    }

    if (job.userId !== req.user!.id && req.user!.role !== 'owner') {
      res.status(403).json({ error: 'Unauthorized to delete this scan.' });
      return;
    }

    db.deleteScanJob(job.id);
    res.json({ success: true, message: 'Scan job deleted.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/scans/:scan_id/report', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const job = db.getScanJobById(req.params.scan_id);
    if (!job) {
      res.status(404).json({ error: 'Scan job not found.' });
      return;
    }

    if (job.userId !== req.user!.id && req.user!.role !== 'owner') {
      res.status(403).json({ error: 'Unauthorized.' });
      return;
    }

    const runs = db.getScannerRunsByScanId(job.id);
    const findings = db.getFindings(job.id);

    const aiMap = new Map();
    for (const f of findings) {
      const ai = db.getAiAnalysisByFindingId(f.id);
      if (ai) aiMap.set(f.id, ai);
    }

    const format = req.query.format === 'json' ? 'json' : 'html';
    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="secure-lens-audit-${job.targetHost}.json"`);
      res.json({
        reportMetadata: {
          platform: 'Secure Lens Web Security Platform',
          version: '1.0.0',
          generatedAt: new Date().toISOString(),
        },
        scan: job,
        scannerRuns: runs,
        findings,
        aiAnalyses: Array.from(aiMap.values()),
      });
      return;
    }

    const html = generateHtmlReport(job, runs, findings, aiMap);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 4. FINDINGS & AI ANALYSIS ENDPOINTS
// ==========================================

app.get('/api/findings', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const scans = db.getScanJobs(req.user!.id);
    const scanIds = new Set(scans.map(s => s.id));
    const findings = db.getFindings().filter(f => scanIds.has(f.scanJobId));
    res.json(findings);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/findings/:finding_id', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const finding = db.getFindingById(req.params.finding_id);
    if (!finding) {
      res.status(404).json({ error: 'Finding not found.' });
      return;
    }

    const scan = db.getScanJobById(finding.scanJobId);
    if (scan && scan.userId !== req.user!.id && req.user!.role !== 'owner') {
      res.status(403).json({ error: 'Unauthorized to view this finding.' });
      return;
    }

    const aiAnalysis = db.getAiAnalysisByFindingId(finding.id);
    res.json({
      finding,
      aiAnalysis: aiAnalysis || null,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/findings/:finding_id/analyze-ai', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const finding = db.getFindingById(req.params.finding_id);
    if (!finding) {
      res.status(404).json({ error: 'Finding not found.' });
      return;
    }

    const analysis = await analyzeFindingWithAI(finding);
    db.saveAiAnalysis(analysis);

    db.addAuditLog({
      userId: req.user!.id,
      action: 'AI_ANALYSIS_EXECUTED',
      resourceType: 'finding',
      resourceId: finding.id,
      safeMetadata: { findingTitle: finding.title, model: analysis.model },
    });

    res.json(analysis);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/ai/copilot-query', requireAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const { question, targetUrl, findingTitle } = req.body;
    if (!question || typeof question !== 'string') {
      res.status(400).json({ error: 'Question string is required.' });
      return;
    }

    const answer = await askSecurityCopilot({
      question,
      targetUrl: targetUrl || 'Unknown Host',
      findingTitle,
    });

    res.json({ answer });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 5. TOOL STATUS & SETTINGS ENDPOINTS
// ==========================================

app.get('/api/tools', (req, res) => {
  res.json(SCANNER_REGISTRY);
});

app.get('/api/tools/status', (req, res) => {
  res.json({
    activeEnginesCount: SCANNER_REGISTRY.length,
    tools: SCANNER_REGISTRY,
  });
});

app.get('/api/settings/ai/status', (req, res) => {
  const status = getAiStatus();
  res.json(status);
});

app.post('/api/settings/ai/test', requireAuth, async (req, res) => {
  const testRes = await testAiConnection();
  res.json(testRes);
});

app.get('/api/audit-logs', requireAuth, (req: AuthenticatedRequest, res) => {
  try {
    const logs = db.getAuditLogs(req.user!.role === 'owner' ? undefined : req.user!.id);
    res.json(logs);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// VITE DEV SERVER / STATIC ASSET MIDDLEWARE
// ==========================================

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, () => {
    console.log(`[Secure Lens] Platform operational on port ${PORT}`);
  });
}

startServer();
