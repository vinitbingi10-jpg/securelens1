import crypto from 'crypto';
import { db } from '../db/database.js';
import { validateScanTarget } from '../security/ssrf.js';
import { scanHttpHeaders } from './http-headers.js';
import { scanTlsSsl } from './tls-ssl.js';
import { scanWhatWeb } from './whatweb.js';
import { scanOwaspZap } from './owasp-zap.js';
import { scanNucleiNonIntrusive } from './nuclei.js';
import { scanNetworkPorts } from './network-nmap.js';
import { analyzeFindingWithAI } from '../ai/gemini-adapter.js';
import { ScanJob, ScannerFinding, ScannerRun } from './types.js';

// In-memory active scan cancellation tokens
const activeCancellations = new Set<string>();

export function cancelScanJob(scanJobId: string): boolean {
  const job = db.getScanJobById(scanJobId);
  if (!job || (job.status !== 'queued' && job.status !== 'running')) {
    return false;
  }
  activeCancellations.add(scanJobId);
  db.updateScanJob(scanJobId, {
    status: 'cancelled',
    completedAt: new Date().toISOString(),
    errorSummary: 'Scan was manually cancelled by authorized user.',
  });
  return true;
}

export function isScanCancelled(scanJobId: string): boolean {
  return activeCancellations.has(scanJobId);
}

export async function executeScanJobAsync(scanJobId: string): Promise<void> {
  const job = db.getScanJobById(scanJobId);
  if (!job) return;

  const startTime = Date.now();
  db.updateScanJob(scanJobId, {
    status: 'running',
    startedAt: new Date().toISOString(),
  });

  const allRawFindings: Array<Omit<ScannerFinding, 'id' | 'scanJobId' | 'scannerRunId' | 'firstSeenAt' | 'createdAt'>> = [];
  let partialFailure = false;

  try {
    // 1. Re-validate target URL and DNS resolution immediately before scanning (Anti-DNS Rebinding)
    const targetVal = await validateScanTarget(job.targetUrl, false);
    if (!targetVal.valid) {
      db.updateScanJob(scanJobId, {
        status: 'failed',
        completedAt: new Date().toISOString(),
        durationSeconds: Math.round((Date.now() - startTime) / 1000),
        errorSummary: `Security validation blocked scan: ${targetVal.error}`,
      });
      return;
    }

    const { hostname, port, protocol } = targetVal;

    // Helper to run an individual scanner tool safely
    const runTool = async (
      toolId: string,
      toolName: string,
      version: string,
      scannerFn: () => Promise<{ findings: any[] }>
    ): Promise<void> => {
      if (isScanCancelled(scanJobId)) return;
      if (!job.selectedTools.includes(toolId)) return;

      const runId = `run_${crypto.randomBytes(6).toString('hex')}`;
      const toolStart = Date.now();

      const run: ScannerRun = {
        id: runId,
        scanJobId,
        scannerName: toolName,
        scannerVersion: version,
        status: 'running',
        startedAt: new Date().toISOString(),
        findingsCount: 0,
      };
      db.createScannerRun(run);

      try {
        const result = await Promise.race([
          scannerFn(),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error(`${toolName} exceeded execution timeout threshold`)), 25000)
          ),
        ]);

        const toolDuration = Math.round((Date.now() - toolStart) / 1000);
        allRawFindings.push(...result.findings);

        db.updateScannerRun(runId, {
          status: 'completed',
          completedAt: new Date().toISOString(),
          durationSeconds: toolDuration,
          findingsCount: result.findings.length,
          resultSummary: `Executed successfully: discovered ${result.findings.length} findings.`,
        });
      } catch (err: any) {
        partialFailure = true;
        const toolDuration = Math.round((Date.now() - toolStart) / 1000);
        db.updateScannerRun(runId, {
          status: 'failed',
          completedAt: new Date().toISOString(),
          durationSeconds: toolDuration,
          errorSummary: err.message || 'Execution failed',
          findingsCount: 0,
        });
      }
    };

    // Run tools in parallel/sequence
    // Tool 1: HTTP Security Headers
    await runTool('http_headers', 'HTTP Security Headers Inspector', 'v2.4.1', async () => {
      const res = await scanHttpHeaders(job.targetUrl);
      return { findings: res.findings };
    });

    if (isScanCancelled(scanJobId)) return;

    // Tool 2: TLS/SSL Certificate Inspector
    if (protocol === 'https:') {
      await runTool('tls_ssl', 'TLS/SSL Certificate Inspector (testssl)', 'v3.2.0', async () => {
        const res = await scanTlsSsl(hostname, port);
        return { findings: res.findings };
      });
    }

    if (isScanCancelled(scanJobId)) return;

    // Tool 3: WhatWeb Technology Fingerprinter
    await runTool('whatweb', 'WhatWeb Technology Fingerprinter', 'v0.5.6', async () => {
      const res = await scanWhatWeb(job.targetUrl);
      return { findings: res.findings };
    });

    if (isScanCancelled(scanJobId)) return;

    // Tool 4: OWASP ZAP Passive Rules
    await runTool('owasp_zap', 'OWASP ZAP Passive Rules Engine', 'v2.14.0', async () => {
      const res = await scanOwaspZap(job.targetUrl);
      return { findings: res.findings };
    });

    if (isScanCancelled(scanJobId)) return;

    // Tool 5: Nuclei Non-Intrusive Engine
    await runTool('nuclei', 'Nuclei Non-Intrusive Engine', 'v3.2.0', async () => {
      const res = await scanNucleiNonIntrusive(job.targetUrl);
      return { findings: res.findings };
    });

    if (isScanCancelled(scanJobId)) return;

    // Tool 6: Network & Ports (Only if explicitly enabled by user)
    if (job.enableNetworkChecks && job.selectedTools.includes('network_nmap')) {
      await runTool('network_nmap', 'Nmap Safe Network Port Scanner', 'v7.94', async () => {
        const res = await scanNetworkPorts(hostname, true);
        return { findings: res.findings };
      });
    }

    if (isScanCancelled(scanJobId)) {
      activeCancellations.delete(scanJobId);
      return;
    }

    // 2. Normalization & Deduplication based on fingerprint
    const seenFingerprints = new Set<string>();
    const deduplicatedFindings: ScannerFinding[] = [];

    const nowIso = new Date().toISOString();
    for (const raw of allRawFindings) {
      if (seenFingerprints.has(raw.fingerprint)) {
        continue;
      }
      seenFingerprints.add(raw.fingerprint);

      const findingId = `fnd_${crypto.randomBytes(8).toString('hex')}`;
      const finding: ScannerFinding = {
        ...raw,
        id: findingId,
        scanJobId,
        firstSeenAt: nowIso,
        createdAt: nowIso,
      };
      deduplicatedFindings.push(finding);
    }

    // Store findings
    db.addFindings(deduplicatedFindings);

    // 3. Trigger AI Analysis for High and Critical findings (and top findings)
    // Run AI analysis asynchronously or sequentially
    const highRiskFindings = deduplicatedFindings.filter(
      f => f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.severity === 'MEDIUM'
    ).slice(0, 5); // Limit to top 5 to respect latency and rate limits

    for (const f of highRiskFindings) {
      try {
        const analysis = await analyzeFindingWithAI(f);
        db.saveAiAnalysis(analysis);
      } catch (err) {
        console.warn('AI analysis failed for finding:', f.id, err);
      }
    }

    // 4. Calculate Final Grade and Metrics
    const criticalCount = deduplicatedFindings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = deduplicatedFindings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = deduplicatedFindings.filter(f => f.severity === 'MEDIUM').length;
    const lowCount = deduplicatedFindings.filter(f => f.severity === 'LOW').length;
    const infoCount = deduplicatedFindings.filter(f => f.severity === 'INFO').length;

    let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'A+';
    if (criticalCount > 0) {
      grade = 'F';
    } else if (highCount >= 2) {
      grade = 'D';
    } else if (highCount === 1) {
      grade = 'C';
    } else if (mediumCount >= 3) {
      grade = 'B';
    } else if (mediumCount > 0 || lowCount > 2) {
      grade = 'A';
    }

    // Security Score out of 10.0
    let score = 10.0;
    score -= criticalCount * 3.0;
    score -= highCount * 1.5;
    score -= mediumCount * 0.6;
    score -= lowCount * 0.2;
    const securityScore = Math.max(1.0, Math.min(10.0, Math.round(score * 10) / 10));

    const totalDuration = Math.round((Date.now() - startTime) / 1000);

    db.updateScanJob(scanJobId, {
      status: partialFailure ? 'partial' : 'completed',
      completedAt: new Date().toISOString(),
      durationSeconds: totalDuration,
      grade,
      securityScore,
      metrics: {
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        infoCount,
        totalFindings: deduplicatedFindings.length,
      },
    });

    db.addAuditLog({
      userId: job.userId,
      action: 'SCAN_COMPLETED',
      resourceType: 'scan_job',
      resourceId: scanJobId,
      safeMetadata: {
        target: job.targetUrl,
        grade,
        totalFindings: deduplicatedFindings.length,
        durationSeconds: totalDuration,
      },
    });
  } catch (err: any) {
    db.updateScanJob(scanJobId, {
      status: 'failed',
      completedAt: new Date().toISOString(),
      durationSeconds: Math.round((Date.now() - startTime) / 1000),
      errorSummary: `Scan failed unexpectedly: ${err.message || 'Unknown execution error'}`,
    });
  } finally {
    activeCancellations.delete(scanJobId);
  }
}
