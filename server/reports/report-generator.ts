import { ScanJob, ScannerFinding, ScannerRun, AIAnalysisResult } from '../scanners/types.js';

export function generateHtmlReport(
  job: ScanJob,
  runs: ScannerRun[],
  findings: ScannerFinding[],
  aiAnalyses: Map<string, AIAnalysisResult>
): string {
  const critFindings = findings.filter(f => f.severity === 'CRITICAL');
  const highFindings = findings.filter(f => f.severity === 'HIGH');
  const medFindings = findings.filter(f => f.severity === 'MEDIUM');
  const lowFindings = findings.filter(f => f.severity === 'LOW');
  const infoFindings = findings.filter(f => f.severity === 'INFO');

  const escapeHtml = (str?: string) =>
    (str || '').replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;',
    }[tag] || tag));

  const severityBadgeClass = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'background:#ef4444; color:#ffffff;';
      case 'HIGH': return 'background:#f97316; color:#ffffff;';
      case 'MEDIUM': return 'background:#eab308; color:#18181b;';
      case 'LOW': return 'background:#3b82f6; color:#ffffff;';
      default: return 'background:#64748b; color:#ffffff;';
    }
  };

  const findingsHtml = findings.map((f, idx) => {
    const ai = aiAnalyses.get(f.id);
    return `
      <div style="border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 24px; padding: 20px; page-break-inside: avoid; background:#ffffff;">
        <div style="display:flex; justify-content:space-between; align-items:center; border-bottom: 1px solid #f1f5f9; padding-bottom: 12px; margin-bottom: 14px;">
          <div>
            <span style="display:inline-block; padding: 3px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; margin-right: 8px; ${severityBadgeClass(f.severity)}">
              ${f.severity}
            </span>
            <span style="font-size:12px; color:#64748b; font-weight:600;">${escapeHtml(f.scannerName)}</span>
          </div>
          <span style="font-size:12px; color:#94a3b8;">Finding #${idx + 1}</span>
        </div>

        <h3 style="margin: 0 0 10px 0; color: #0f172a; font-size: 17px; font-weight: 700;">${escapeHtml(f.title)}</h3>
        <p style="color: #475569; font-size: 13px; line-height: 1.6; margin: 0 0 14px 0;">${escapeHtml(f.description)}</p>

        <div style="background: #f8fafc; border-radius: 6px; padding: 12px; margin-bottom: 14px; font-size: 12px;">
          <div style="margin-bottom: 6px;"><strong style="color:#334155;">Target Endpoint:</strong> <code style="color:#0284c7;">${escapeHtml(f.affectedUrl)}</code></div>
          ${f.cwe ? `<div style="margin-bottom: 6px;"><strong style="color:#334155;">CWE Reference:</strong> ${escapeHtml(f.cwe)}</div>` : ''}
          ${f.owaspCategory ? `<div style="margin-bottom: 6px;"><strong style="color:#334155;">OWASP Category:</strong> ${escapeHtml(f.owaspCategory)}</div>` : ''}
          <div><strong style="color:#334155;">Verification Status:</strong> ${escapeHtml(f.verificationStatus)} (Confidence: ${escapeHtml(f.confidence)})</div>
        </div>

        <!-- Raw Scanner Evidence -->
        <div style="margin-bottom: 14px;">
          <div style="font-size: 12px; font-weight: 700; color: #334155; margin-bottom: 6px;">[Raw Scanner Evidence]</div>
          <pre style="background: #0f172a; color: #38bdf8; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 11px; overflow-x: auto; margin:0;">${escapeHtml(f.evidence.rawHeader || f.evidence.snippet || JSON.stringify(f.evidence.details || {}, null, 2))}</pre>
        </div>

        <!-- AI Remediation Advice -->
        ${ai ? `
          <div style="border-left: 3px solid #06b6d4; background: #f0fdfa; border-radius: 0 6px 6px 0; padding: 14px; margin-top: 14px;">
            <div style="display:flex; align-items:center; margin-bottom: 8px;">
              <span style="background: #0d9488; color: #ffffff; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; margin-right: 8px;">AI REMEDIATION ANALYSIS</span>
              <span style="font-size: 11px; color: #0f766e;">Engine: ${escapeHtml(ai.provider)} (${escapeHtml(ai.model)})</span>
            </div>
            <div style="font-size: 13px; color: #134e4a; margin-bottom: 8px;"><strong>Impact:</strong> ${escapeHtml(ai.impact.technicalImpact)} ${escapeHtml(ai.impact.businessImpact)}</div>
            <div style="font-size: 13px; color: #134e4a; margin-bottom: 8px;"><strong>Remediation Strategy:</strong> ${escapeHtml(ai.remediation.overview)}</div>
            ${ai.remediation.codeFixes.length > 0 ? `
              <div style="margin-top: 8px;">
                <strong style="font-size:11px; color:#0f766e;">Suggested Platform Code:</strong>
                ${ai.remediation.codeFixes.map(fix => `
                  <div style="margin-top: 6px;">
                    <div style="font-size: 10px; font-weight: 700; color: #047857;">[${escapeHtml(fix.platform)}]</div>
                    <pre style="background: #1e293b; color: #a7f3d0; padding: 8px; border-radius: 4px; font-size: 11px; margin: 2px 0 0 0;">${escapeHtml(fix.code)}</pre>
                  </div>
                `).join('')}
              </div>
            ` : ''}
          </div>
        ` : `
          <div style="background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 6px; padding: 10px; font-size: 12px; color: #64748b;">
            <strong>Standard Remediation:</strong> ${escapeHtml(f.remediation || 'Apply standard defense-in-depth secure configurations.')}
          </div>
        `}
      </div>
    `;
  }).join('');

  const toolExecutionRows = runs.map(r => `
    <tr>
      <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; font-weight:600; color:#1e293b;">${escapeHtml(r.scannerName)}</td>
      <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; color:#64748b;">${escapeHtml(r.scannerVersion)}</td>
      <td style="padding: 10px; border-bottom: 1px solid #e2e8f0;">
        <span style="display:inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 700; ${r.status === 'completed' ? 'background:#dcfce7; color:#15803d;' : r.status === 'failed' ? 'background:#fee2e2; color:#b91c1c;' : 'background:#f1f5f9; color:#475569;'}">
          ${r.status.toUpperCase()}
        </span>
      </td>
      <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; color:#475569;">${r.durationSeconds || 0}s</td>
      <td style="padding: 10px; border-bottom: 1px solid #e2e8f0; color:#475569;">${r.findingsCount} findings</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Assessment Report - ${escapeHtml(job.targetHost)} - Secure Lens</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 40px;
      color: #0f172a;
      background: #f8fafc;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    .report-card {
      max-width: 900px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 40px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
    }
    @media print {
      body { background: #ffffff; padding: 0; }
      .report-card { border: none; box-shadow: none; padding: 20px; }
      .no-print { display: none; }
    }
  </style>
</head>
<body>
  <div class="report-card">
    <!-- Header -->
    <div style="display:flex; justify-content:space-between; align-items:flex-start; border-bottom: 2px solid #0f172a; padding-bottom: 24px; margin-bottom: 30px;">
      <div>
        <div style="display:flex; align-items:center; gap: 10px; margin-bottom: 6px;">
          <div style="width: 24px; height: 24px; background: #0284c7; border-radius: 6px; display:flex; align-items:center; justify-content:center; color:#fff; font-weight:bold; font-size:14px;">L</div>
          <span style="font-size: 22px; font-weight: 800; letter-spacing: -0.5px; color:#0f172a;">SECURE LENS</span>
          <span style="font-size: 11px; background: #e0f2fe; color: #0369a1; padding: 2px 8px; border-radius: 4px; font-weight: 700;">SECURITY AUDIT</span>
        </div>
        <div style="font-size: 13px; color: #64748b;">Automated Web Vulnerability & Defensive Posture Assessment</div>
      </div>
      <div style="text-align: right;">
        <div style="font-size: 13px; font-weight: 700; color: #1e293b;">Report Generated</div>
        <div style="font-size: 12px; color: #64748b;">${new Date(job.completedAt || job.createdAt).toUTCString()}</div>
      </div>
    </div>

    <!-- Target Executive Summary -->
    <div style="display:grid; grid-template-columns: 2fr 1fr; gap: 20px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px; margin-bottom: 30px;">
      <div>
        <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 6px;">TARGET DETAILS</div>
        <div style="font-size: 18px; font-weight: 800; color: #0284c7; margin-bottom: 8px;">${escapeHtml(job.targetUrl)}</div>
        <div style="font-size: 12px; color: #475569; line-height: 1.5;">
          <strong>Target Host:</strong> ${escapeHtml(job.targetHost)}<br>
          <strong>Resolved IP:</strong> ${escapeHtml(job.resolvedIp || 'N/A')}<br>
          <strong>Scan Profile:</strong> ${escapeHtml(job.scanProfile)} | <strong>Duration:</strong> ${job.durationSeconds || 0} seconds
        </div>
      </div>
      <div style="text-align: center; border-left: 1px solid #e2e8f0; padding-left: 20px;">
        <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 4px;">SECURITY RATING</div>
        <div style="font-size: 38px; font-weight: 900; font-family: monospace; color: ${(job.securityScore || 7) >= 7 ? '#059669' : (job.securityScore || 7) >= 5 ? '#d97706' : '#dc2626'};">
          ${(job.securityScore || 7.0).toFixed(1)} <span style="font-size: 18px; color:#64748b;">/ 10</span>
        </div>
        <div style="font-size: 11px; font-weight: 600; color: #475569;">Grade: ${job.grade || 'A'} • ${findings.length} findings</div>
      </div>
    </div>

    <!-- Severity Distribution Breakdown -->
    <div style="display:grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 30px;">
      <div style="background:#fef2f2; border:1px solid #fecaca; border-radius:8px; padding:12px; text-align:center;">
        <div style="font-size:24px; font-weight:800; color:#dc2626;">${critFindings.length}</div>
        <div style="font-size:11px; font-weight:700; color:#991b1b;">CRITICAL</div>
      </div>
      <div style="background:#fff7ed; border:1px solid #fed7aa; border-radius:8px; padding:12px; text-align:center;">
        <div style="font-size:24px; font-weight:800; color:#ea580c;">${highFindings.length}</div>
        <div style="font-size:11px; font-weight:700; color:#9a3412;">HIGH</div>
      </div>
      <div style="background:#fefce8; border:1px solid #fef08a; border-radius:8px; padding:12px; text-align:center;">
        <div style="font-size:24px; font-weight:800; color:#ca8a04;">${medFindings.length}</div>
        <div style="font-size:11px; font-weight:700; color:#854d0e;">MEDIUM</div>
      </div>
      <div style="background:#eff6ff; border:1px solid #bfdbfe; border-radius:8px; padding:12px; text-align:center;">
        <div style="font-size:24px; font-weight:800; color:#2563eb;">${lowFindings.length}</div>
        <div style="font-size:11px; font-weight:700; color:#1e40af;">LOW</div>
      </div>
      <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:12px; text-align:center;">
        <div style="font-size:24px; font-weight:800; color:#475569;">${infoFindings.length}</div>
        <div style="font-size:11px; font-weight:700; color:#334155;">INFO</div>
      </div>
    </div>

    <!-- Scanner Execution Methodology -->
    <div style="margin-bottom: 30px;">
      <h2 style="font-size: 16px; font-weight: 800; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-bottom: 12px;">
        1. Tool Execution & Methodology
      </h2>
      <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
        <thead>
          <tr style="background:#f1f5f9; text-align:left;">
            <th style="padding: 8px 10px; color:#475569;">Scanner Engine</th>
            <th style="padding: 8px 10px; color:#475569;">Version</th>
            <th style="padding: 8px 10px; color:#475569;">Status</th>
            <th style="padding: 8px 10px; color:#475569;">Duration</th>
            <th style="padding: 8px 10px; color:#475569;">Discovered</th>
          </tr>
        </thead>
        <tbody>
          ${toolExecutionRows}
        </tbody>
      </table>
    </div>

    <!-- Findings & Evidence Section -->
    <div style="margin-bottom: 30px;">
      <h2 style="font-size: 16px; font-weight: 800; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin-bottom: 16px;">
        2. Detailed Findings, Evidence & AI Remediation
      </h2>
      ${findings.length === 0 ? `
        <div style="padding: 24px; background: #ecfdf5; border-radius: 8px; color: #065f46; font-size: 14px;">
          No security vulnerabilities or configuration defects were discovered across the executed tool suite.
        </div>
      ` : findingsHtml}
    </div>

    <!-- Assessment Scope & Limitations -->
    <div style="border-top: 1px solid #e2e8f0; padding-top: 20px; font-size: 11px; color: #64748b; line-height: 1.6;">
      <strong style="color: #334155;">ASSESSMENT SCOPE & LEGAL NOTICE:</strong> This assessment report was conducted automatically based on passive web probes, TLS handshake analysis, HTTP header inspection, and non-intrusive heuristic checks against authorized endpoints. It does not replace a comprehensive manual penetration test or full source-code security audit. Observable scanner evidence is strictly separated from AI-generated remediation guidance.
    </div>

    <div class="no-print" style="margin-top: 30px; text-align: center;">
      <button onclick="window.print()" style="background: #0284c7; color: #ffffff; border: none; padding: 10px 24px; font-weight: 700; border-radius: 6px; cursor: pointer;">
        Print / Save as PDF
      </button>
    </div>
  </div>
</body>
</html>`;
}
