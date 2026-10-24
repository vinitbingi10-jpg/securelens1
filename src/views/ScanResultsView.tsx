import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ScanJob, ScannerRun, ScannerFinding } from '../types';
import { ScoreGauge } from '../components/ScoreGauge';
import { SecurityActionChecklist } from '../components/SecurityActionChecklist';
import { SeverityBadge } from '../components/SeverityBadge';
import {
  ArrowLeft,
  Printer,
  Download,
  ListChecks,
  Code2,
  Globe,
  Clock,
  Sparkles,
  ExternalLink,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

interface Props {
  scanId: string;
  onBack: () => void;
  onSelectFinding: (finding: ScannerFinding) => void;
  onOpenCopilot: (targetUrl: string, findingTitle?: string) => void;
}

export const ScanResultsView: React.FC<Props> = ({
  scanId,
  onBack,
  onSelectFinding,
  onOpenCopilot,
}) => {
  const [scan, setScan] = useState<ScanJob | null>(null);
  const [runs, setRuns] = useState<ScannerRun[]>([]);
  const [findings, setFindings] = useState<ScannerFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<'checklist' | 'technical'>('checklist');
  const [expandedEvidence, setExpandedEvidence] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const fetchResults = async () => {
      try {
        setLoading(true);
        const data = await api.getScanById(scanId);
        setScan(data.scan);
        setRuns(data.runs);
        setFindings(data.findings);
      } catch (err: any) {
        setError(err.message || 'Failed to load scan results');
      } finally {
        setLoading(false);
      }
    };

    fetchResults();
  }, [scanId]);

  const toggleEvidence = (id: string) => {
    setExpandedEvidence((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleDownloadHtml = () => {
    const token = api.getToken();
    window.open(`/api/scans/${scanId}/report?token=${token || ''}`, '_blank');
  };

  const handleDownloadJson = () => {
    const token = api.getToken();
    window.open(`/api/scans/${scanId}/report?format=json&token=${token || ''}`, '_blank');
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center space-y-2">
          <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <div className="text-sm text-slate-400">Evaluating security posture...</div>
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center space-y-4 max-w-md mx-auto">
        <div className="text-rose-400 font-bold">{error || 'Scan not found'}</div>
        <button
          onClick={onBack}
          className="px-4 py-2 rounded-lg bg-slate-800 text-slate-200 text-xs font-semibold cursor-pointer"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  const score = scan.securityScore || 7.0;
  const criticalCount = scan.metrics.criticalCount;
  const highCount = scan.metrics.highCount;
  const needFixesCount = criticalCount + highCount + scan.metrics.mediumCount + scan.metrics.lowCount;

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Clean Top Navigation Bar */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white font-semibold transition cursor-pointer"
        >
          <ArrowLeft size={15} />
          <span>Back to Dashboard</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadHtml}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition cursor-pointer flex items-center gap-1.5"
            title="Download printable report"
          >
            <Printer size={13} />
            <span>Download Report</span>
          </button>
          <button
            onClick={handleDownloadJson}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition cursor-pointer flex items-center gap-1.5"
            title="Download JSON export"
          >
            <Download size={13} />
            <span>JSON</span>
          </button>
        </div>
      </div>

      {/* Main Posture Score Card (Simple & Easy to understand) */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-7 shadow-sm grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
        <div className="md:col-span-2 space-y-3">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Globe size={14} className="text-cyan-400" />
            <span className="font-mono text-slate-300 truncate">{scan.targetUrl}</span>
          </div>

          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            Security Audit Results
          </h1>

          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            {score >= 8.0 ? (
              <span>Your website has a high level of security protection with only minor optimizations recommended.</span>
            ) : score >= 6.0 ? (
              <span>
                Your website has good baseline protection, but is missing <strong>{needFixesCount} important security measures</strong> that leave it open to common attacks.
              </span>
            ) : (
              <span>
                Your website has critical vulnerabilities or missing security headers. Immediate remediation is strongly advised.
              </span>
            )}
          </p>

          <div className="flex items-center gap-4 text-xs text-slate-400 pt-1">
            <span className="flex items-center gap-1">
              <Clock size={12} />
              <span>Audited on {new Date(scan.completedAt || scan.createdAt).toLocaleDateString()}</span>
            </span>
            <span>•</span>
            <span>{findings.length} Total Signals Checked</span>
          </div>
        </div>

        {/* Score Out of 10 Widget */}
        <div>
          <ScoreGauge score={score} totalFindings={findings.length} size="md" />
        </div>
      </div>

      {/* Simple View Switcher: "What to Add" vs "Technical Details" */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('checklist')}
          className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition cursor-pointer ${
            activeTab === 'checklist'
              ? 'bg-cyan-600 text-white shadow-md'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          <ListChecks size={15} />
          <span>Security Measures to Add ({needFixesCount})</span>
        </button>

        <button
          onClick={() => setActiveTab('technical')}
          className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition cursor-pointer ${
            activeTab === 'technical'
              ? 'bg-cyan-600 text-white shadow-md'
              : 'text-slate-400 hover:text-white hover:bg-slate-900'
          }`}
        >
          <Code2 size={15} />
          <span>Raw Technical Details & Headers</span>
        </button>
      </div>

      {/* Tab 1: Clean Action Checklist (Easy to Understand) */}
      {activeTab === 'checklist' && (
        <SecurityActionChecklist
          findings={findings}
          targetUrl={scan.targetUrl}
          onOpenCopilot={onOpenCopilot}
          onSelectFinding={onSelectFinding}
        />
      )}

      {/* Tab 2: Technical Breakdown */}
      {activeTab === 'technical' && (
        <div className="space-y-4">
          <div className="text-xs text-slate-400">
            Advanced findings list with raw HTTP evidence and scanner diagnostic output.
          </div>

          <div className="space-y-3">
            {findings.map((finding) => {
              const isEvidenceOpen = expandedEvidence[finding.id];
              return (
                <div
                  key={finding.id}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3"
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity} size="sm" />
                      <span className="text-xs font-semibold text-white">{finding.title}</span>
                    </div>
                    <span className="text-[11px] text-slate-500 font-mono">{finding.scannerName}</span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>

                  <div className="text-xs text-slate-400 font-mono bg-slate-950 p-2 rounded border border-slate-800">
                    Endpoint: {finding.affectedUrl}
                  </div>

                  <div>
                    <button
                      type="button"
                      onClick={() => toggleEvidence(finding.id)}
                      className="flex items-center gap-1 text-xs text-cyan-400 hover:underline font-semibold cursor-pointer"
                    >
                      <span>{isEvidenceOpen ? 'Hide Raw Header Evidence' : 'View Raw Header Evidence'}</span>
                      {isEvidenceOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                    </button>

                    {isEvidenceOpen && (
                      <pre className="mt-2 p-3 bg-slate-950 border border-slate-800 rounded text-[11px] font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                        {finding.evidence.rawHeader ||
                          finding.evidence.snippet ||
                          JSON.stringify(finding.evidence.details || {}, null, 2) ||
                          'No raw payload recorded.'}
                      </pre>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
