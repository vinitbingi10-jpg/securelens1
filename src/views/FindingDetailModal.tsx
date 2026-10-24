import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ScannerFinding, AIAnalysisResult } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import {
  X,
  Sparkles,
  RotateCw,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  Terminal,
  Code,
  BookOpen,
  Info,
} from 'lucide-react';

interface Props {
  finding: ScannerFinding | null;
  onClose: () => void;
  onOpenCopilot: (targetUrl: string, findingTitle: string) => void;
}

export const FindingDetailModal: React.FC<Props> = ({ finding, onClose, onOpenCopilot }) => {
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysisResult | null>(null);
  const [loadingAi, setLoadingAi] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);

  useEffect(() => {
    if (!finding) return;

    const fetchDetail = async () => {
      try {
        const data = await api.getFindingById(finding.id);
        setAiAnalysis(data.aiAnalysis);
      } catch (err) {
        console.error('Failed to load finding details:', err);
      }
    };

    fetchDetail();
  }, [finding]);

  if (!finding) return null;

  const handleRunAiAnalysis = async () => {
    setLoadingAi(true);
    try {
      const result = await api.requestAiAnalysis(finding.id);
      setAiAnalysis(result);
    } catch (err) {
      console.error('AI analysis request failed:', err);
    } finally {
      setLoadingAi(false);
    }
  };

  const handleCopyCode = (code: string, idx: number) => {
    navigator.clipboard.writeText(code);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCopyCurl = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-950/80 backdrop-blur-sm p-4 sm:p-6 flex items-center justify-center">
      <div className="w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-start justify-between bg-slate-950/60">
          <div className="space-y-1 pr-6">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={finding.severity} size="md" />
              <span className="text-xs text-slate-400 font-semibold">{finding.scannerName}</span>
              <span className="text-xs text-slate-600">•</span>
              <span className="text-xs font-mono text-cyan-400">{finding.category}</span>
            </div>
            <h2 className="text-lg font-bold text-white pt-1">{finding.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer"
          >
            <X size={18} />
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Target URL & Verification Status */}
          <div className="bg-slate-950 border border-slate-800/80 rounded-xl p-4 text-xs space-y-2">
            <div className="flex items-center gap-2 text-slate-300">
              <strong className="text-slate-400">Target Endpoint:</strong>
              <code className="text-cyan-400 font-mono break-all">{finding.affectedUrl}</code>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-slate-400 pt-1 border-t border-slate-800/60">
              <div>Verification: <strong className="text-slate-200">{finding.verificationStatus}</strong></div>
              <div>Confidence: <strong className="text-slate-200">{finding.confidence}</strong></div>
              <div>First Seen: <span className="text-slate-200">{new Date(finding.firstSeenAt).toLocaleDateString()}</span></div>
              {finding.cwe && <div className="col-span-2 sm:col-span-1">CWE: <span className="text-cyan-400 font-mono">{finding.cwe}</span></div>}
              {finding.owaspCategory && <div className="col-span-2">OWASP: <span className="text-slate-200">{finding.owaspCategory}</span></div>}
            </div>
          </div>

          {/* Description */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Vulnerability Description</h3>
            <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/40 p-3 rounded-lg border border-slate-800/60">
              {finding.description}
            </p>
          </div>

          {/* Raw Scanner Evidence */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Terminal size={13} className="text-slate-400" />
                <span>Observable Scanner Evidence</span>
              </h3>
              <span className="text-[10px] text-slate-500 font-mono">Unmodified Scanner Payload</span>
            </div>
            <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-[11px] font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap">
              {finding.evidence.rawHeader ||
                finding.evidence.snippet ||
                JSON.stringify(finding.evidence.details || {}, null, 2) ||
                'No raw text payload captured for this check.'}
            </pre>
          </div>

          {/* AI-Grounded Remediation Analysis */}
          <div className="rounded-xl border border-cyan-800/60 bg-gradient-to-br from-slate-950 via-slate-900 to-cyan-950/20 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-cyan-800/40 pb-3">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-md bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
                  <Sparkles size={15} />
                </div>
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                    AI Remediation & Security Engineering Guidance
                  </h3>
                  <div className="text-[10px] text-slate-400">
                    {aiAnalysis ? `Analyzed by ${aiAnalysis.provider} (${aiAnalysis.model})` : 'Awaiting live model analysis'}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleRunAiAnalysis}
                  disabled={loadingAi}
                  className="px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 border border-cyan-700/80 text-cyan-300 text-xs font-semibold transition cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
                >
                  <RotateCw size={13} className={loadingAi ? 'animate-spin' : ''} />
                  <span>{loadingAi ? 'Analyzing...' : aiAnalysis ? 'Regenerate Analysis' : 'Analyze Finding with AI'}</span>
                </button>
              </div>
            </div>

            {aiAnalysis ? (
              <div className="space-y-4 text-xs">
                {/* Explanation */}
                <div className="space-y-1">
                  <div className="font-semibold text-slate-200">Executive Summary & Impact:</div>
                  <p className="text-slate-300 leading-relaxed">{aiAnalysis.explanation}</p>
                </div>

                {/* Business & Tech Impact */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <div>
                    <div className="text-[11px] font-bold text-rose-400 mb-0.5">Technical Impact</div>
                    <p className="text-slate-300 text-[11px] leading-relaxed">{aiAnalysis.impact.technicalImpact}</p>
                  </div>
                  <div>
                    <div className="text-[11px] font-bold text-amber-400 mb-0.5">Business & Compliance Impact</div>
                    <p className="text-slate-300 text-[11px] leading-relaxed">{aiAnalysis.impact.businessImpact}</p>
                  </div>
                </div>

                {/* Remediation Overview */}
                <div className="space-y-1">
                  <div className="font-semibold text-slate-200">Recommended Fix Strategy:</div>
                  <p className="text-slate-300 leading-relaxed">{aiAnalysis.remediation.overview}</p>
                </div>

                {/* Code Fix Snippets */}
                {aiAnalysis.remediation.codeFixes && aiAnalysis.remediation.codeFixes.length > 0 && (
                  <div className="space-y-2 pt-1">
                    <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                      <Code size={14} className="text-cyan-400" />
                      <span>Production Configuration Code:</span>
                    </div>

                    <div className="space-y-2">
                      {aiAnalysis.remediation.codeFixes.map((fix, idx) => (
                        <div key={idx} className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
                          <div className="px-3 py-1.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                            <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wide">
                              {fix.platform}
                            </span>
                            <button
                              onClick={() => handleCopyCode(fix.code, idx)}
                              className="text-[11px] text-slate-400 hover:text-white flex items-center gap-1 transition cursor-pointer"
                            >
                              {copiedIndex === idx ? (
                                <>
                                  <Check size={12} className="text-emerald-400" />
                                  <span className="text-emerald-400">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy size={12} />
                                  <span>Copy</span>
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="p-3 text-[11px] font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                            {fix.code}
                          </pre>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Verification CLI steps */}
                {aiAnalysis.remediation.verificationSteps && aiAnalysis.remediation.verificationSteps.length > 0 && (
                  <div className="space-y-2 pt-1">
                    <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                      <Terminal size={14} className="text-cyan-400" />
                      <span>Audit Verification Command:</span>
                    </div>
                    {aiAnalysis.remediation.verificationSteps.map((step, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-[11px] font-mono text-cyan-300"
                      >
                        <code className="truncate pr-2">{step}</code>
                        <button
                          onClick={() => handleCopyCurl(step)}
                          className="text-slate-400 hover:text-white shrink-0 cursor-pointer"
                          title="Copy command"
                        >
                          <Copy size={13} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                {/* Security References */}
                {aiAnalysis.references && aiAnalysis.references.length > 0 && (
                  <div className="space-y-1.5 pt-1">
                    <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                      <BookOpen size={14} className="text-cyan-400" />
                      <span>Authoritative Security References:</span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {aiAnalysis.references.map((ref, idx) => (
                        <a
                          key={idx}
                          href={ref.url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-950 hover:bg-slate-800 text-[11px] text-cyan-300 border border-slate-800 transition"
                        >
                          <span>{ref.title}</span>
                          <ExternalLink size={10} />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-6 space-y-3">
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Click below to generate deep, contextual remediation code snippets and validation curl commands using the configured AI engine.
                </p>
                <button
                  onClick={handleRunAiAnalysis}
                  disabled={loadingAi}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition cursor-pointer"
                >
                  Generate AI Remediation Guidance
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <button
            onClick={() => {
              onClose();
              onOpenCopilot(finding.affectedUrl, finding.title);
            }}
            className="px-3.5 py-2 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800 text-cyan-300 text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer"
          >
            <Sparkles size={14} />
            <span>Consult Security Copilot</span>
          </button>

          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
