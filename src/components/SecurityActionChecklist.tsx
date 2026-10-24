import React, { useState } from 'react';
import { ScannerFinding } from '../types';
import { SeverityBadge } from './SeverityBadge';
import {
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Code2,
  Terminal,
  ExternalLink,
} from 'lucide-react';

interface Props {
  findings: ScannerFinding[];
  targetUrl: string;
  onOpenCopilot: (targetUrl: string, findingTitle?: string) => void;
  onSelectFinding: (finding: ScannerFinding) => void;
}

export const SecurityActionChecklist: React.FC<Props> = ({
  findings,
  targetUrl,
  onOpenCopilot,
  onSelectFinding,
}) => {
  const [expandedId, setExpandedId] = useState<string | null>(findings[0]?.id || null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Group findings into what needs fixing vs informational
  const actionableFindings = findings.filter((f) => f.severity !== 'INFO');
  const infoFindings = findings.filter((f) => f.severity === 'INFO');

  const handleCopyCode = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Summary */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 flex items-center justify-center text-xs font-black">
              {actionableFindings.length}
            </span>
            <span>Security Measures You Need to Add</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Follow this simple prioritized checklist to improve your website's security score.
          </p>
        </div>

        <button
          onClick={() => onOpenCopilot(targetUrl, 'General Checklist Fixes')}
          className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold cursor-pointer"
        >
          <Sparkles size={13} />
          <span>Ask AI Copilot for Full Fix Guide</span>
        </button>
      </div>

      {actionableFindings.length === 0 ? (
        <div className="p-8 rounded-xl bg-emerald-950/20 border border-emerald-800/40 text-center space-y-2">
          <CheckCircle2 size={32} className="mx-auto text-emerald-400" />
          <h3 className="text-sm font-bold text-white">All Key Security Defenses Are Active!</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Your website passed standard tests for headers, TLS configurations, and basic safe practices.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {actionableFindings.map((finding, idx) => {
            const isExpanded = expandedId === finding.id;
            return (
              <div
                key={finding.id}
                className="bg-slate-900 border border-slate-800 hover:border-slate-700/80 rounded-xl overflow-hidden transition"
              >
                {/* Main Row / Card Header */}
                <div
                  onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                  className="p-4 flex items-center justify-between gap-4 cursor-pointer select-none"
                >
                  <div className="flex items-start sm:items-center gap-3 min-w-0">
                    <span className="w-6 h-6 rounded-full bg-slate-800 border border-slate-700 text-slate-300 text-xs font-bold flex items-center justify-center shrink-0">
                      {idx + 1}
                    </span>

                    <div className="space-y-0.5 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-bold text-white hover:text-cyan-400 transition truncate">
                          {finding.title}
                        </span>
                        <SeverityBadge severity={finding.severity} size="sm" showIcon={false} />
                      </div>
                      <p className="text-xs text-slate-400 line-clamp-1">
                        {finding.remediation || finding.description}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onOpenCopilot(targetUrl, finding.title);
                      }}
                      className="hidden sm:flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 text-[11px] font-semibold cursor-pointer"
                    >
                      <Sparkles size={11} />
                      <span>How to Fix</span>
                    </button>
                    {isExpanded ? <ChevronUp size={16} className="text-slate-400" /> : <ChevronDown size={16} className="text-slate-400" />}
                  </div>
                </div>

                {/* Expanded Simple Step-By-Step Solution */}
                {isExpanded && (
                  <div className="p-4 border-t border-slate-800/80 bg-slate-950/60 space-y-3 text-xs">
                    <div className="space-y-1">
                      <div className="font-semibold text-slate-300">Why this matters:</div>
                      <p className="text-slate-400 leading-relaxed">{finding.description}</p>
                    </div>

                    <div className="space-y-1.5">
                      <div className="font-semibold text-slate-300 flex items-center justify-between">
                        <span>How to fix it:</span>
                        <span className="text-[11px] text-slate-500 font-mono">Suggested Code</span>
                      </div>

                      <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 font-mono text-[11px] text-emerald-300 relative group">
                        <div className="pr-16 whitespace-pre-wrap">
                          {finding.remediation || 'Apply standard defense-in-depth secure configurations.'}
                        </div>
                        <button
                          type="button"
                          onClick={() => handleCopyCode(finding.remediation || '', finding.id)}
                          className="absolute top-2.5 right-2.5 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-semibold flex items-center gap-1 cursor-pointer transition"
                        >
                          {copiedId === finding.id ? (
                            <>
                              <Check size={11} className="text-emerald-400" />
                              <span className="text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy size={11} />
                              <span>Copy Fix</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>

                    <div className="flex items-center justify-between pt-1 text-[11px] text-slate-400">
                      <span>Affected URL: <code className="text-slate-300">{finding.affectedUrl}</code></span>
                      <button
                        type="button"
                        onClick={() => onSelectFinding(finding)}
                        className="text-cyan-400 hover:underline font-semibold cursor-pointer"
                      >
                        View Full Technical Details & Curl Test →
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Verified Passing Checks */}
      <div className="border border-slate-800/60 rounded-xl p-4 bg-slate-900/40 space-y-2">
        <h3 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
          <CheckCircle2 size={14} className="text-emerald-400" />
          <span>Already Active & Passing Checks</span>
        </h3>
        <p className="text-xs text-slate-400">
          The scanner checked for exposed .git folders, untrusted certificate chains, and dangerous open ports. No immediate critical compromise was observed on verified passive checks.
        </p>
      </div>
    </div>
  );
};
