import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { DashboardSummary, ScanJob, ScannerFinding } from '../types';
import { ScoreGauge } from '../components/ScoreGauge';
import {
  Globe,
  ArrowRight,
  ShieldCheck,
  RotateCw,
  Search,
  CheckCircle2,
  Clock,
  Sparkles,
  AlertTriangle,
} from 'lucide-react';

interface Props {
  onStartNewScan: (prefillUrl?: string) => void;
  onViewScan: (scanId: string) => void;
  onSelectFinding: (finding: ScannerFinding) => void;
  onViewTools: () => void;
}

export const DashboardView: React.FC<Props> = ({
  onStartNewScan,
  onViewScan,
  onSelectFinding,
}) => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [quickUrl, setQuickUrl] = useState('');
  const [error, setError] = useState<string | null>(null);

  const fetchSummary = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getDashboardSummary();
      setSummary(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, []);

  const handleQuickSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (quickUrl.trim()) {
      onStartNewScan(quickUrl.trim());
    } else {
      onStartNewScan();
    }
  };

  if (loading && !summary) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="flex flex-col items-center gap-3 text-slate-400">
          <RotateCw className="w-6 h-6 animate-spin text-cyan-400" />
          <span className="text-xs">Loading security dashboard...</span>
        </div>
      </div>
    );
  }

  // Calculate average score out of 10 from completed scans
  const completedScans = summary?.recentScans.filter((s) => s.status === 'completed') || [];
  const averageScore =
    completedScans.length > 0
      ? completedScans.reduce((acc, s) => acc + (s.securityScore || 6.5), 0) / completedScans.length
      : 7.5;

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Friendly, Simple Scan Bar (No Confusion, No Clutter) */}
      <div className="text-center space-y-4 py-4">
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Website Security Scanner
        </h1>
        <p className="text-sm text-slate-400 max-w-lg mx-auto">
          Test any website for security headers, SSL certificates, and common vulnerabilities. Get a clear score out of 10 and a simple fix checklist.
        </p>

        {/* Big Clean Search Box */}
        <form onSubmit={handleQuickSubmit} className="max-w-xl mx-auto pt-2">
          <div className="flex flex-col sm:flex-row gap-2 bg-slate-900 border border-slate-800 p-1.5 rounded-xl shadow-lg">
            <div className="relative flex-1 flex items-center">
              <Globe size={18} className="absolute left-3.5 text-slate-500" />
              <input
                type="text"
                value={quickUrl}
                onChange={(e) => setQuickUrl(e.target.value)}
                placeholder="Enter website URL (e.g. https://mywebsite.com)"
                className="w-full pl-10 pr-3 py-2.5 bg-transparent text-sm text-white focus:outline-none placeholder:text-slate-500"
              />
            </div>
            <button
              type="submit"
              className="px-6 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs uppercase tracking-wider transition cursor-pointer flex items-center justify-center gap-1.5"
            >
              <span>Test Security</span>
              <ArrowRight size={14} />
            </button>
          </div>
          <div className="text-[11px] text-slate-500 mt-2">
            Safe, non-destructive scanning • Instant rating out of 10
          </div>
        </form>
      </div>

      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle size={15} />
          <span>{error}</span>
        </div>
      )}

      {/* Simple 3-Card Summary (Breathable, Clean) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-800/80 rounded-xl p-5 space-y-1">
          <div className="text-xs font-medium text-slate-400">Average Security Rating</div>
          <div className="text-2xl font-black text-cyan-400 font-mono">
            {averageScore.toFixed(1)} <span className="text-base text-slate-500 font-normal">/ 10</span>
          </div>
          <div className="text-[11px] text-slate-500">Across your audited websites</div>
        </div>

        <div className="bg-slate-900 border border-slate-800/80 rounded-xl p-5 space-y-1">
          <div className="text-xs font-medium text-slate-400">Total Scans Executed</div>
          <div className="text-2xl font-black text-white">{summary?.totalScans ?? 0}</div>
          <div className="text-[11px] text-slate-500">{summary?.completedScans ?? 0} successfully completed</div>
        </div>

        <div className="bg-slate-900 border border-slate-800/80 rounded-xl p-5 space-y-1">
          <div className="text-xs font-medium text-slate-400">Security Items to Fix</div>
          <div className="text-2xl font-black text-amber-400">
            {(summary?.criticalFindings || 0) + (summary?.highFindings || 0) + (summary?.mediumFindings || 0)}
          </div>
          <div className="text-[11px] text-slate-500">Action items across all targets</div>
        </div>
      </div>

      {/* Recent Scans (Simplified Table with Score out of 10) */}
      <div className="bg-slate-900 border border-slate-800/80 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-bold text-white">Recent Website Audits</h2>
            <p className="text-xs text-slate-400">Click any site to see its score and what security to add</p>
          </div>
          <button
            onClick={() => onStartNewScan()}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold cursor-pointer"
          >
            + New Audit
          </button>
        </div>

        {summary?.recentScans && summary.recentScans.length > 0 ? (
          <div className="space-y-2.5">
            {summary.recentScans.map((scan) => {
              const score = scan.securityScore || 6.5;
              return (
                <div
                  key={scan.id}
                  onClick={() => onViewScan(scan.id)}
                  className="p-4 rounded-xl bg-slate-950/50 hover:bg-slate-950 border border-slate-800/60 hover:border-slate-700 transition flex items-center justify-between gap-4 cursor-pointer group"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-sm text-white group-hover:text-cyan-400 transition truncate">
                        {scan.targetUrl}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-slate-400">
                      <span>Audited on {new Date(scan.createdAt).toLocaleDateString()}</span>
                      <span>•</span>
                      <span>{scan.metrics.totalFindings} security checks</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 shrink-0">
                    {/* Score Out of 10 Badge */}
                    <div className="text-right">
                      <div className="text-base font-black font-mono text-cyan-400">
                        {score.toFixed(1)} <span className="text-xs text-slate-500 font-normal">/ 10</span>
                      </div>
                      <div className="text-[10px] text-slate-500">Security Score</div>
                    </div>

                    <div className="p-2 rounded-lg bg-slate-800 group-hover:bg-cyan-600 group-hover:text-white text-slate-400 transition">
                      <ArrowRight size={14} />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-8 text-xs text-slate-500">
            No audits recorded yet. Type a website address above to check its security score.
          </div>
        )}
      </div>
    </div>
  );
};
