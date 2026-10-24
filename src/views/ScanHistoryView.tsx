import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ScanJob } from '../types';
import { GradeBadge } from '../components/GradeBadge';
import {
  History,
  Search,
  Download,
  Trash2,
  ExternalLink,
  Play,
  RotateCw,
  Clock,
  Printer,
  ShieldCheck,
} from 'lucide-react';

interface Props {
  onViewScan: (scanId: string) => void;
  onRerunScan: (targetUrl: string, profile: string) => void;
}

export const ScanHistoryView: React.FC<Props> = ({ onViewScan, onRerunScan }) => {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const fetchScans = async () => {
    try {
      setLoading(true);
      const data = await api.getScans();
      setScans(data);
    } catch (err) {
      console.error('Failed to load scan history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleDelete = async (scanId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to permanently delete this audit record?')) return;
    try {
      await api.deleteScan(scanId);
      setScans(scans.filter((s) => s.id !== scanId));
    } catch (err) {
      console.error('Failed to delete scan:', err);
    }
  };

  const filteredScans = scans.filter((s) => {
    if (statusFilter !== 'ALL' && s.status !== statusFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return s.targetUrl.toLowerCase().includes(q) || s.targetHost.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight flex items-center gap-2">
            <History className="text-cyan-400" size={24} />
            <span>Audit History & Historical Archive</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Access previous assessments, export compliance reports, and trace vulnerability trends over time.
          </p>
        </div>

        <button
          onClick={fetchScans}
          className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition cursor-pointer"
          title="Refresh Archive"
        >
          <RotateCw size={16} />
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1">
          <Search size={15} className="absolute left-3 top-3 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search scans by URL or domain..."
            className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 transition"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 transition cursor-pointer"
          >
            <option value="ALL">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>
      </div>

      {/* Scans Table / Cards */}
      {loading ? (
        <div className="py-16 text-center text-xs text-slate-500">Loading audit history...</div>
      ) : filteredScans.length > 0 ? (
        <div className="space-y-3">
          {filteredScans.map((scan) => (
            <div
              key={scan.id}
              onClick={() => onViewScan(scan.id)}
              className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-4 sm:p-5 shadow-sm transition flex flex-col sm:flex-row sm:items-center justify-between gap-4 cursor-pointer group"
            >
              <div className="flex items-start sm:items-center gap-4 min-w-0">
                <div className="text-center px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 font-mono">
                  <div className="text-sm font-black text-cyan-400">
                    {(scan.securityScore || 6.5).toFixed(1)}
                  </div>
                  <div className="text-[9px] text-slate-500 uppercase">/ 10</div>
                </div>
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-sm text-white group-hover:text-cyan-400 transition truncate">
                      {scan.targetUrl}
                    </span>
                    <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono">
                      {scan.scanProfile}
                    </span>
                    <span
                      className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                        scan.status === 'completed'
                          ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40'
                          : scan.status === 'running'
                          ? 'bg-cyan-950/40 text-cyan-400 border-cyan-800/40 animate-pulse'
                          : 'bg-rose-950/40 text-rose-400 border-rose-800/40'
                      }`}
                    >
                      {scan.status}
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-xs text-slate-400">
                    <span className="flex items-center gap-1">
                      <Clock size={12} />
                      {new Date(scan.createdAt).toLocaleDateString([], {
                        month: 'short',
                        day: 'numeric',
                        year: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                    <span>Duration: {scan.durationSeconds || 0}s</span>
                    <span className="font-semibold text-slate-300">
                      {scan.metrics.totalFindings} findings ({scan.metrics.criticalCount} Critical,{' '}
                      {scan.metrics.highCount} High)
                    </span>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 self-end sm:self-auto shrink-0" onClick={(e) => e.stopPropagation()}>
                <a
                  href={`/api/scans/${scan.id}/report?token=${api.getToken() || ''}`}
                  target="_blank"
                  rel="noreferrer"
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition cursor-pointer"
                  title="Print / View Executive HTML Report"
                >
                  <Printer size={15} />
                </a>

                <a
                  href={`/api/scans/${scan.id}/report?format=json&token=${api.getToken() || ''}`}
                  target="_blank"
                  rel="noreferrer"
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition cursor-pointer"
                  title="Download JSON Report"
                >
                  <Download size={15} />
                </a>

                <button
                  onClick={() => onRerunScan(scan.targetUrl, scan.scanProfile)}
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 transition cursor-pointer"
                  title="Re-run assessment against target"
                >
                  <Play size={15} />
                </button>

                <button
                  onClick={(e) => handleDelete(scan.id, e)}
                  className="p-2 rounded-lg bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400 transition cursor-pointer"
                  title="Delete Audit"
                >
                  <Trash2 size={15} />
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="p-16 text-center rounded-2xl bg-slate-900 border border-slate-800 text-slate-400 text-xs">
          No audits found matching your criteria.
        </div>
      )}
    </div>
  );
};
