import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ScanJob, ScannerRun, ScannerFinding } from '../types';
import {
  RotateCw,
  CheckCircle2,
  AlertCircle,
  XCircle,
  Shield,
  Clock,
  Ban,
  Activity,
  ArrowRight,
  Terminal,
} from 'lucide-react';

interface Props {
  scanId: string;
  onScanFinished: (scanId: string) => void;
  onBackToDashboard: () => void;
}

export const LiveScanView: React.FC<Props> = ({ scanId, onScanFinished, onBackToDashboard }) => {
  const [scan, setScan] = useState<ScanJob | null>(null);
  const [runs, setRuns] = useState<ScannerRun[]>([]);
  const [findings, setFindings] = useState<ScannerFinding[]>([]);
  const [elapsed, setElapsed] = useState(0);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let interval: any;
    let timerInterval: any;

    const fetchStatus = async () => {
      try {
        const data = await api.getScanById(scanId);
        setScan(data.scan);
        setRuns(data.runs);
        setFindings(data.findings);

        if (
          data.scan.status === 'completed' ||
          data.scan.status === 'partial' ||
          data.scan.status === 'failed' ||
          data.scan.status === 'cancelled'
        ) {
          clearInterval(interval);
          clearInterval(timerInterval);
        }
      } catch (err: any) {
        setError(err.message || 'Failed to poll scan status');
      }
    };

    fetchStatus();
    interval = setInterval(fetchStatus, 2000);
    timerInterval = setInterval(() => {
      setElapsed((prev) => prev + 1);
    }, 1000);

    return () => {
      clearInterval(interval);
      clearInterval(timerInterval);
    };
  }, [scanId]);

  const handleCancel = async () => {
    setCancelling(true);
    try {
      await api.cancelScan(scanId);
      const data = await api.getScanById(scanId);
      setScan(data.scan);
    } catch (err: any) {
      setError(err.message || 'Failed to cancel scan');
    } finally {
      setCancelling(false);
    }
  };

  const isTerminal = scan && ['completed', 'partial', 'failed', 'cancelled'].includes(scan.status);

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Top Status Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/60">
              {scanId}
            </span>
            <span
              className={`text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${
                scan?.status === 'running'
                  ? 'bg-cyan-950 text-cyan-400 border-cyan-800 animate-pulse'
                  : scan?.status === 'completed'
                  ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                  : scan?.status === 'cancelled'
                  ? 'bg-slate-800 text-slate-400 border-slate-700'
                  : 'bg-amber-950 text-amber-400 border-amber-800'
              }`}
            >
              {scan?.status || 'QUEUED'}
            </span>
          </div>

          <h1 className="text-xl font-black text-white truncate max-w-lg mt-1">
            {scan?.targetUrl || 'Initializing target audit...'}
          </h1>

          <div className="flex items-center gap-4 text-xs text-slate-400 pt-1">
            <span className="flex items-center gap-1">
              <Clock size={13} />
              <span>Elapsed: {elapsed}s</span>
            </span>
            <span>Profile: {scan?.scanProfile || 'owasp_standard'}</span>
            <span>Discovered Findings: <strong className="text-cyan-400">{findings.length}</strong></span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-3">
          {!isTerminal && (
            <button
              onClick={handleCancel}
              disabled={cancelling}
              className="px-4 py-2 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800 text-rose-300 text-xs font-bold transition cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
            >
              <Ban size={14} />
              <span>{cancelling ? 'Cancelling...' : 'Abort Scan'}</span>
            </button>
          )}

          {isTerminal && (
            <button
              onClick={() => onScanFinished(scanId)}
              className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white text-xs font-bold uppercase tracking-wider shadow-lg shadow-cyan-500/20 transition cursor-pointer flex items-center gap-2"
            >
              <span>View Audit Results</span>
              <ArrowRight size={15} />
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Progress & Live Tool Status Grid */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Activity size={16} className="text-cyan-400" />
            <span>Scanner Engine Execution Pipeline</span>
          </h2>
          <span className="text-xs text-slate-400">
            {runs.filter((r) => r.status === 'completed').length} of {runs.length || 5} Tools Finished
          </span>
        </div>

        <div className="space-y-3">
          {runs.map((run) => (
            <div
              key={run.id}
              className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-slate-200">{run.scannerName}</span>
                  <span className="text-[10px] text-slate-500 font-mono">({run.scannerVersion})</span>
                </div>
                <div className="text-[11px] text-slate-400">
                  {run.resultSummary || (run.status === 'running' ? 'Scanning target endpoints & headers...' : 'Awaiting worker execution')}
                </div>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                {run.status === 'running' && (
                  <span className="flex items-center gap-1.5 text-xs text-cyan-400 font-semibold">
                    <RotateCw size={13} className="animate-spin" />
                    <span>Running</span>
                  </span>
                )}
                {run.status === 'completed' && (
                  <span className="flex items-center gap-1.5 text-xs text-emerald-400 font-semibold">
                    <CheckCircle2 size={15} />
                    <span>Finished ({run.findingsCount} findings)</span>
                  </span>
                )}
                {run.status === 'failed' && (
                  <span className="flex items-center gap-1.5 text-xs text-rose-400 font-semibold">
                    <XCircle size={15} />
                    <span>Failed</span>
                  </span>
                )}
                {run.status === 'pending' && (
                  <span className="text-xs text-slate-500 font-medium">Pending</span>
                )}
              </div>
            </div>
          ))}

          {runs.length === 0 && (
            <div className="text-center py-8 text-xs text-slate-500 flex flex-col items-center gap-2">
              <RotateCw className="w-5 h-5 animate-spin text-cyan-400" />
              <span>Orchestrating scanner containers and resolving target...</span>
            </div>
          )}
        </div>
      </div>

      {/* Discovered Findings Live Ticker */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3">
        <h2 className="text-sm font-bold text-white flex items-center gap-2">
          <Terminal size={15} className="text-cyan-400" />
          <span>Real-Time Discovered Findings Feed</span>
        </h2>

        {findings.length > 0 ? (
          <div className="space-y-2">
            {findings.map((f) => (
              <div
                key={f.id}
                className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 flex items-center justify-between text-xs"
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      f.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : f.severity === 'HIGH'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : f.severity === 'MEDIUM'
                        ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                        : 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                    }`}
                  >
                    {f.severity}
                  </span>
                  <span className="font-semibold text-slate-200">{f.title}</span>
                </div>
                <span className="text-[11px] text-slate-500 font-mono">{f.scannerName.split(' ')[0]}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-6 text-xs text-slate-500">
            No findings flagged yet. Telemetry will stream here as scanners complete.
          </div>
        )}
      </div>
    </div>
  );
};
