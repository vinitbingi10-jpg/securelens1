import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { User, AiStatus, AuditLog } from '../types';
import {
  Sliders,
  Sparkles,
  RotateCw,
  CheckCircle2,
  XCircle,
  Shield,
  FileText,
  User as UserIcon,
  Clock,
  Terminal,
  Lock,
} from 'lucide-react';

interface Props {
  currentUser: User | null;
  aiStatus: AiStatus | null;
  onRefreshAiStatus: () => void;
}

export const SettingsView: React.FC<Props> = ({ currentUser, aiStatus, onRefreshAiStatus }) => {
  const [testingAi, setTestingAi] = useState(false);
  const [testResult, setTestResult] = useState<{
    success?: boolean;
    latencyMs?: number;
    message?: string;
  } | null>(null);

  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(true);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        setLoadingLogs(true);
        const data = await api.getAuditLogs();
        setAuditLogs(data);
      } catch (err) {
        console.error('Failed to load audit logs:', err);
      } finally {
        setLoadingLogs(false);
      }
    };

    fetchLogs();
  }, []);

  const handleTestAi = async () => {
    setTestingAi(true);
    setTestResult(null);
    try {
      const res = await api.testAiConnection();
      setTestResult(res);
      onRefreshAiStatus();
    } catch (err: any) {
      setTestResult({
        success: false,
        latencyMs: 0,
        message: err.message || 'AI Connection Test failed',
      });
    } finally {
      setTestingAi(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800 pb-5">
        <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight flex items-center gap-2">
          <Sliders className="text-cyan-400" size={24} />
          <span>Platform Settings & AI Configuration</span>
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          Verify AI runtime health, inspect security audit logs, and review platform permissions.
        </p>
      </div>

      {/* Section 1: AI Provider & Live Connection */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
              <Sparkles size={18} />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">AI Security Engine Status</h2>
              <div className="text-[11px] text-slate-400">
                Server-side @google/genai orchestration adapter
              </div>
            </div>
          </div>

          <button
            onClick={handleTestAi}
            disabled={testingAi}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
          >
            <RotateCw size={14} className={testingAi ? 'animate-spin' : ''} />
            <span>{testingAi ? 'Pinging Model...' : 'Test AI Connection'}</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs bg-slate-950 p-4 rounded-xl border border-slate-800">
          <div>
            <span className="text-slate-400 font-medium block">Configured Provider</span>
            <span className="font-bold text-white text-sm mt-0.5 block">{aiStatus?.provider || 'Google AI'}</span>
          </div>
          <div>
            <span className="text-slate-400 font-medium block">Active Analysis Model</span>
            <span className="font-bold text-cyan-400 text-sm mt-0.5 font-mono block">
              {aiStatus?.model || 'gemini-3.8-flash'}
            </span>
          </div>
          <div>
            <span className="text-slate-400 font-medium block">API Secret State</span>
            <span className="inline-flex items-center gap-1.5 font-bold text-emerald-400 text-sm mt-0.5">
              <CheckCircle2 size={14} />
              <span>Injected via Server Environment</span>
            </span>
          </div>
        </div>

        {/* Test Result Message */}
        {testResult && (
          <div
            className={`p-3.5 rounded-lg border text-xs flex items-center gap-2.5 ${
              testResult.success
                ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60'
                : 'bg-rose-950/40 text-rose-300 border-rose-800/60'
            }`}
          >
            {testResult.success ? (
              <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
            ) : (
              <XCircle size={16} className="text-rose-400 shrink-0" />
            )}
            <div className="flex-1">
              <span className="font-semibold">{testResult.message}</span>
              {testResult.latencyMs ? (
                <span className="ml-2 font-mono text-[11px] opacity-80">
                  (Roundtrip latency: {testResult.latencyMs}ms)
                </span>
              ) : null}
            </div>
          </div>
        )}

        <div className="text-[11px] text-slate-400 leading-relaxed bg-slate-950/40 p-3 rounded-lg border border-slate-800/60 flex items-start gap-2">
          <Lock size={14} className="text-cyan-400 shrink-0 mt-0.5" />
          <span>
            API keys are handled strictly within server environment variables (<code className="text-cyan-300">GEMINI_API_KEY</code>). Client browsers never receive, store, or transmit the secret key.
          </span>
        </div>
      </div>

      {/* Section 2: Account & Role Profile */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center gap-2.5 border-b border-slate-800/80 pb-3">
          <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
            <UserIcon size={18} />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white">Security Analyst Profile</h2>
            <div className="text-[11px] text-slate-400">Current authenticated session credentials</div>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs bg-slate-950 p-4 rounded-xl border border-slate-800">
          <div>
            <span className="text-slate-400 font-medium block">Display Name</span>
            <span className="font-bold text-white mt-0.5 block">{currentUser?.displayName || 'Anonymous User'}</span>
          </div>
          <div>
            <span className="text-slate-400 font-medium block">Email Identifier</span>
            <span className="font-bold text-slate-200 mt-0.5 block">{currentUser?.email || 'Not Signed In'}</span>
          </div>
          <div>
            <span className="text-slate-400 font-medium block">Access Control Role</span>
            <span className="font-bold text-cyan-400 capitalize mt-0.5 block">{currentUser?.role || 'Viewer'}</span>
          </div>
        </div>
      </div>

      {/* Section 3: Audit Logs */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
              <FileText size={18} />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">System Security Audit Log</h2>
              <div className="text-[11px] text-slate-400">Immutable ledger of scans, auth events, and AI analysis requests</div>
            </div>
          </div>
        </div>

        {loadingLogs ? (
          <div className="py-8 text-center text-xs text-slate-500">Loading audit records...</div>
        ) : auditLogs.length > 0 ? (
          <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
            {auditLogs.map((log) => (
              <div
                key={log.id}
                className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs flex items-center justify-between gap-3"
              >
                <div className="space-y-0.5 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] bg-slate-800 text-cyan-400 px-1.5 py-0.5 rounded">
                      {log.action}
                    </span>
                    <span className="font-semibold text-slate-300 truncate">
                      {log.resourceType}: {log.resourceId || 'N/A'}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono truncate">
                    {JSON.stringify(log.safeMetadata)}
                  </div>
                </div>

                <span className="text-[10px] text-slate-500 font-mono shrink-0">
                  {new Date(log.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-6 text-center text-xs text-slate-500">No audit events logged yet.</div>
        )}
      </div>
    </div>
  );
};
