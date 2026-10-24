import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ScanJob, ToolMetadata } from '../types';
import {
  Globe,
  Play,
  RotateCw,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ArrowLeft,
  Lock,
} from 'lucide-react';

interface Props {
  tools: ToolMetadata[];
  initialUrl?: string;
  onScanStarted: (scan: ScanJob) => void;
  onCancel: () => void;
}

export const NewScanView: React.FC<Props> = ({
  tools,
  initialUrl = '',
  onScanStarted,
  onCancel,
}) => {
  const [targetUrl, setTargetUrl] = useState(initialUrl);
  const [authorizedConsent, setAuthorizedConsent] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    if (initialUrl) {
      setTargetUrl(initialUrl);
    }
  }, [initialUrl]);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError(null);

    if (!targetUrl.trim()) {
      setSubmitError('Please enter a website URL.');
      return;
    }

    if (!authorizedConsent) {
      setSubmitError('Please confirm you have authorization to test this website.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await api.createScan({
        targetUrl: targetUrl.trim(),
        scanProfile: 'owasp_standard',
        selectedTools: ['http_headers', 'tls_ssl', 'whatweb', 'owasp_zap', 'nuclei'],
        enableNetworkChecks: false,
        authorizationConfirmed: authorizedConsent,
      });

      onScanStarted(res.scan);
    } catch (err: any) {
      setSubmitError(err.message || 'Failed to initialize scan');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="max-w-xl mx-auto space-y-6">
      <div className="flex items-center gap-2">
        <button
          onClick={onCancel}
          className="text-xs text-slate-400 hover:text-white flex items-center gap-1 font-semibold cursor-pointer"
        >
          <ArrowLeft size={14} />
          <span>Back</span>
        </button>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-7 shadow-sm space-y-5">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Test Website Security</h1>
          <p className="text-xs text-slate-400 mt-1">
            We will run a safe, non-destructive audit and provide a clear score out of 10 and a fix checklist.
          </p>
        </div>

        {submitError && (
          <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle size={15} className="shrink-0" />
            <span>{submitError}</span>
          </div>
        )}

        <form onSubmit={handleStartScan} className="space-y-5">
          {/* URL Input */}
          <div className="space-y-1.5">
            <label className="block text-xs font-semibold text-slate-300">Website Address</label>
            <div className="relative">
              <Globe size={16} className="absolute left-3.5 top-3.5 text-slate-500" />
              <input
                type="text"
                required
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full pl-10 pr-3 py-2.5 bg-slate-950 border border-slate-800 focus:border-cyan-500 rounded-xl text-sm text-white focus:outline-none transition font-mono"
              />
            </div>
          </div>

          {/* Simple Explanation of What Is Checked */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2.5 text-xs text-slate-300">
            <div className="font-semibold text-white">What we inspect:</div>
            <div className="space-y-1.5 text-slate-400">
              <div className="flex items-center gap-2">
                <CheckCircle2 size={13} className="text-cyan-400 shrink-0" />
                <span>Security Headers (HSTS, Content Security Policy, Clickjacking protection)</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 size={13} className="text-cyan-400 shrink-0" />
                <span>SSL / TLS Certificate validity, expiration date, and cipher security</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 size={13} className="text-cyan-400 shrink-0" />
                <span>Passive check for accidentally exposed files (e.g. .git or .env)</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 size={13} className="text-cyan-400 shrink-0" />
                <span>Cookies security flags (Secure, HttpOnly, SameSite)</span>
              </div>
            </div>
          </div>

          {/* Authorization Checkbox */}
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                required
                checked={authorizedConsent}
                onChange={(e) => setAuthorizedConsent(e.target.checked)}
                className="mt-0.5 accent-cyan-500 w-4 h-4 rounded cursor-pointer"
              />
              <span className="text-xs text-slate-300 font-medium leading-relaxed">
                I verify that I own or am authorized to test this website.
              </span>
            </label>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={submitting || !authorizedConsent || !targetUrl.trim()}
            className="w-full py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs uppercase tracking-wider transition cursor-pointer disabled:opacity-50 flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/20"
          >
            {submitting ? (
              <>
                <RotateCw size={14} className="animate-spin" />
                <span>Starting Scan...</span>
              </>
            ) : (
              <>
                <Play size={14} />
                <span>Run Security Audit</span>
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
};
