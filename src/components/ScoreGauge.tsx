import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Shield } from 'lucide-react';

interface Props {
  score?: number;
  totalFindings?: number;
  size?: 'sm' | 'md' | 'lg';
}

export const ScoreGauge: React.FC<Props> = ({ score = 7.5, totalFindings = 0, size = 'md' }) => {
  const rounded = Math.round(score * 10) / 10;

  let colorClass = 'text-emerald-400';
  let barColorClass = 'bg-emerald-500';
  let bgClass = 'bg-emerald-500/10 border-emerald-500/30';
  let label = 'Strong Security';
  let Icon = ShieldCheck;

  if (rounded >= 8.5) {
    colorClass = 'text-emerald-400';
    barColorClass = 'bg-emerald-500';
    bgClass = 'bg-emerald-500/10 border-emerald-500/30';
    label = 'Strong Security';
    Icon = ShieldCheck;
  } else if (rounded >= 7.0) {
    colorClass = 'text-cyan-400';
    barColorClass = 'bg-cyan-500';
    bgClass = 'bg-cyan-500/10 border-cyan-500/30';
    label = 'Good Protection';
    Icon = Shield;
  } else if (rounded >= 5.0) {
    colorClass = 'text-amber-400';
    barColorClass = 'bg-amber-500';
    bgClass = 'bg-amber-500/10 border-amber-500/30';
    label = 'Moderate Risk';
    Icon = AlertTriangle;
  } else {
    colorClass = 'text-rose-400';
    barColorClass = 'bg-rose-500';
    bgClass = 'bg-rose-500/10 border-rose-500/30';
    label = 'High Risk - Needs Fixes';
    Icon = ShieldAlert;
  }

  const percent = Math.min(100, Math.max(10, rounded * 10));

  if (size === 'sm') {
    return (
      <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border font-mono font-bold text-xs ${bgClass} ${colorClass}`}>
        <Icon size={13} className="shrink-0" />
        <span>{rounded.toFixed(1)} / 10</span>
      </div>
    );
  }

  return (
    <div className={`rounded-xl border p-5 ${bgClass} flex flex-col justify-between space-y-3`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold tracking-wider uppercase text-slate-300 flex items-center gap-1.5">
          <Icon size={16} className={colorClass} />
          <span>Security Score</span>
        </span>
        <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full bg-slate-950/70 border border-slate-700/50 ${colorClass}`}>
          {label}
        </span>
      </div>

      <div className="flex items-baseline gap-2">
        <span className={`text-4xl sm:text-5xl font-black tracking-tight font-mono ${colorClass}`}>
          {rounded.toFixed(1)}
        </span>
        <span className="text-xl sm:text-2xl font-bold text-slate-400 font-mono">/ 10</span>
      </div>

      {/* Progress Bar out of 10 */}
      <div className="space-y-1.5">
        <div className="w-full bg-slate-950/60 rounded-full h-2.5 overflow-hidden border border-slate-800">
          <div
            className={`h-full rounded-full transition-all duration-500 ${barColorClass}`}
            style={{ width: `${percent}%` }}
          />
        </div>
        <div className="flex justify-between text-[11px] text-slate-400">
          <span>0 (Vulnerable)</span>
          <span>10 (Secure)</span>
        </div>
      </div>
    </div>
  );
};
