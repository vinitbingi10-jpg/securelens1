import React from 'react';
import { SeverityLevel } from '../types';
import { ShieldAlert, AlertTriangle, AlertCircle, Info } from 'lucide-react';

interface Props {
  severity: SeverityLevel;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const SeverityBadge: React.FC<Props> = ({ severity, size = 'md', showIcon = true }) => {
  let colorStyles = '';
  let IconComponent = Info;

  switch (severity) {
    case 'CRITICAL':
      colorStyles = 'bg-rose-500/15 text-rose-400 border-rose-500/30';
      IconComponent = ShieldAlert;
      break;
    case 'HIGH':
      colorStyles = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      IconComponent = AlertTriangle;
      break;
    case 'MEDIUM':
      colorStyles = 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30';
      IconComponent = AlertCircle;
      break;
    case 'LOW':
      colorStyles = 'bg-sky-500/15 text-sky-400 border-sky-500/30';
      IconComponent = Info;
      break;
    case 'INFO':
    default:
      colorStyles = 'bg-slate-500/15 text-slate-300 border-slate-500/30';
      IconComponent = Info;
      break;
  }

  const sizeStyles = {
    sm: 'text-[10px] px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-sm px-3.5 py-1.5 gap-2 font-bold',
  }[size];

  const iconSizes = {
    sm: 11,
    md: 13,
    lg: 16,
  }[size];

  return (
    <span
      className={`inline-flex items-center font-semibold rounded-md border tracking-wide uppercase ${colorStyles} ${sizeStyles}`}
    >
      {showIcon && <IconComponent size={iconSizes} className="shrink-0" />}
      <span>{severity}</span>
    </span>
  );
};
