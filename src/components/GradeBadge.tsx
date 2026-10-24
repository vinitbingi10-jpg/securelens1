import React from 'react';

interface Props {
  grade?: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

export const GradeBadge: React.FC<Props> = ({ grade = 'A', size = 'md' }) => {
  let colorClass = '';

  switch (grade) {
    case 'A+':
    case 'A':
      colorClass = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30 shadow-emerald-950/20';
      break;
    case 'B':
      colorClass = 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30 shadow-cyan-950/20';
      break;
    case 'C':
      colorClass = 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30 shadow-yellow-950/20';
      break;
    case 'D':
      colorClass = 'text-amber-400 bg-amber-500/10 border-amber-500/30 shadow-amber-950/20';
      break;
    case 'F':
    default:
      colorClass = 'text-rose-400 bg-rose-500/10 border-rose-500/30 shadow-rose-950/20';
      break;
  }

  const sizeClasses = {
    sm: 'w-7 h-7 text-xs font-bold border rounded',
    md: 'w-10 h-10 text-base font-extrabold border rounded-lg',
    lg: 'w-14 h-14 text-2xl font-black border-2 rounded-xl shadow-lg',
    xl: 'w-20 h-20 text-4xl font-black border-2 rounded-2xl shadow-xl',
  }[size];

  return (
    <div className={`inline-flex items-center justify-center font-mono ${colorClass} ${sizeClasses}`}>
      {grade}
    </div>
  );
};
