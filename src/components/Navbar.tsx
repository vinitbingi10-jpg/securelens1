import React from 'react';
import { User, AiStatus } from '../types';
import {
  Shield,
  Activity,
  PlusCircle,
  History,
  Sliders,
  Cpu,
  Sparkles,
  User as UserIcon,
  LogOut,
  LogIn,
} from 'lucide-react';

export type NavTab = 'dashboard' | 'new-scan' | 'scans' | 'tools' | 'settings';

interface Props {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  currentUser: User | null;
  aiStatus: AiStatus | null;
  onOpenAuth: () => void;
  onLogout: () => void;
  onOpenCopilot: () => void;
}

export const Navbar: React.FC<Props> = ({
  currentTab,
  onSelectTab,
  currentUser,
  aiStatus,
  onOpenAuth,
  onLogout,
  onOpenCopilot,
}) => {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Brand / Logo */}
        <div className="flex items-center gap-6">
          <button
            onClick={() => onSelectTab('dashboard')}
            className="flex items-center gap-3 group text-left cursor-pointer transition"
          >
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 group-hover:scale-105 transition-transform">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-lg tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                  SECURE LENS
                </span>
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800/60 text-cyan-400 uppercase tracking-wider">
                  v1.0
                </span>
              </div>
              <p className="text-[10px] text-slate-400 hidden sm:block">AI-Powered Web Vulnerability Platform</p>
            </div>
          </button>

          {/* Nav Tabs */}
          <nav className="hidden md:flex items-center gap-1 ml-4">
            <button
              onClick={() => onSelectTab('dashboard')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition cursor-pointer ${
                currentTab === 'dashboard'
                  ? 'bg-slate-800 text-cyan-400 border border-slate-700/80'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Activity size={14} />
              Dashboard
            </button>

            <button
              onClick={() => onSelectTab('new-scan')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition cursor-pointer ${
                currentTab === 'new-scan'
                  ? 'bg-slate-800 text-cyan-400 border border-slate-700/80'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <PlusCircle size={14} />
              New Scan
            </button>

            <button
              onClick={() => onSelectTab('scans')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition cursor-pointer ${
                currentTab === 'scans'
                  ? 'bg-slate-800 text-cyan-400 border border-slate-700/80'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <History size={14} />
              Scan History
            </button>

            <button
              onClick={() => onSelectTab('tools')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition cursor-pointer ${
                currentTab === 'tools'
                  ? 'bg-slate-800 text-cyan-400 border border-slate-700/80'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Cpu size={14} />
              Scanners
            </button>

            <button
              onClick={() => onSelectTab('settings')}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition cursor-pointer ${
                currentTab === 'settings'
                  ? 'bg-slate-800 text-cyan-400 border border-slate-700/80'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Sliders size={14} />
              Settings
            </button>
          </nav>
        </div>

        {/* Right Side: AI Status + Copilot + User */}
        <div className="flex items-center gap-3">
          {/* AI Status Badge */}
          <div
            className={`hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full text-[11px] border ${
              aiStatus?.configured
                ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/50'
                : 'bg-amber-950/30 text-amber-400 border-amber-800/40'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                aiStatus?.configured ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
              }`}
            />
            <span className="font-semibold">
              {aiStatus?.configured ? `${aiStatus.model}` : 'AI Inactive'}
            </span>
          </div>

          {/* Security Copilot Quick Trigger */}
          <button
            onClick={onOpenCopilot}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600/20 to-blue-600/20 hover:from-cyan-600/30 hover:to-blue-600/30 border border-cyan-500/30 text-cyan-300 text-xs font-semibold shadow-sm transition cursor-pointer"
            title="Ask AI Security Copilot"
          >
            <Sparkles size={13} className="text-cyan-400 animate-spin-slow" />
            <span className="hidden sm:inline">Ask Copilot</span>
          </button>

          {/* Auth Button */}
          {currentUser ? (
            <div className="flex items-center gap-2">
              <div className="hidden sm:flex flex-col text-right">
                <span className="text-xs font-semibold text-slate-200">{currentUser.displayName}</span>
                <span className="text-[10px] text-slate-400 capitalize">{currentUser.role}</span>
              </div>
              <button
                onClick={onLogout}
                className="p-1.5 rounded-lg border border-slate-800 text-slate-400 hover:text-rose-400 hover:border-rose-900/40 hover:bg-rose-950/20 transition cursor-pointer"
                title="Log out"
              >
                <LogOut size={16} />
              </button>
            </div>
          ) : (
            <button
              onClick={onOpenAuth}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition cursor-pointer"
            >
              <LogIn size={14} />
              <span>Sign In</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
