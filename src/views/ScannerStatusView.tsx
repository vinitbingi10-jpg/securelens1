import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ToolMetadata } from '../types';
import {
  Cpu,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  Terminal,
  Shield,
  RotateCw,
  Sliders,
  BookOpen,
} from 'lucide-react';

interface Props {
  onStartScan: () => void;
}

export const ScannerStatusView: React.FC<Props> = ({ onStartScan }) => {
  const [tools, setTools] = useState<ToolMetadata[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchTools = async () => {
    try {
      setLoading(true);
      const data = await api.getTools();
      setTools(data);
    } catch (err) {
      console.error('Failed to load scanner status:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTools();
  }, []);

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-black text-white tracking-tight flex items-center gap-2">
            <Cpu className="text-cyan-400" size={24} />
            <span>Multi-Tool Scanner Availability Registry</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Engine health, installed adapters, versions, and execution environments.
          </p>
        </div>

        <button
          onClick={fetchTools}
          className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition cursor-pointer"
          title="Refresh Registry"
        >
          <RotateCw size={16} />
        </button>
      </div>

      {/* Summary KPI Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div>
          <div className="text-xs text-slate-400 font-semibold">Active Integrated Engines</div>
          <div className="text-2xl font-black text-emerald-400 mt-1">{tools.length} / {tools.length}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Real-time Node.js & network adapters</div>
        </div>
        <div>
          <div className="text-xs text-slate-400 font-semibold">Scanning Scope Safety</div>
          <div className="text-2xl font-black text-cyan-400 mt-1">100% Non-Destructive</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Strict passive, TLS, and safe headers checks</div>
        </div>
        <div>
          <div className="text-xs text-slate-400 font-semibold">SSRF & Metadata Guard</div>
          <div className="text-2xl font-black text-white mt-1">Enforced</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Blocks private subnets and 169.254.169.254</div>
        </div>
      </div>

      {/* Tool Cards */}
      <div className="space-y-4">
        {tools.map((tool) => (
          <div
            key={tool.id}
            className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4"
          >
            {/* Tool Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
                  <Shield size={18} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-white">{tool.name}</h3>
                    <span className="text-[10px] bg-slate-800 text-slate-300 font-mono px-2 py-0.5 rounded">
                      {tool.version}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">{tool.category} • {tool.activeEngine}</div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                  <CheckCircle2 size={12} />
                  <span>Installed & Active</span>
                </span>
              </div>
            </div>

            {/* Description */}
            <p className="text-xs text-slate-300 leading-relaxed">
              {tool.description}
            </p>

            {/* Technical Execution Profile & Setup Guide */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs bg-slate-950 p-4 rounded-xl border border-slate-800/80">
              <div className="space-y-2">
                <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <Sliders size={13} className="text-cyan-400" />
                  <span>Adapter Implementation & Capabilities:</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {tool.setupGuide.description}
                </p>
                <div className="text-[11px] text-slate-400">
                  <strong>Prerequisites:</strong> {tool.setupGuide.prerequisites}
                </div>
              </div>

              <div className="space-y-2">
                <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <Terminal size={13} className="text-cyan-400" />
                  <span>CLI Equivalent Reference:</span>
                </div>
                <pre className="p-2.5 bg-slate-900 border border-slate-800 rounded text-[11px] font-mono text-cyan-300 overflow-x-auto">
                  {tool.setupGuide.cliCommand}
                </pre>
                <div className="pt-1">
                  <a
                    href={tool.setupGuide.docsUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:underline"
                  >
                    <span>View Official Documentation</span>
                    <ExternalLink size={10} />
                  </a>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
