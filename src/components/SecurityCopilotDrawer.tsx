import React, { useState } from 'react';
import { api } from '../services/api';
import { X, Sparkles, Send, Bot, User, Code, CheckCircle, Shield } from 'lucide-react';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  contextTarget?: string;
  contextFinding?: string;
}

interface Message {
  role: 'user' | 'assistant';
  text: string;
  timestamp: string;
}

export const SecurityCopilotDrawer: React.FC<Props> = ({
  isOpen,
  onClose,
  contextTarget = 'General Target',
  contextFinding,
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      text: `Hello! I am your Secure Lens Security Copilot. I analyze discovered vulnerabilities and assist you with concrete Nginx/Apache/Express configurations, defensive policies, and curl verification steps. What can I help you resolve?`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSend = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!input.trim() || loading) return;

    const userText = input.trim();
    setInput('');

    const newMsg: Message = {
      role: 'user',
      text: userText,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, newMsg]);
    setLoading(true);

    try {
      const res = await api.askCopilot({
        question: userText,
        targetUrl: contextTarget,
        findingTitle: contextFinding,
      });

      const aiMsg: Message = {
        role: 'assistant',
        text: res.answer,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (err: any) {
      const errorMsg: Message = {
        role: 'assistant',
        text: `Error connecting to AI Security Copilot: ${err.message || 'API request failed'}. Please check your environment configuration.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const quickPrompts = [
    'How do I configure HSTS in Nginx?',
    'Provide a strict Content-Security-Policy for React',
    'How do I test my TLS certificate from CLI?',
  ];

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/60 backdrop-blur-xs flex justify-end">
      <div className="w-full max-w-lg bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Sparkles size={17} />
            </div>
            <div>
              <div className="text-sm font-bold text-white flex items-center gap-1.5">
                <span>Security Copilot</span>
                <span className="text-[10px] bg-cyan-950 border border-cyan-800 text-cyan-400 px-1.5 py-0.2 rounded font-mono">
                  Defensive AI
                </span>
              </div>
              <p className="text-[11px] text-slate-400 truncate max-w-[280px]">
                Target: {contextTarget} {contextFinding ? `• ${contextFinding}` : ''}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer"
          >
            <X size={18} />
          </button>
        </div>

        {/* Chat History */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((m, idx) => (
            <div
              key={idx}
              className={`flex gap-3 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {m.role === 'assistant' && (
                <div className="w-7 h-7 rounded-md bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400 shrink-0 mt-0.5">
                  <Bot size={15} />
                </div>
              )}
              <div
                className={`max-w-[85%] rounded-xl p-3 text-xs leading-relaxed ${
                  m.role === 'user'
                    ? 'bg-cyan-600 text-white shadow-md rounded-tr-none'
                    : 'bg-slate-950 border border-slate-800 text-slate-200 rounded-tl-none whitespace-pre-wrap'
                }`}
              >
                <div>{m.text}</div>
                <div
                  className={`mt-1.5 text-[9px] ${
                    m.role === 'user' ? 'text-cyan-200 text-right' : 'text-slate-500'
                  }`}
                >
                  {m.timestamp}
                </div>
              </div>
              {m.role === 'user' && (
                <div className="w-7 h-7 rounded-md bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 shrink-0 mt-0.5">
                  <User size={15} />
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div className="flex gap-3 justify-start items-center text-xs text-cyan-400">
              <div className="w-7 h-7 rounded-md bg-cyan-950 border border-cyan-800 flex items-center justify-center">
                <Sparkles size={14} className="animate-spin" />
              </div>
              <span className="animate-pulse">Security Copilot is analyzing defensive recommendations...</span>
            </div>
          )}
        </div>

        {/* Quick Prompts */}
        {messages.length <= 2 && (
          <div className="px-4 py-2 border-t border-slate-800/80 bg-slate-950/40">
            <div className="text-[11px] text-slate-400 mb-1.5 font-medium">Suggested queries:</div>
            <div className="flex flex-wrap gap-1.5">
              {quickPrompts.map((q, i) => (
                <button
                  key={i}
                  onClick={() => {
                    setInput(q);
                  }}
                  className="text-[11px] px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700/60 transition cursor-pointer text-left"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input */}
        <form onSubmit={handleSend} className="p-3 border-t border-slate-800 bg-slate-950">
          <div className="relative flex items-center">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask how to remediate, harden headers, or write test curls..."
              className="w-full pr-10 pl-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 transition"
            />
            <button
              type="submit"
              disabled={!input.trim() || loading}
              className="absolute right-1.5 p-1.5 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white transition disabled:opacity-40 cursor-pointer"
            >
              <Send size={14} />
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
