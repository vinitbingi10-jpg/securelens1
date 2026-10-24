import React, { useState, useEffect } from 'react';
import { api } from './services/api';
import { User, AiStatus, ToolMetadata, ScannerFinding, ScanJob } from './types';
import { Navbar, NavTab } from './components/Navbar';
import { AuthModal } from './components/AuthModal';
import { SecurityCopilotDrawer } from './components/SecurityCopilotDrawer';
import { DashboardView } from './views/DashboardView';
import { NewScanView } from './views/NewScanView';
import { LiveScanView } from './views/LiveScanView';
import { ScanResultsView } from './views/ScanResultsView';
import { FindingDetailModal } from './views/FindingDetailModal';
import { ScanHistoryView } from './views/ScanHistoryView';
import { ScannerStatusView } from './views/ScannerStatusView';
import { SettingsView } from './views/SettingsView';

export default function App() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [currentTab, setCurrentTab] = useState<NavTab | 'live-scan' | 'scan-results'>('dashboard');
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<ScannerFinding | null>(null);

  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null);
  const [tools, setTools] = useState<ToolMetadata[]>([]);

  // Modals / Drawers
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [copilotContext, setCopilotContext] = useState<{ targetUrl: string; findingTitle?: string }>({
    targetUrl: 'General Target',
  });

  const checkAuthAndInit = async () => {
    try {
      const meRes = await api.getMe();
      if (meRes.user) {
        setCurrentUser(meRes.user);
      } else {
        // Auto-authenticate with seeded demo analyst for immediate out-of-the-box readiness
        try {
          const loginRes = await api.login('analyst@securelens.local', 'SecurityLens2026!');
          setCurrentUser(loginRes.user);
        } catch {
          // Continue as guest
        }
      }

      // Fetch AI Status & Scanner Tools
      const [aiData, toolsData] = await Promise.all([api.getAiStatus(), api.getTools()]);
      setAiStatus(aiData);
      setTools(toolsData);
    } catch (err) {
      console.error('Initialization error:', err);
    }
  };

  useEffect(() => {
    checkAuthAndInit();
  }, []);

  const handleLogout = async () => {
    await api.logout();
    setCurrentUser(null);
  };

  const handleOpenCopilot = (targetUrl?: string, findingTitle?: string) => {
    setCopilotContext({
      targetUrl: targetUrl || 'General Target',
      findingTitle,
    });
    setIsCopilotOpen(true);
  };

  const [initialScanUrl, setInitialScanUrl] = useState('');

  const handleStartNewScan = (url?: string) => {
    if (url) {
      setInitialScanUrl(url);
    } else {
      setInitialScanUrl('');
    }
    setCurrentTab('new-scan');
  };

  const handleScanStarted = (scan: ScanJob) => {
    setActiveScanId(scan.id);
    setCurrentTab('live-scan');
  };

  const handleViewScan = (scanId: string) => {
    setActiveScanId(scanId);
    setCurrentTab('scan-results');
  };

  const handleRerunScan = (targetUrl: string) => {
    setInitialScanUrl(targetUrl);
    setCurrentTab('new-scan');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navigation */}
      <Navbar
        currentTab={currentTab as NavTab}
        onSelectTab={(tab) => {
          setCurrentTab(tab);
          setActiveScanId(null);
        }}
        currentUser={currentUser}
        aiStatus={aiStatus}
        onOpenAuth={() => setIsAuthOpen(true)}
        onLogout={handleLogout}
        onOpenCopilot={() => handleOpenCopilot()}
      />

      {/* Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {currentTab === 'dashboard' && (
          <DashboardView
            onStartNewScan={handleStartNewScan}
            onViewScan={handleViewScan}
            onSelectFinding={(f) => setSelectedFinding(f)}
            onViewTools={() => setCurrentTab('tools')}
          />
        )}

        {currentTab === 'new-scan' && (
          <NewScanView
            tools={tools}
            initialUrl={initialScanUrl}
            onScanStarted={handleScanStarted}
            onCancel={() => setCurrentTab('dashboard')}
          />
        )}

        {currentTab === 'live-scan' && activeScanId && (
          <LiveScanView
            scanId={activeScanId}
            onScanFinished={handleViewScan}
            onBackToDashboard={() => setCurrentTab('dashboard')}
          />
        )}

        {currentTab === 'scan-results' && activeScanId && (
          <ScanResultsView
            scanId={activeScanId}
            onBack={() => setCurrentTab('dashboard')}
            onSelectFinding={(f) => setSelectedFinding(f)}
            onOpenCopilot={handleOpenCopilot}
          />
        )}

        {currentTab === 'scans' && (
          <ScanHistoryView
            onViewScan={handleViewScan}
            onRerunScan={handleRerunScan}
          />
        )}

        {currentTab === 'tools' && (
          <ScannerStatusView
            onStartScan={() => setCurrentTab('new-scan')}
          />
        )}

        {currentTab === 'settings' && (
          <SettingsView
            currentUser={currentUser}
            aiStatus={aiStatus}
            onRefreshAiStatus={checkAuthAndInit}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-400">Secure Lens</span>
            <span>•</span>
            <span>Automated Web Security & Vulnerability Platform</span>
          </div>
          <div className="flex items-center gap-4 text-slate-500">
            <span>OWASP ASVS Standard</span>
            <span>•</span>
            <span>Non-Destructive Defensive Scope</span>
            <span>•</span>
            <span>SSRF Guard Enforced</span>
          </div>
        </div>
      </footer>

      {/* Finding Detail Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onOpenCopilot={handleOpenCopilot}
      />

      {/* Interactive AI Security Copilot Drawer */}
      <SecurityCopilotDrawer
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
        contextTarget={copilotContext.targetUrl}
        contextFinding={copilotContext.findingTitle}
      />

      {/* Authentication Modal */}
      <AuthModal
        isOpen={isAuthOpen}
        onClose={() => setIsAuthOpen(false)}
        onSuccess={(user) => setCurrentUser(user)}
      />
    </div>
  );
}
