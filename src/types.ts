export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface User {
  id: string;
  email: string;
  displayName: string;
  role: 'owner' | 'analyst' | 'viewer';
}

export interface ScannerFinding {
  id: string;
  scanJobId: string;
  scannerRunId?: string;
  scannerName: string;
  title: string;
  category: string;
  severity: SeverityLevel;
  originalSeverity: SeverityLevel;
  confidence: 'CERTAIN' | 'FIRM' | 'TENTATIVE';
  verificationStatus: 'CONFIRMED' | 'POTENTIAL' | 'INFORMATIONAL';
  description: string;
  affectedUrl: string;
  affectedParameter?: string;
  evidence: {
    rawHeader?: string;
    matchedPattern?: string;
    snippet?: string;
    details?: Record<string, any>;
  };
  remediation?: string;
  fingerprint: string;
  cwe?: string;
  owaspCategory?: string;
  firstSeenAt: string;
  createdAt: string;
}

export interface AIAnalysisResult {
  id: string;
  findingId: string;
  provider: string;
  model: string;
  title: string;
  explanation: string;
  impact: {
    businessImpact: string;
    technicalImpact: string;
  };
  recommendedSeverity: SeverityLevel;
  remediation: {
    overview: string;
    codeFixes: Array<{
      platform: string;
      code: string;
    }>;
    verificationSteps: string[];
  };
  confidence: string;
  references: Array<{
    title: string;
    url: string;
  }>;
  createdAt: string;
}

export interface ScannerRun {
  id: string;
  scanJobId: string;
  scannerName: string;
  scannerVersion: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  startedAt?: string;
  completedAt?: string;
  durationSeconds?: number;
  resultSummary?: string;
  findingsCount: number;
  errorSummary?: string;
}

export interface ScanJob {
  id: string;
  userId: string;
  targetUrl: string;
  targetHost: string;
  resolvedIp?: string;
  scanProfile: 'quick_health' | 'owasp_standard' | 'full_audit' | 'custom';
  selectedTools: string[];
  enableNetworkChecks: boolean;
  authorizationConfirmedAt: string;
  status: 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';
  startedAt?: string;
  completedAt?: string;
  durationSeconds?: number;
  errorSummary?: string;
  grade?: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  securityScore?: number;
  metrics: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    totalFindings: number;
  };
  createdAt: string;
}

export interface DashboardSummary {
  totalScans: number;
  completedScans: number;
  failedScans: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  infoFindings: number;
  categories: Array<{
    category: string;
    count: number;
    highOrCrit: number;
  }>;
  recentScans: ScanJob[];
  recentFindings: ScannerFinding[];
}

export interface ToolMetadata {
  id: string;
  name: string;
  version: string;
  category: string;
  description: string;
  status: 'installed' | 'unavailable' | 'active_node_engine';
  installed: boolean;
  activeEngine: string;
  configStatus: 'configured' | 'opt_in_required' | 'ready';
  isSafePassive: boolean;
  requiresExplicitNetworkConsent?: boolean;
  setupGuide: {
    prerequisites: string;
    cliCommand: string;
    docsUrl: string;
    description: string;
  };
}

export interface AiStatus {
  configured: boolean;
  provider: string;
  model: string;
  keyPresent: boolean;
  message: string;
}

export interface AuditLog {
  id: string;
  userId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  safeMetadata: Record<string, any>;
  createdAt: string;
}
