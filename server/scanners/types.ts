export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type VerificationStatus = 'CONFIRMED' | 'POTENTIAL' | 'INFORMATIONAL';
export type ConfidenceLevel = 'CERTAIN' | 'FIRM' | 'TENTATIVE';

export interface ScannerFinding {
  id: string;
  scanJobId: string;
  scannerRunId?: string;
  scannerName: string;
  title: string;
  category: string; // e.g. 'Headers & Policy', 'SSL/TLS', 'OWASP Top 10', 'Information Disclosure', 'Network & Ports', 'Misconfiguration'
  severity: SeverityLevel;
  originalSeverity: SeverityLevel;
  confidence: ConfidenceLevel;
  verificationStatus: VerificationStatus;
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
  fingerprint: string; // Used for deduplication
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
      platform: string; // e.g. 'Nginx', 'Apache', 'Express.js', 'Next.js', 'HTML Header'
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
  securityScore?: number; // Score out of 10 (e.g. 7.5)
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

export interface ToolMetadata {
  id: string;
  name: string;
  version: string;
  category: string;
  description: string;
  status: 'installed' | 'unavailable' | 'active_node_engine';
  isSafePassive: boolean;
  requiresExplicitNetworkConsent?: boolean;
}
