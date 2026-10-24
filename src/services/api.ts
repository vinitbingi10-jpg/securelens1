import {
  User,
  ScanJob,
  ScannerFinding,
  ScannerRun,
  DashboardSummary,
  ToolMetadata,
  AiStatus,
  AIAnalysisResult,
  AuditLog,
} from '../types';

const TOKEN_KEY = 'secure_lens_auth_token';

class ApiService {
  private token: string | null = null;

  constructor() {
    this.token = localStorage.getItem(TOKEN_KEY);
  }

  public setToken(token: string | null) {
    this.token = token;
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  }

  public getToken(): string | null {
    return this.token;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(endpoint, {
      ...options,
      headers,
    });

    if (!response.ok) {
      let errorMsg = `Request failed with status ${response.status}`;
      try {
        const errorData = await response.json();
        errorMsg = errorData.error || errorMsg;
      } catch {
        // use default errorMsg
      }
      throw new Error(errorMsg);
    }

    return response.json();
  }

  // Auth
  public async register(email: string, password: string, displayName?: string): Promise<{ token: string; user: User }> {
    const data = await this.request<{ token: string; user: User }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, displayName }),
    });
    this.setToken(data.token);
    return data;
  }

  public async login(email: string, password: string): Promise<{ token: string; user: User }> {
    const data = await this.request<{ token: string; user: User }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    this.setToken(data.token);
    return data;
  }

  public async logout(): Promise<void> {
    try {
      await this.request('/api/auth/logout', { method: 'POST' });
    } catch {
      // ignore
    } finally {
      this.setToken(null);
    }
  }

  public async getMe(): Promise<{ user: User | null }> {
    return this.request<{ user: User | null }>('/api/auth/me');
  }

  // Dashboard
  public async getDashboardSummary(): Promise<DashboardSummary> {
    return this.request<DashboardSummary>('/api/dashboard/summary');
  }

  // Scans
  public async validateTarget(targetUrl: string): Promise<{
    valid: boolean;
    sanitizedUrl: string;
    hostname: string;
    resolvedIp?: string;
    error?: string;
  }> {
    return this.request('/api/scans/validate-target', {
      method: 'POST',
      body: JSON.stringify({ targetUrl }),
    });
  }

  public async createScan(params: {
    targetUrl: string;
    scanProfile: string;
    selectedTools: string[];
    enableNetworkChecks: boolean;
    authorizationConfirmed: boolean;
  }): Promise<{ message: string; scan: ScanJob }> {
    return this.request('/api/scans', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  public async getScans(): Promise<ScanJob[]> {
    return this.request<ScanJob[]>('/api/scans');
  }

  public async getScanById(scanId: string): Promise<{
    scan: ScanJob;
    runs: ScannerRun[];
    findings: ScannerFinding[];
  }> {
    return this.request(`/api/scans/${scanId}`);
  }

  public async cancelScan(scanId: string): Promise<{ success: boolean; message: string }> {
    return this.request(`/api/scans/${scanId}/cancel`, { method: 'POST' });
  }

  public async deleteScan(scanId: string): Promise<{ success: boolean }> {
    return this.request(`/api/scans/${scanId}`, { method: 'DELETE' });
  }

  // Findings
  public async getFindings(): Promise<ScannerFinding[]> {
    return this.request<ScannerFinding[]>('/api/findings');
  }

  public async getFindingById(findingId: string): Promise<{
    finding: ScannerFinding;
    aiAnalysis: AIAnalysisResult | null;
  }> {
    return this.request(`/api/findings/${findingId}`);
  }

  public async requestAiAnalysis(findingId: string): Promise<AIAnalysisResult> {
    return this.request(`/api/findings/${findingId}/analyze-ai`, { method: 'POST' });
  }

  public async askCopilot(params: {
    question: string;
    targetUrl: string;
    findingTitle?: string;
  }): Promise<{ answer: string }> {
    return this.request('/api/ai/copilot-query', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  // Tools & Settings
  public async getTools(): Promise<ToolMetadata[]> {
    return this.request<ToolMetadata[]>('/api/tools');
  }

  public async getAiStatus(): Promise<AiStatus> {
    return this.request<AiStatus>('/api/settings/ai/status');
  }

  public async testAiConnection(): Promise<{ success: boolean; latencyMs: number; message: string }> {
    return this.request('/api/settings/ai/test', { method: 'POST' });
  }

  public async getAuditLogs(): Promise<AuditLog[]> {
    return this.request<AuditLog[]>('/api/audit-logs');
  }
}

export const api = new ApiService();
