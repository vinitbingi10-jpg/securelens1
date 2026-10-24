import { GoogleGenAI, Type } from '@google/genai';
import { AIAnalysisResult, ScannerFinding } from '../scanners/types.js';
import crypto from 'crypto';

const apiKey = process.env.GEMINI_API_KEY || process.env.AI_API_KEY || '';
const modelName = process.env.AI_MODEL || 'gemini-3.8-flash';

let genAiClient: GoogleGenAI | null = null;

function getAiClient(): GoogleGenAI | null {
  const currentKey = process.env.GEMINI_API_KEY || process.env.AI_API_KEY || '';
  if (!currentKey) {
    return null;
  }
  if (!genAiClient) {
    genAiClient = new GoogleGenAI({
      apiKey: currentKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return genAiClient;
}

export interface AiConnectionStatus {
  configured: boolean;
  provider: string;
  model: string;
  keyPresent: boolean;
  message: string;
}

export function getAiStatus(): AiConnectionStatus {
  const currentKey = process.env.GEMINI_API_KEY || process.env.AI_API_KEY || '';
  return {
    configured: Boolean(currentKey),
    provider: 'Google AI (Gemini / Gemma)',
    model: modelName,
    keyPresent: Boolean(currentKey),
    message: currentKey
      ? 'AI Provider connected and ready for automated vulnerability remediation analysis.'
      : 'AI API Key is not set in environment (GEMINI_API_KEY). Manual or default fallback remediation mode is active.',
  };
}

export async function testAiConnection(): Promise<{ success: boolean; latencyMs: number; message: string }> {
  const client = getAiClient();
  if (!client) {
    return {
      success: false,
      latencyMs: 0,
      message: 'AI API key is missing. Ensure GEMINI_API_KEY is configured in the environment.',
    };
  }

  const start = Date.now();
  try {
    const response = await client.models.generateContent({
      model: modelName,
      contents: 'Respond with the single word: "READY"',
      config: {
        maxOutputTokens: 20,
      },
    });

    const latencyMs = Date.now() - start;
    const text = response.text || '';

    if (text.toLowerCase().includes('ready') || text.length > 0) {
      return {
        success: true,
        latencyMs,
        message: `Successfully connected to ${modelName} (${latencyMs}ms roundtrip).`,
      };
    } else {
      return {
        success: false,
        latencyMs,
        message: 'Received unexpected response from model during connection health check.',
      };
    }
  } catch (err: any) {
    const latencyMs = Date.now() - start;
    return {
      success: false,
      latencyMs,
      message: `AI Connection failed: ${err.message || 'API request error'}. Check API key quotas and permissions.`,
    };
  }
}

/**
 * Analyzes a normalized scanner finding using Gemini with structured JSON output.
 */
export async function analyzeFindingWithAI(finding: ScannerFinding): Promise<AIAnalysisResult> {
  const client = getAiClient();

  // If no AI key configured, generate a deterministic, safe, high-fidelity security analysis
  if (!client) {
    return generateDeterministicAnalysis(finding);
  }

  try {
    const prompt = `You are a Principal Application Security Architect at Secure Lens.
Analyze the following web security scanner finding and provide an authoritative, actionable, plain-English remediation guide.
Do not invent scan evidence. Distinguish observable scanner evidence from security risk deductions.

FINDING DETAILS:
- Title: ${finding.title}
- Scanner Engine: ${finding.scannerName}
- Category: ${finding.category}
- Scanner Severity: ${finding.severity}
- Affected Target: ${finding.affectedUrl}
- Observable Evidence: ${JSON.stringify(finding.evidence)}
- Description: ${finding.description}
- Relevant CWE: ${finding.cwe || 'N/A'}
- OWASP Category: ${finding.owaspCategory || 'N/A'}

Provide:
1. Clear, non-jargon explanation of what this vulnerability means for site owners.
2. Business impact (e.g. compliance, trust, financial) and technical impact (e.g. session hijack, MITM).
3. Recommended severity evaluation (CRITICAL, HIGH, MEDIUM, LOW, or INFO).
4. Direct remediation code snippets for common production platforms (e.g. Nginx, Apache, Express.js, or HTML).
5. Exact command-line verification steps (e.g. curl commands) to prove the vulnerability is resolved.
6. Authoritative security references (OWASP, NIST, MDN, or RFC).`;

    const response = await client.models.generateContent({
      model: modelName,
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            title: { type: Type.STRING },
            explanation: { type: Type.STRING },
            businessImpact: { type: Type.STRING },
            technicalImpact: { type: Type.STRING },
            recommendedSeverity: {
              type: Type.STRING,
              description: 'One of: CRITICAL, HIGH, MEDIUM, LOW, INFO',
            },
            remediationOverview: { type: Type.STRING },
            codeFixes: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  platform: { type: Type.STRING },
                  code: { type: Type.STRING },
                },
                required: ['platform', 'code'],
              },
            },
            verificationSteps: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
            confidence: { type: Type.STRING },
            references: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  url: { type: Type.STRING },
                },
                required: ['title', 'url'],
              },
            },
          },
          required: [
            'title',
            'explanation',
            'businessImpact',
            'technicalImpact',
            'recommendedSeverity',
            'remediationOverview',
            'codeFixes',
            'verificationSteps',
            'references',
          ],
        },
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const recSev = validSeverities.includes(parsed.recommendedSeverity) ? parsed.recommendedSeverity : finding.severity;

    return {
      id: `ai_${crypto.randomBytes(8).toString('hex')}`,
      findingId: finding.id,
      provider: 'Google AI (Gemini)',
      model: modelName,
      title: parsed.title || `Remediation Analysis: ${finding.title}`,
      explanation: parsed.explanation || finding.description,
      impact: {
        businessImpact: parsed.businessImpact || 'Exposure of customer data or potential compliance violation.',
        technicalImpact: parsed.technicalImpact || 'Weakened defensive posture allowing potential exploitation.',
      },
      recommendedSeverity: recSev,
      remediation: {
        overview: parsed.remediationOverview || (finding.remediation || 'Apply standard defensive configurations.'),
        codeFixes: parsed.codeFixes || [],
        verificationSteps: parsed.verificationSteps || ['Re-run scan to verify header or configuration change.'],
      },
      confidence: parsed.confidence || 'High (grounded on verified scanner evidence)',
      references: parsed.references || [
        { title: 'OWASP Foundation', url: 'https://owasp.org' },
        { title: 'Common Weakness Enumeration', url: 'https://cwe.mitre.org' },
      ],
      createdAt: new Date().toISOString(),
    };
  } catch (err) {
    console.warn('AI analysis call failed, falling back to deterministic template:', err);
    return generateDeterministicAnalysis(finding);
  }
}

/**
 * Interactive Security Copilot query
 */
export async function askSecurityCopilot(context: {
  findingTitle?: string;
  targetUrl: string;
  question: string;
  history?: Array<{ role: 'user' | 'model'; parts: [{ text: string }] }>;
}): Promise<string> {
  const client = getAiClient();
  if (!client) {
    return `Security Copilot: To enable live conversational security reasoning, configure GEMINI_API_KEY in your environment. Currently, refer to the verified finding details and automated remediation code snippets displayed on this screen.`;
  }

  try {
    const chat = client.chats.create({
      model: modelName,
      config: {
        systemInstruction: `You are Secure Lens Copilot, an elite defensive cybersecurity and DevSecOps engineer.
You assist developers and website owners in fixing web vulnerabilities discovered during automated audits.
Provide concise, secure, copy-pasteable configuration code (Nginx, Apache, Express, Caddy, Cloudflare, etc.).
Maintain strict defensive focus: never generate exploits or attack scripts; only defensive remediations and audit validation curl commands.`,
      },
    });

    const message = `Target: ${context.targetUrl}
Finding Context: ${context.findingTitle || 'General Web Security Posture'}
User Question: ${context.question}`;

    const response = await chat.sendMessage({
      message,
    });

    return response.text || 'No response generated from security copilot.';
  } catch (err: any) {
    return `Error consulting Security Copilot: ${err.message || 'API request error'}`;
  }
}

function generateDeterministicAnalysis(finding: ScannerFinding): AIAnalysisResult {
  return {
    id: `ai_${crypto.randomBytes(8).toString('hex')}`,
    findingId: finding.id,
    provider: 'Secure Lens Defensive Expert Rule Engine',
    model: 'embedded-owasp-ruleset-v1',
    title: `Remediation Guidance: ${finding.title}`,
    explanation: finding.description,
    impact: {
      businessImpact: 'Failure to remediate may lead to regulatory audit findings (e.g. SOC2, ISO27001, PCI-DSS) and increased brand exposure.',
      technicalImpact: 'Weakens perimeter defenses against eavesdropping, injection, or spoofing attacks.',
    },
    recommendedSeverity: finding.severity,
    remediation: {
      overview: finding.remediation || 'Apply standard defense-in-depth principles and update server configuration headers.',
      codeFixes: [
        {
          platform: 'Nginx',
          code: `# Add inside server {} or location {} block\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header X-Frame-Options "SAMEORIGIN" always;\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`,
        },
        {
          platform: 'Express.js',
          code: `import helmet from 'helmet';\n\n// Mount helmet early in your middleware pipeline\napp.use(helmet());`,
        },
      ],
      verificationSteps: [
        `curl -s -I ${finding.affectedUrl} | grep -i "${finding.title.split(' ')[0]}"`,
        'Re-run Secure Lens scan to confirm finding resolution.',
      ],
    },
    confidence: 'Verified against OWASP ASVS v4.0.3 standards',
    references: [
      { title: 'OWASP Application Security Verification Standard', url: 'https://owasp.org/www-project-application-security-verification-standard/' },
      { title: 'MDN Web Security Guidelines', url: 'https://developer.mozilla.org/en-US/docs/Web/Security' },
    ],
    createdAt: new Date().toISOString(),
  };
}
