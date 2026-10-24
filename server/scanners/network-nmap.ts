import net from 'net';
import { ScannerFinding } from './types.js';

interface PortCheckResult {
  port: number;
  isOpen: boolean;
  serviceGuess: string;
}

const COMMON_WEB_PORTS = [
  { port: 80, name: 'HTTP Standard' },
  { port: 443, name: 'HTTPS Standard' },
  { port: 8080, name: 'HTTP Alt / Proxy' },
  { port: 8443, name: 'HTTPS Alt' },
  { port: 3000, name: 'Node.js / Dev Web Server' },
  { port: 8000, name: 'Python / Dev HTTP Server' },
  { port: 8888, name: 'Web Admin / Jupyter' },
];

function checkPort(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = false;

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      status = true;
      socket.destroy();
      resolve(true);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });

    socket.connect(port, host);
  });
}

export async function scanNetworkPorts(hostname: string, authorizedTarget: boolean): Promise<{ findings: Omit<ScannerFinding, 'id' | 'scanJobId' | 'scannerRunId' | 'firstSeenAt' | 'createdAt'>[] }> {
  const findings: any[] = [];

  if (!authorizedTarget) {
    return { findings };
  }

  const results: PortCheckResult[] = [];

  for (const p of COMMON_WEB_PORTS) {
    const isOpen = await checkPort(hostname, p.port, 1200);
    if (isOpen) {
      results.push({ port: p.port, isOpen: true, serviceGuess: p.name });
    }
  }

  const openPorts = results.filter(r => r.isOpen);
  if (openPorts.length > 0) {
    const portList = openPorts.map(p => `${p.port} (${p.serviceGuess})`).join(', ');

    findings.push({
      scannerName: 'Nmap Safe Network Port Scanner',
      title: `Accessible Network Web Ports Discovered: [${openPorts.map(p => p.port).join(', ')}]`,
      category: 'Network & Ports',
      severity: openPorts.some(p => [3000, 8000, 8888].includes(p.port)) ? 'LOW' : 'INFO',
      originalSeverity: 'INFO',
      confidence: 'CERTAIN',
      verificationStatus: 'CONFIRMED',
      description: `Discovered active listening ports on host ${hostname}: ${portList}. Discovered ports match expected web infrastructure.`,
      affectedUrl: `tcp://${hostname}`,
      evidence: {
        details: { openPorts: results },
      },
      remediation: 'Ensure non-essential development or administration ports are filtered by firewall and not exposed directly to the public internet.',
      fingerprint: `nmap_ports_${hostname}_${openPorts.map(p => p.port).join('_')}`,
      cwe: 'CWE-200: Information Exposure Through Network Services',
      owaspCategory: 'A05:2021-Security Misconfiguration',
    });
  }

  return { findings };
}
