import dns from 'dns/promises';
import net from 'net';

/**
 * Validates target URLs to strictly prevent Server-Side Request Forgery (SSRF)
 * and access to private, loopback, link-local, multicast, or cloud metadata endpoints.
 */

// Private IPv4 CIDR blocks
const PRIVATE_IPV4_RANGES = [
  { start: '0.0.0.0', end: '0.255.255.255' },         // Current network
  { start: '10.0.0.0', end: '10.255.255.255' },       // Class A private
  { start: '100.64.0.0', end: '100.127.255.255' },   // Carrier-grade NAT
  { start: '127.0.0.0', end: '127.255.255.255' },   // Loopback
  { start: '169.254.0.0', end: '169.254.255.255' }, // Link-local / Cloud metadata (AWS, GCP, Azure: 169.254.169.254)
  { start: '172.16.0.0', end: '172.31.255.255' },   // Class B private
  { start: '192.0.0.0', end: '192.0.0.255' },       // IETF protocol assignments
  { start: '192.168.0.0', end: '192.168.255.255' }, // Class C private
  { start: '198.18.0.0', end: '198.19.255.255' },   // Benchmark tests
  { start: '224.0.0.0', end: '239.255.255.255' },   // Multicast
  { start: '240.0.0.0', end: '255.255.255.255' },   // Reserved / Broadcast
];

// Blocked hostnames associated with metadata or internal testing
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  '127.0.0.1',
  '::1',
  '0.0.0.0',
  'metadata.google.internal',
  'metadata',
  'instance-data',
]);

function ipv4ToLong(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

export function isPrivateIPv4(ip: string): boolean {
  const ipLong = ipv4ToLong(ip);
  for (const range of PRIVATE_IPV4_RANGES) {
    const startLong = ipv4ToLong(range.start);
    const endLong = ipv4ToLong(range.end);
    if (ipLong >= startLong && ipLong <= endLong) {
      return true;
    }
  }
  return false;
}

export function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  // Loopback
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
  // Unspecified
  if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true;
  // Unique local addresses (fc00::/7)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
  // Link-local unicast (fe80::/10)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || 
      normalized.startsWith('fea') || normalized.startsWith('feb')) return true;
  // IPv4-mapped IPv6 (::ffff:x.x.x.x)
  if (normalized.startsWith('::ffff:')) {
    const v4Part = normalized.replace('::ffff:', '');
    if (net.isIPv4(v4Part)) {
      return isPrivateIPv4(v4Part);
    }
  }
  return false;
}

export interface TargetValidationResult {
  valid: boolean;
  sanitizedUrl: string;
  hostname: string;
  resolvedIp?: string;
  port: number;
  protocol: string;
  error?: string;
}

export async function validateScanTarget(rawUrl: string, allowLocalForTesting = false): Promise<TargetValidationResult> {
  let trimmed = rawUrl.trim();

  // If URL has a protocol scheme that is not http or https, flag it immediately
  const protocolMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (protocolMatch) {
    const proto = protocolMatch[1].toLowerCase();
    if (proto !== 'http' && proto !== 'https') {
      return {
        valid: false,
        sanitizedUrl: trimmed,
        hostname: '',
        port: 0,
        protocol: `${proto}:`,
        error: `Unsupported protocol ${proto}:. Only http: and https: targets are authorized for scanning.`,
      };
    }
  } else {
    trimmed = 'https://' + trimmed;
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch (err) {
    return {
      valid: false,
      sanitizedUrl: trimmed,
      hostname: '',
      port: 0,
      protocol: '',
      error: 'Invalid target URL format. Must be a well-formed HTTP/HTTPS address.',
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      sanitizedUrl: trimmed,
      hostname: parsed.hostname,
      port: 0,
      protocol: parsed.protocol,
      error: `Unsupported protocol ${parsed.protocol}. Only http: and https: targets are authorized for scanning.`,
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);

  // Check if port is in restricted danger ports (e.g., SMTP, internal database ports)
  const DANGEROUS_PORTS = [22, 23, 25, 110, 143, 3306, 5432, 6379, 27017, 9200, 11211];
  if (DANGEROUS_PORTS.includes(port)) {
    return {
      valid: false,
      sanitizedUrl: parsed.origin,
      hostname,
      port,
      protocol: parsed.protocol,
      error: `Port ${port} is restricted to prevent unauthorized service probing. Only web-service ports are permitted.`,
    };
  }

  if (BLOCKED_HOSTNAMES.has(hostname) && !allowLocalForTesting) {
    return {
      valid: false,
      sanitizedUrl: parsed.origin,
      hostname,
      port,
      protocol: parsed.protocol,
      error: `Access to internal host '${hostname}' is prohibited by SSRF security policy.`,
    };
  }

  // Resolve IP to prevent DNS rebinding or private IP probing
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    if (!addresses || addresses.length === 0) {
      return {
        valid: false,
        sanitizedUrl: parsed.origin,
        hostname,
        port,
        protocol: parsed.protocol,
        error: `Could not resolve hostname '${hostname}'. Verify domain DNS records exist.`,
      };
    }

    // Inspect all resolved IP addresses
    for (const record of addresses) {
      const ip = record.address;
      if (record.family === 4) {
        if (isPrivateIPv4(ip) && !allowLocalForTesting) {
          return {
            valid: false,
            sanitizedUrl: parsed.origin,
            hostname,
            resolvedIp: ip,
            port,
            protocol: parsed.protocol,
            error: `Target resolved to non-public/private IP (${ip}). Scans against internal network ranges are blocked.`,
          };
        }
      } else if (record.family === 6) {
        if (isPrivateIPv6(ip) && !allowLocalForTesting) {
          return {
            valid: false,
            sanitizedUrl: parsed.origin,
            hostname,
            resolvedIp: ip,
            port,
            protocol: parsed.protocol,
            error: `Target resolved to reserved IPv6 address (${ip}). Scans against internal ranges are blocked.`,
          };
        }
      }
    }

    return {
      valid: true,
      sanitizedUrl: `${parsed.protocol}//${parsed.host}${parsed.pathname}`,
      hostname,
      resolvedIp: addresses[0].address,
      port,
      protocol: parsed.protocol,
    };
  } catch (err: any) {
    return {
      valid: false,
      sanitizedUrl: parsed.origin,
      hostname,
      port,
      protocol: parsed.protocol,
      error: `DNS lookup failed for '${hostname}': ${err.message || 'Unknown network resolution error'}`,
    };
  }
}
