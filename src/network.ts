import net from 'node:net';
import dns from 'node:dns/promises';

export interface ValidateHttpUrlOptions {
  allowPrivateNetwork?: boolean;
}

export interface HttpPostOptions {
  url: string;
  body: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  allowPrivateNetwork?: boolean;
  maxRetries?: number;
  retryDelayMs?: number;
}

export interface HttpPostResult {
  ok: boolean;
  statusCode?: number;
  statusText?: string;
  responseBody?: string;
  durationMs: number;
  attempts?: number;
  error?: string;
}

const RESTRICTED_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'metadata.azure.internal',
]);

function normalizeHostname(rawHostname: string): string {
  return rawHostname
    .trim()
    .toLowerCase()
    .replace(/^\[/, '')
    .replace(/\]$/, '')
    .replace(/\.+$/, '');
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    return false;
  }
  const octets = parts.map((p) => Number(p));
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
    return true;
  }

  const [a, b, c] = octets;

  // 0.0.0.0/8 (current network / unspecified)
  if (a === 0) return true;
  // 10.0.0.0/8 (RFC 1918)
  if (a === 10) return true;
  // 100.64.0.0/10 (Carrier-Grade NAT RFC 6598)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8 (loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (link-local & cloud instance metadata 169.254.169.254)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (RFC 1918)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24 (IETF protocol assignments)
  if (a === 192 && b === 0 && c === 0) return true;
  // 192.168.0.0/16 (RFC 1918)
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15 (benchmarking / internal inter-network testing)
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 224.0.0.0/4 (multicast) & 240.0.0.0/4 (reserved/broadcast)
  if (a >= 224) return true;

  return false;
}

function isPrivateIpv6(ip: string): boolean {
  // Strip IPv6 zone index if present (e.g. fe80::1%eth0)
  const clean = ip.split('%')[0].toLowerCase();

  if (clean === '::' || clean === '::1') {
    return true;
  }

  // IPv4-mapped IPv6 dotted form: ::ffff:127.0.0.1
  if (clean.startsWith('::ffff:')) {
    const tail = clean.slice('::ffff:'.length);
    if (net.isIPv4(tail)) {
      return isPrivateIpv4(tail);
    }
    // Hex form: ::ffff:7f00:0001
    const hexMatch = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(tail);
    if (hexMatch) {
      const hi = parseInt(hexMatch[1], 16);
      const lo = parseInt(hexMatch[2], 16);
      const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isPrivateIpv4(ipv4);
    }
  }

  // Extract first hextet
  const firstSegment = clean.split(':')[0];
  if (firstSegment) {
    const val = parseInt(firstSegment, 16);
    if (!Number.isNaN(val)) {
      // fc00::/7 (Unique Local Addresses)
      if ((val & 0xfe00) === 0xfc00) return true;
      // fe80::/10 (Link-Local)
      if ((val & 0xffc0) === 0xfe80) return true;
      // ff00::/8 (Multicast)
      if ((val & 0xff00) === 0xff00) return true;
    }
  }

  return false;
}

/**
 * Checks whether an IPv4 or IPv6 literal belongs to a private, loopback, link-local,
 * metadata, multicast, or unspecified address block.
 */
export function isPrivateIpAddress(ip: string): boolean {
  const normalized = normalizeHostname(ip).split('%')[0];
  const version = net.isIP(normalized);
  if (version === 4) {
    return isPrivateIpv4(normalized);
  }
  if (version === 6) {
    return isPrivateIpv6(normalized);
  }
  return false;
}

/**
 * Checks whether a hostname or IP literal targets a local, internal, or private network address.
 */
export function isRestrictedHostname(hostname: string): boolean {
  const normalized = normalizeHostname(hostname);
  if (!normalized) {
    return true;
  }

  if (
    RESTRICTED_HOSTNAMES.has(normalized) ||
    normalized.endsWith('.localhost') ||
    normalized.endsWith('.local') ||
    normalized.endsWith('.internal') ||
    normalized.endsWith('.localdomain')
  ) {
    return true;
  }

  if (net.isIP(normalized.split('%')[0]) !== 0) {
    return isPrivateIpAddress(normalized);
  }

  return false;
}

/**
 * Validates that a target endpoint uses strict http: or https: protocol, has no embedded
 * credentials, and (unless allowPrivateNetwork is true) does not target local/private hosts.
 */
export function validateHttpUrl(rawUrl: string, options: ValidateHttpUrlOptions = {}): URL {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`URL must use http: or https: protocol (received "${parsed.protocol}").`);
  }

  if (parsed.username || parsed.password) {
    throw new Error('URL must not contain embedded username or password credentials.');
  }

  if (!options.allowPrivateNetwork && isRestrictedHostname(parsed.hostname)) {
    throw new Error(
      `Blocked private or restricted network host "${parsed.hostname}" (pass allowPrivateNetwork: true to permit local endpoints).`
    );
  }

  return parsed;
}

function isRetryableStatusCode(statusCode: number): boolean {
  return statusCode === 408 || statusCode === 429 || (statusCode >= 500 && statusCode <= 599);
}

function computeBackoffDelayMs(baseDelayMs: number, retryAttempt: number): number {
  const exponential = baseDelayMs * Math.pow(2, retryAttempt);
  const jitter = Math.floor(Math.random() * Math.max(10, Math.floor(exponential * 0.25)));
  return exponential + jitter;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function checkResolvedAddresses(hostname: string): Promise<string | null> {
  const cleanHost = normalizeHostname(hostname);
  if (net.isIP(cleanHost.split('%')[0]) !== 0) {
    return isPrivateIpAddress(cleanHost) ? cleanHost : null;
  }

  try {
    const records = await dns.lookup(cleanHost, { all: true });
    for (const record of records) {
      if (isPrivateIpAddress(record.address)) {
        return record.address;
      }
    }
  } catch {
    // Allow underlying fetch to handle DNS lookup failures/ENOTFOUND uniformly
  }
  return null;
}

/**
 * Dispatches an HTTP POST request with JSON payload, SSRF host/DNS verification,
 * strict AbortController timeout bounds, and bounded exponential backoff retries.
 */
export async function postJsonWithTimeout(options: HttpPostOptions): Promise<HttpPostResult> {
  const {
    url,
    body,
    headers = {},
    timeoutMs = 10000,
    allowPrivateNetwork = false,
    maxRetries = 2,
    retryDelayMs = 150,
  } = options;

  const startTime = Date.now();
  let parsedUrl: URL;

  try {
    parsedUrl = validateHttpUrl(url, { allowPrivateNetwork });
  } catch (err: unknown) {
    return {
      ok: false,
      durationMs: Date.now() - startTime,
      attempts: 0,
      error: `Invalid URL: ${(err as Error).message}`,
    };
  }

  if (!allowPrivateNetwork) {
    const blockedIp = await checkResolvedAddresses(parsedUrl.hostname);
    if (blockedIp) {
      return {
        ok: false,
        durationMs: Date.now() - startTime,
        attempts: 0,
        error: `SSRF protection blocked host "${parsedUrl.hostname}" resolving to private/restricted IP "${blockedIp}".`,
      };
    }
  }

  const boundedRetries = Math.max(0, Math.min(5, Math.floor(maxRetries)));
  let lastResult: HttpPostResult | undefined;

  for (let attempt = 0; attempt <= boundedRetries; attempt++) {
    if (attempt > 0) {
      await sleep(computeBackoffDelayMs(Math.max(10, retryDelayMs), attempt - 1));
    }

    const controller = new AbortController();
    const timeoutTimer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Evidence-MCP/1.5.0',
          ...headers,
        },
        body,
        redirect: 'error',
        signal: controller.signal,
      });

      clearTimeout(timeoutTimer);
      const durationMs = Date.now() - startTime;
      const responseBody = await response.text();

      lastResult = {
        ok: response.ok,
        statusCode: response.status,
        statusText: response.statusText,
        responseBody,
        durationMs,
        attempts: attempt + 1,
        error: response.ok ? undefined : `HTTP error: ${response.status} ${response.statusText}`,
      };

      if (response.ok || !isRetryableStatusCode(response.status)) {
        return lastResult;
      }
    } catch (err: unknown) {
      clearTimeout(timeoutTimer);
      const durationMs = Date.now() - startTime;
      const isAbort = (err as Error).name === 'AbortError';
      lastResult = {
        ok: false,
        durationMs,
        attempts: attempt + 1,
        error: isAbort
          ? `Request timed out after ${timeoutMs}ms.`
          : `Network error: ${(err as Error).message}`,
      };
    }
  }

  return (
    lastResult || {
      ok: false,
      durationMs: Date.now() - startTime,
      attempts: boundedRetries + 1,
      error: 'Network error: request failed after retries.',
    }
  );
}
