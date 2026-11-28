import dnsPromises from 'node:dns/promises';
import https from 'node:https';
import { Readable } from 'node:stream';
import {
  ReconResult,
  DnsRecordsData,
  RdapRegistrationData,
  ReconFinding,
} from '../types/recon.js';

/**
 * Checks whether an IPv4 address is in a reserved, private, or loopback range.
 */
export function isSpecialUseIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return false;
  }

  const [a, b] = parts;

  // 127.0.0.0/8 - Loopback
  if (a === 127) return true;
  // 10.0.0.0/8 - Private
  if (a === 10) return true;
  // 172.16.0.0/12 - Private (172.16.x.x - 172.31.x.x)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 - Private
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 - Link-local
  if (a === 169 && b === 254) return true;
  // 100.64.0.0/10 - Carrier-Grade NAT / Shared Address Space (RFC 6598)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 198.18.0.0/15 - Benchmarking (RFC 2544)
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 0.0.0.0/8 - Current network
  if (a === 0) return true;
  // 224.0.0.0/4 - Multicast (224.0.0.0 - 239.255.255.255)
  if (a >= 224 && a <= 239) return true;
  // 240.0.0.0/4 - Reserved (240.0.0.0 - 255.255.255.255)
  if (a >= 240) return true;

  return false;
}

/**
 * Checks whether an IPv6 address is in a reserved, private, loopback, or IPv4-mapped/compatible range.
 */
export function isSpecialUseIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase().trim();

  // Loopback (::1) and Unspecified (::)
  if (normalized === '::1' || normalized === '::') return true;

  // IPv4-mapped or IPv4-compatible IPv6: e.g. ::ffff:127.0.0.1 or ::127.0.0.1
  if (normalized.includes('.')) {
    const v4Part = normalized.split(':').pop() || '';
    if (isSpecialUseIpv4(v4Part)) return true;
    if (normalized.startsWith('::ffff:') || normalized.startsWith('0:0:0:0:0:ffff:') || normalized.startsWith('::')) {
      return false;
    }
  }

  // Hex-encoded IPv4-mapped IPv6: ::ffff:w.x.y.z in hex
  if (normalized.startsWith('::ffff:') || normalized.startsWith('0:0:0:0:0:ffff:')) {
    const hexSuffix = normalized.replace(/^.*ffff:/, '');
    const hexParts = hexSuffix.split(':');
    if (hexParts.length === 2 && hexParts.every((p) => /^[0-9a-f]{1,4}$/.test(p))) {
      const high = parseInt(hexParts[0], 16);
      const low = parseInt(hexParts[1], 16);
      const v4 = `${(high >> 8) & 0xff}.${high & 0xff}.${(low >> 8) & 0xff}.${low & 0xff}`;
      return isSpecialUseIpv4(v4);
    }
    return true;
  }

  // Unique Local Addresses (fc00::/7)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;

  // Link-local unicast (fe80::/10)
  if (/^fe[89ab]/i.test(normalized)) return true;

  // Multicast (ff00::/8)
  if (normalized.startsWith('ff')) return true;

  return false;
}

/**
 * Validates whether a hostname is a loopback or reserved special-use domain.
 */
export function isSpecialUseHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase().trim();
  const unbracketed = lower.replace(/^\[|\]$/g, '');

  if (lower === 'localhost' || unbracketed === 'localhost') return true;
  if (
    lower.endsWith('.localhost') ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal') ||
    lower.endsWith('.test') ||
    lower.endsWith('.invalid') ||
    lower.endsWith('.example')
  ) {
    return true;
  }

  // Direct IP checks (supports unbracketed and bracketed notation)
  if (isSpecialUseIpv4(unbracketed)) return true;
  if (isSpecialUseIpv6(unbracketed)) return true;

  return false;
}

/**
 * Detects if a string is a standard decimal IPv4 address.
 */
export function isIpv4(host: string): boolean {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d+$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255 && (p === '0' || !p.startsWith('0'));
  });
}

/**
 * Detects if a string is an IPv6 address.
 */
export function isIpv6(host: string): boolean {
  return host.includes(':');
}

/**
 * Resolver interface for dependency injection in unit tests.
 */
export interface DnsResolverInterface {
  resolve4: (hostname: string) => Promise<string[]>;
  resolve6: (hostname: string) => Promise<string[]>;
  resolveMx: (hostname: string) => Promise<Array<{ exchange: string; priority: number }>>;
}

/**
 * Default native Node.js DNS resolver.
 */
export const defaultDnsResolver: DnsResolverInterface = {
  resolve4: (h) => dnsPromises.resolve4(h),
  resolve6: (h) => dnsPromises.resolve6(h),
  resolveMx: (h) => dnsPromises.resolveMx(h),
};

/**
 * Runs a promise with a strict timeout limit.
 */
async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const err = new Error(`${label} timed out after ${timeoutMs}ms`);
      err.name = 'TimeoutError';
      reject(err);
    }, timeoutMs);
  });

  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    clearTimeout(timer!);
  }
}

/**
 * Performs DNS reconnaissance on a target hostname.
 */
export async function performDnsRecon(
  hostname: string,
  resolver: DnsResolverInterface = defaultDnsResolver
): Promise<DnsRecordsData> {
  const [aRes, aaaaRes, mxRes] = await Promise.allSettled([
    withTimeout(resolver.resolve4(hostname), 3000, 'DNS A lookup'),
    withTimeout(resolver.resolve6(hostname), 3000, 'DNS AAAA lookup'),
    withTimeout(resolver.resolveMx(hostname), 3000, 'DNS MX lookup'),
  ]);

  const aRecords: string[] = aRes.status === 'fulfilled' ? aRes.value : [];
  const aaaaRecords: string[] = aaaaRes.status === 'fulfilled' ? aaaaRes.value : [];
  const mxRecords: Array<{ exchange: string; priority: number }> =
    mxRes.status === 'fulfilled' ? mxRes.value : [];

  const isTimeout =
    (aRes.status === 'rejected' && aRes.reason?.name === 'TimeoutError') ||
    (aaaaRes.status === 'rejected' && aaaaRes.reason?.name === 'TimeoutError');

  const isNxDomain =
    aRes.status === 'rejected' &&
    (aRes.reason?.code === 'ENOTFOUND' || aRes.reason?.code === 'NODATA') &&
    aaaaRes.status === 'rejected' &&
    (aaaaRes.reason?.code === 'ENOTFOUND' || aaaaRes.reason?.code === 'NODATA');

  let status: DnsRecordsData['status'] = 'resolved';
  let message: string | undefined;

  if (isTimeout) {
    status = 'timeout';
    message = 'DNS lookup timed out after 3 seconds.';
  } else if (isNxDomain) {
    status = 'nxdomain';
    message = 'Domain does not resolve to active A or AAAA records (NXDOMAIN).';
  } else if (aRecords.length === 0 && aaaaRecords.length === 0) {
    status = 'nodata';
    message = 'No active A or AAAA records found for this domain.';
  }

  return {
    status,
    aRecords,
    aaaaRecords,
    mxRecords,
    aCount: aRecords.length,
    aaaaCount: aaaaRecords.length,
    mxCount: mxRecords.length,
    hasMailExchange: mxRecords.length > 0,
    message,
  };
}

export interface IanaRdapBootstrapJson {
  version: string;
  publication: string;
  services: Array<[string[], string[]]>;
}

let bootstrapCache: {
  data: IanaRdapBootstrapJson | null;
  timestamp: number;
} = {
  data: null,
  timestamp: 0,
};

export function clearRdapBootstrapCacheForTesting(): void {
  bootstrapCache = { data: null, timestamp: 0 };
}

/**
 * Custom error thrown when a streaming or header response body exceeds the allocated byte limit.
 */
export class ResponseSizeLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ResponseSizeLimitError';
  }
}

/**
 * Reads a response body stream enforcing a strict byte limit.
 * - Checks Content-Length header early when available.
 * - Streams chunks and accumulates byte counts (Uint8Array.byteLength), measuring true bytes, not string characters.
 * - Cancels the stream reader immediately (`await reader.cancel()`) if byte limit is exceeded.
 * - Handles missing Content-Length, chunked transfers, and stream errors safely.
 */
export async function readResponseBodyWithByteLimit(
  response: Response,
  maxBytes: number,
  label: string
): Promise<string> {
  // 1. Early Content-Length check
  const contentLengthHeader = response.headers.get('content-length');
  if (contentLengthHeader) {
    const contentLength = parseInt(contentLengthHeader, 10);
    if (!isNaN(contentLength) && contentLength > maxBytes) {
      if (response.body) {
        try {
          const reader = response.body.getReader();
          await reader.cancel('Content-Length exceeded limit');
        } catch {}
      }
      throw new ResponseSizeLimitError(
        `${label} response Content-Length header (${contentLength} bytes) exceeds limit of ${maxBytes} bytes.`
      );
    }
  }

  // If no body exists, return empty string
  if (!response.body) {
    return '';
  }

  const reader = response.body.getReader();
  let totalBytes = 0;
  const chunks: Uint8Array[] = [];

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (value) {
        let chunkBytes: Uint8Array;
        if (typeof value === 'string') {
          chunkBytes = new TextEncoder().encode(value);
        } else if ((value as unknown) instanceof Uint8Array) {
          chunkBytes = value as unknown as Uint8Array;
        } else if ((value as unknown) instanceof ArrayBuffer) {
          chunkBytes = new Uint8Array(value as unknown as ArrayBuffer);
        } else {
          chunkBytes = new Uint8Array(value as unknown as ArrayLike<number>);
        }

        totalBytes += chunkBytes.byteLength;
        if (totalBytes > maxBytes) {
          try {
            await reader.cancel('Response body stream exceeded byte limit');
          } catch {}
          throw new ResponseSizeLimitError(
            `${label} response stream exceeded byte limit of ${maxBytes} bytes (read ${totalBytes} bytes).`
          );
        }
        chunks.push(chunkBytes);
      }
    }
  } catch (err) {
    if (!(err instanceof ResponseSizeLimitError)) {
      try {
        await reader.cancel('Stream reading error');
      } catch {}
    }
    throw err;
  }

  // Combine chunks and decode as UTF-8
  const combined = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8').decode(combined);
}

export async function getIanaRdapBootstrap(
  fetchFn: typeof fetch = fetch
): Promise<IanaRdapBootstrapJson | null> {
  const now = Date.now();
  // Cache TTL: 24 hours
  if (bootstrapCache.data && now - bootstrapCache.timestamp < 86400000) {
    return bootstrapCache.data;
  }

  try {
    const res = await fetchFn('https://data.iana.org/rdap/dns.json', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(4000), // Strict 4-second timeout
    });

    if (!res.ok) {
      console.error(`Failed to fetch IANA RDAP bootstrap registry: HTTP ${res.status}`);
      return bootstrapCache.data;
    }

    const text = await readResponseBodyWithByteLimit(res, 1048576, 'IANA RDAP bootstrap');
    const json = JSON.parse(text) as IanaRdapBootstrapJson;
    if (
      json &&
      typeof json === 'object' &&
      Array.isArray(json.services) &&
      json.services.every(
        (s) =>
          Array.isArray(s) &&
          s.length >= 2 &&
          Array.isArray(s[0]) &&
          Array.isArray(s[1])
      )
    ) {
      bootstrapCache = { data: json, timestamp: now };
      return json;
    } else {
      console.error('Invalid IANA RDAP bootstrap structure: services array is malformed.');
    }
  } catch (err: unknown) {
    if (err instanceof ResponseSizeLimitError) {
      console.error(`IANA RDAP bootstrap response exceeded safety size limit: ${err.message}`);
    } else {
      console.error('Failed to fetch IANA RDAP bootstrap registry:', err instanceof Error ? err.message : 'Unknown');
    }
  }

  return bootstrapCache.data;
}

export async function resolveRdapBaseUrl(
  domain: string,
  fetchFn: typeof fetch = fetch
): Promise<string> {
  const lowerDomain = domain.toLowerCase().trim();
  const labels = lowerDomain.split('.');

  const bootstrap = await getIanaRdapBootstrap(fetchFn);
  if (bootstrap && Array.isArray(bootstrap.services)) {
    let bestMatchUrl: string | null = null;
    let maxMatchedLength = 0;

    for (const [tldList, baseUrlList] of bootstrap.services) {
      if (!Array.isArray(tldList) || !Array.isArray(baseUrlList)) continue;
      for (const tld of tldList) {
        const tldParts = tld.toLowerCase().split('.');
        if (labels.length >= tldParts.length) {
          const tail = labels.slice(labels.length - tldParts.length);
          if (tail.join('.') === tldParts.join('.')) {
            if (tldParts.length > maxMatchedLength) {
              const httpsUrl = baseUrlList.find(
                (u) => typeof u === 'string' && u.startsWith('https://')
              );
              if (httpsUrl) {
                maxMatchedLength = tldParts.length;
                bestMatchUrl = httpsUrl;
              }
            }
          }
        }
      }
    }

    if (bestMatchUrl) {
      try {
        const parsedBase = new URL(bestMatchUrl);
        if (parsedBase.protocol === 'https:' && !isSpecialUseHostname(parsedBase.hostname)) {
          return bestMatchUrl;
        }
      } catch {}
    }
  }

  // Fallback defaults based on TLD
  const tld = labels[labels.length - 1];
  if (tld === 'com' || tld === 'net') {
    return 'https://rdap.verisign.com/com/v1/';
  } else if (tld === 'org') {
    return 'https://rdap.publicinterestregistry.org/rdap/';
  } else if (tld === 'gov') {
    return 'https://rdap.nic.gov/';
  } else if (tld === 'edu') {
    return 'https://rdap.educause.edu/rdap/';
  }

  return 'https://rdap.org/';
}

/**
 * Constructs the canonical RDAP resource path `/domain/{domain}`.
 * Example: `{baseUrl}/domain/{domain}`.
 */
export function constructRdapQueryUrl(baseUrl: string, domain: string): string {
  const cleanBase = baseUrl.trim().replace(/\/+$/, '');
  const encodedDomain = encodeURIComponent(domain.trim().toLowerCase());
  if (cleanBase.endsWith('/domain')) {
    return `${cleanBase}/${encodedDomain}`;
  }
  return `${cleanBase}/domain/${encodedDomain}`;
}

/**
 * Validates an outbound RDAP URL:
 * - Strict HTTPS enforcement
 * - Reject special-use, loopback, link-local, private, or reserved hostnames and IPs
 * - DNS resolution check to mitigate DNS rebinding and private infrastructure access
 */
/**
 * Creates a custom DNS lookup function that always resolves to the pinned IP address.
 * Bypasses OS DNS resolution at connect time to prevent DNS rebinding / TOCTOU attacks.
 */
export function createPinnedLookup(
  pinnedIp: string
): (
  hostname: string,
  optionsOrCallback: unknown,
  callback?: (
    err: NodeJS.ErrnoException | null,
    address: string | Array<{ address: string; family: number }>,
    family?: number
  ) => void
) => void {
  const isIpV6 = pinnedIp.includes(':');
  const family = isIpV6 ? 6 : 4;

  return (
    _hostname: string,
    optionsOrCallback: unknown,
    callback?: (
      err: NodeJS.ErrnoException | null,
      address: string | Array<{ address: string; family: number }>,
      family?: number
    ) => void
  ) => {
    const cb = (
      typeof optionsOrCallback === 'function' ? optionsOrCallback : callback
    ) as
      | ((
          err: NodeJS.ErrnoException | null,
          address: string | Array<{ address: string; family: number }>,
          family?: number
        ) => void)
      | undefined;
    if (!cb) return;

    const opts = typeof optionsOrCallback === 'object' && optionsOrCallback ? optionsOrCallback : {};
    if ((opts as { all?: boolean }).all) {
      cb(null, [{ address: pinnedIp, family }]);
    } else {
      cb(null, pinnedIp, family);
    }
  };
}

/**
 * Normalizes an IP string by stripping any ::ffff: IPv4-mapped prefix.
 */
function normalizeIp(ip: string): string {
  return ip.trim().toLowerCase().replace(/^::ffff:/, '');
}

/**
 * Checks if two IP addresses match, taking into account IPv4-mapped IPv6 prefixes.
 */
export function ipMatches(socketIp?: string, expectedIp?: string): boolean {
  if (!socketIp || !expectedIp) return false;
  return normalizeIp(socketIp) === normalizeIp(expectedIp);
}

/**
 * Performs an HTTPS request pinned directly to a validated IP address.
 * - Connects socket to `pinnedIp` via custom lookup.
 * - Sets SNI hostname via `servername: targetUrl.hostname` to preserve TLS certificate validation.
 * - Verifies socket remote address matches `pinnedIp`.
 * - Converts `http.IncomingMessage` to standard Web `Response`.
 */
export function pinnedHttpsFetch(
  targetUrl: URL,
  pinnedIp: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    timeoutMs?: number;
    signal?: AbortSignal;
  } = {}
): Promise<Response> {
  return new Promise((resolve, reject) => {
    if (targetUrl.protocol !== 'https:') {
      return reject(new Error(`Insecure protocol scheme "${targetUrl.protocol}". Only HTTPS is permitted.`));
    }

    const port = targetUrl.port ? Number(targetUrl.port) : 443;
    const method = options.method || 'GET';
    const timeoutMs = options.timeoutMs ?? 4000;

    let settled = false;

    const reqOptions: https.RequestOptions = {
      protocol: targetUrl.protocol,
      hostname: targetUrl.hostname,
      port,
      path: `${targetUrl.pathname || '/'}${targetUrl.search || ''}`,
      method,
      headers: {
        Host: targetUrl.host,
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) FraudLinkDetector/1.0',
        Connection: 'close',
        ...options.headers,
      },
      servername: targetUrl.hostname,
      lookup: createPinnedLookup(pinnedIp) as unknown as https.RequestOptions['lookup'],
      timeout: timeoutMs,
    };

    const req = https.request(reqOptions, (res) => {
      // Verify that the socket connected to the validated IP
      const remoteAddress = res.socket?.remoteAddress;
      if (!ipMatches(remoteAddress, pinnedIp)) {
        req.destroy(new Error(`Socket remote address mismatch: connected to ${remoteAddress}, expected ${pinnedIp}`));
        if (!settled) {
          settled = true;
          const mismatchErr = new Error(`Connection security error: socket connected to unverified address ${remoteAddress}`);
          mismatchErr.name = 'SecurityError';
          reject(mismatchErr);
        }
        return;
      }

      // Convert Node headers to web Headers
      const webHeaders = new Headers();
      for (const [key, val] of Object.entries(res.headers)) {
        if (val === undefined) continue;
        if (Array.isArray(val)) {
          for (const v of val) webHeaders.append(key, v);
        } else {
          webHeaders.set(key, val);
        }
      }

      const webStream = Readable.toWeb(res) as ReadableStream<Uint8Array>;
      const webResponse = new Response(webStream, {
        status: res.statusCode || 200,
        statusText: res.statusMessage || 'OK',
        headers: webHeaders,
      });

      if (!settled) {
        settled = true;
        resolve(webResponse);
      }
    });

    if (options.signal) {
      if (options.signal.aborted) {
        req.destroy(new Error('AbortError'));
        settled = true;
        const abortErr = new Error('The operation was aborted');
        abortErr.name = 'AbortError';
        return reject(abortErr);
      }
      options.signal.addEventListener('abort', () => {
        req.destroy(new Error('AbortError'));
        if (!settled) {
          settled = true;
          const abortErr = new Error('The operation was aborted');
          abortErr.name = 'AbortError';
          reject(abortErr);
        }
      });
    }

    req.on('timeout', () => {
      req.destroy(new Error('TimeoutError'));
      if (!settled) {
        settled = true;
        const timeoutErr = new Error(`Request timed out after ${timeoutMs}ms`);
        timeoutErr.name = 'TimeoutError';
        reject(timeoutErr);
      }
    });

    req.on('error', (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });

    req.end();
  });
}

export interface RdapValidationResult {
  valid: boolean;
  error?: string;
  url?: URL;
  pinnedIp?: string;
  isTimeout?: boolean;
  isDnsError?: boolean;
}

/**
 * Validates an outbound RDAP URL:
 * - Strict HTTPS enforcement
 * - Reject special-use, loopback, link-local, private, or reserved hostnames and IPs
 * - DNS resolution check to mitigate DNS rebinding and private infrastructure access
 * - Pins validated public IP address for connection-level enforcement
 * - Fails closed on DNS lookup errors or timeouts
 */
export async function validateRdapOutboundUrl(
  urlStr: string,
  resolver: DnsResolverInterface = defaultDnsResolver
): Promise<RdapValidationResult> {
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    return { valid: false, error: 'Malformed URL' };
  }

  if (parsed.protocol !== 'https:') {
    return { valid: false, error: `Insecure protocol scheme "${parsed.protocol}". Only HTTPS is permitted for RDAP.` };
  }

  const hostname = parsed.hostname;
  if (!hostname) {
    return { valid: false, error: 'Missing hostname in RDAP destination' };
  }

  const unbracketedHost = hostname.replace(/^\[|\]$/g, '');

  if (isSpecialUseHostname(hostname) || isSpecialUseHostname(unbracketedHost)) {
    return { valid: false, error: `Destination host "${hostname}" is a reserved or special-use address.` };
  }

  if (isIpv4(unbracketedHost)) {
    if (isSpecialUseIpv4(unbracketedHost)) {
      return { valid: false, error: `Destination IP "${unbracketedHost}" is a private or reserved IPv4 address.` };
    }
    return { valid: true, url: parsed, pinnedIp: unbracketedHost };
  }

  if (isIpv6(unbracketedHost)) {
    if (isSpecialUseIpv6(unbracketedHost)) {
      return { valid: false, error: `Destination IP "${unbracketedHost}" is a private or reserved IPv6 address.` };
    }
    return { valid: true, url: parsed, pinnedIp: unbracketedHost };
  }

  try {
    const [v4Result, v6Result] = await Promise.allSettled([
      withTimeout(resolver.resolve4(hostname), 2000, 'RDAP host IPv4 lookup'),
      withTimeout(resolver.resolve6(hostname), 2000, 'RDAP host IPv6 lookup'),
    ]);

    const isTimeout =
      (v4Result.status === 'rejected' && v4Result.reason?.name === 'TimeoutError') ||
      (v6Result.status === 'rejected' && v6Result.reason?.name === 'TimeoutError');

    if (isTimeout) {
      return {
        valid: false,
        error: `DNS lookup timed out for RDAP host "${hostname}".`,
        isTimeout: true,
      };
    }

    const v4Ips = v4Result.status === 'fulfilled' ? v4Result.value : [];
    const v6Ips = v6Result.status === 'fulfilled' ? v6Result.value : [];
    const allIps = [...v4Ips, ...v6Ips];

    if (allIps.length === 0) {
      return {
        valid: false,
        error: `DNS resolution failed for RDAP host "${hostname}".`,
        isDnsError: true,
      };
    }

    for (const ip of allIps) {
      if (isSpecialUseIpv4(ip) || isSpecialUseIpv6(ip)) {
        return { valid: false, error: `Destination host "${hostname}" resolves to restricted address ${ip}.` };
      }
    }

    return { valid: true, url: parsed, pinnedIp: allIps[0] };
  } catch (err: unknown) {
    const isTimeout = err instanceof Error && err.name === 'TimeoutError';
    return {
      valid: false,
      error: `DNS resolution error for RDAP host "${hostname}".`,
      isTimeout,
      isDnsError: !isTimeout,
    };
  }
}

/**
 * Queries RDAP for domain registration information.
 */
export async function performRdapLookup(
  domain: string,
  fetchFn: typeof fetch = fetch,
  resolver: DnsResolverInterface = defaultDnsResolver
): Promise<RdapRegistrationData> {
  // Validate domain format before constructing URL to prevent injection
  const trimmed = domain.trim().toLowerCase();
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(trimmed)) {
    return {
      status: 'unsupported',
      message: 'Domain format is not eligible for RDAP lookup.',
    };
  }

  // Resolve authoritative RDAP base URL via IANA DNS bootstrap registry (RFC 9224)
  const baseRdapUrl = await resolveRdapBaseUrl(trimmed, fetchFn);
  const rdapEndpoint = constructRdapQueryUrl(baseRdapUrl, trimmed);

  const MAX_REDIRECTS = 3;
  let currentUrl = rdapEndpoint;
  let redirectCount = 0;
  let response: Response;
  let endpointHostname = 'rdap.org';

  while (true) {
    try {
      endpointHostname = new URL(currentUrl).hostname;
    } catch {}

    const validation = await validateRdapOutboundUrl(currentUrl, resolver);
    if (!validation.valid) {
      if (validation.isTimeout) {
        console.error(`RDAP diagnostic classification [TIMEOUT] for endpoint host ${endpointHostname}: ${validation.error}`);
        return {
          status: 'timeout',
          message: 'RDAP request timed out after 4 seconds.',
        };
      }
      if (validation.isDnsError) {
        console.error(`RDAP diagnostic classification [DNS_FAILURE] for endpoint host ${endpointHostname}: ${validation.error}`);
        return {
          status: 'error',
          message: 'Unable to connect to RDAP service due to network or DNS failure.',
        };
      }
      console.error(`RDAP diagnostic classification [SECURITY_BLOCKED]: ${validation.error}`);
      return {
        status: 'error',
        message: validation.error || 'RDAP request blocked by destination security policy.',
      };
    }

    const pinnedIp = validation.pinnedIp!;
    const parsedTargetUrl = validation.url!;

    try {
      if (fetchFn === fetch) {
        response = await pinnedHttpsFetch(parsedTargetUrl, pinnedIp, {
          method: 'GET',
          headers: {
            Accept: 'application/rdap+json, application/json',
          },
          timeoutMs: 4000,
        });
      } else {
        response = await fetchFn(currentUrl, {
          method: 'GET',
          headers: {
            Accept: 'application/rdap+json, application/json',
          },
          redirect: 'manual',
          signal: AbortSignal.timeout(4000),
          ...({ pinnedIp } as unknown as object),
        });
      }
    } catch (err: unknown) {
      const isTimeout =
        err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
      const isDns = err instanceof Error && ('code' in err) && (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN');
      const failureCategory = isTimeout ? 'TIMEOUT' : isDns ? 'DNS_FAILURE' : 'NETWORK_FAILURE';
      console.error(`RDAP diagnostic classification [${failureCategory}] for endpoint host ${endpointHostname}:`, err instanceof Error ? err.message : 'Unknown');

      return {
        status: isTimeout ? 'timeout' : 'error',
        message: isTimeout
          ? 'RDAP request timed out after 4 seconds.'
          : 'Unable to connect to RDAP service due to network or DNS failure.',
      };
    }

    // Manual redirect handling: validate every redirect target before following it
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) {
        console.error(`RDAP diagnostic classification [REDIRECT_ERROR]: endpoint host ${endpointHostname}, missing Location header`);
        return {
          status: 'error',
          message: 'RDAP server returned redirect without Location header.',
        };
      }

      redirectCount++;
      if (redirectCount > MAX_REDIRECTS) {
        console.error(`RDAP diagnostic classification [REDIRECT_LIMIT_EXCEEDED]: endpoint host ${endpointHostname}`);
        return {
          status: 'error',
          message: 'RDAP lookup exceeded maximum redirect hops.',
        };
      }

      try {
        const nextUrl = new URL(location, currentUrl);
        currentUrl = nextUrl.href;
        continue;
      } catch {
        console.error(`RDAP diagnostic classification [INVALID_REDIRECT_URL]: endpoint host ${endpointHostname}, Location: ${location}`);
        return {
          status: 'error',
          message: 'RDAP server returned invalid redirect location.',
        };
      }
    }

    // Not a redirect - break loop and process response
    break;
  }

  const httpStatus = response.status;
  const contentType = response.headers.get('content-type') || 'unknown';

  if (httpStatus === 404 || httpStatus === 501) {
    console.error(`RDAP diagnostic classification [UNSUPPORTED_TLD]: endpoint host ${endpointHostname}, HTTP ${httpStatus}`);
    return {
      status: 'unsupported',
      message: 'RDAP information is not supported or not available for this TLD.',
    };
  }

  if (!response.ok) {
    console.error(`RDAP diagnostic classification [HTTP_ERROR]: endpoint host ${endpointHostname}, HTTP ${httpStatus}, Content-Type: ${contentType}`);
    return {
      status: 'error',
      message: `RDAP service returned HTTP error ${httpStatus}.`,
    };
  }

  // Response size guard: stream response up to 512KB (524288 bytes)
  let text: string;
  try {
    text = await readResponseBodyWithByteLimit(response, 524288, 'RDAP server');
  } catch (err: unknown) {
    if (err instanceof ResponseSizeLimitError) {
      console.error(`RDAP diagnostic classification [SIZE_LIMIT_EXCEEDED]: endpoint host ${endpointHostname}, ${err.message}`);
      return {
        status: 'error',
        message: 'RDAP response exceeded safety size limit.',
      };
    }
    console.error(`RDAP diagnostic classification [NETWORK_FAILURE]: endpoint host ${endpointHostname}`, err instanceof Error ? err.message : '');
    return {
      status: 'error',
      message: 'Unable to read RDAP response.',
    };
  }

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (err: unknown) {
    console.error(`RDAP diagnostic classification [MALFORMED_JSON]: endpoint host ${endpointHostname}, Content-Type: ${contentType}`, err instanceof Error ? err.message : '');
    return {
      status: 'error',
      message: 'Invalid RDAP JSON payload received.',
    };
  }

  if (!json || typeof json !== 'object') {
    console.error(`RDAP diagnostic classification [MALFORMED_JSON]: endpoint host ${endpointHostname}, Content-Type: ${contentType} (non-object JSON)`);
    return {
      status: 'error',
      message: 'Invalid RDAP JSON payload received.',
    };
  }

  // Extract registration and expiration events
  const events = Array.isArray((json as { events?: Array<{ eventAction?: string; eventDate?: string }> }).events) ? (json as { events?: Array<{ eventAction?: string; eventDate?: string }> }).events! : [];
  const regEvent = events.find((e) => e.eventAction === 'registration');
  const expEvent = events.find((e) => e.eventAction === 'expiration');

  const registrationDate: string | undefined = regEvent?.eventDate;
  const expirationDate: string | undefined = expEvent?.eventDate;

  // Extract registrar entity
  let registrar: string | undefined;
  const entities = Array.isArray((json as { entities?: Array<{ roles?: string[]; vcardArray?: unknown[]; handle?: string }> }).entities) ? (json as { entities?: Array<{ roles?: string[]; vcardArray?: unknown[]; handle?: string }> }).entities! : [];
  const registrarEntity = entities.find((ent) =>
    Array.isArray(ent.roles) && ent.roles.includes('registrar')
  );

  if (registrarEntity) {
    if (registrarEntity.vcardArray && Array.isArray(registrarEntity.vcardArray[1])) {
      const fnCard = (registrarEntity.vcardArray[1] as unknown[]).find((card: unknown) => Array.isArray(card) && card[0] === 'fn');
      if (fnCard && Array.isArray(fnCard) && typeof fnCard[3] === 'string') {
        registrar = fnCard[3];
      }
    }
    if (!registrar && typeof registrarEntity.handle === 'string') {
      registrar = registrarEntity.handle;
    }
  }

  let domainAgeDays: number | undefined;
  if (registrationDate) {
    const regTime = new Date(registrationDate).getTime();
    if (!isNaN(regTime)) {
      domainAgeDays = Math.max(0, Math.floor((Date.now() - regTime) / (1000 * 60 * 60 * 24)));
    }
  }

  if (!registrationDate) {
    const hasExplicitRedaction =
      Boolean((json as { redacted?: unknown }).redacted) ||
      (Array.isArray((json as { remarks?: Array<{ description?: string[] }> }).remarks) &&
        (json as { remarks?: Array<{ description?: string[] }> }).remarks!.some((r) =>
          Array.isArray(r.description) &&
          r.description.some((d) => /redacted|privacy|withheld|protected/i.test(d))
        )) ||
      (Array.isArray((json as { notices?: Array<{ description?: string[] }> }).notices) &&
        (json as { notices?: Array<{ description?: string[] }> }).notices!.some((n) =>
          Array.isArray(n.description) &&
          n.description.some((d) => /redacted|privacy|withheld|protected/i.test(d))
        ));

    if (hasExplicitRedaction) {
      console.error(`RDAP diagnostic classification [REDACTED]: endpoint host ${endpointHostname}, Content-Type: ${contentType} (explicit redaction indicators present)`);
      return {
        status: 'redacted',
        registrar,
        expirationDate,
        message: 'Registration date is explicitly redacted or withheld under registry privacy policy.',
      };
    } else {
      console.error(`RDAP diagnostic classification [UNAVAILABLE]: endpoint host ${endpointHostname}, Content-Type: ${contentType} (no registration date and no explicit redaction evidence)`);
      return {
        status: 'unavailable',
        registrar,
        expirationDate,
        message: 'Registration date could not be determined from the available response.',
      };
    }
  }

  return {
    status: 'available',
    registrationDate,
    expirationDate,
    domainAgeDays,
    registrar,
  };
}

/**
 * Generates human-readable, educational findings based on DNS and RDAP results.
 */
export function generateReconFindings(
  hostname: string,
  isIp: boolean,
  dns: DnsRecordsData,
  rdap: RdapRegistrationData
): ReconFinding[] {
  const findings: ReconFinding[] = [];

  if (isIp) {
    findings.push({
      id: 'recon-direct-ip',
      category: 'infrastructure',
      severity: 'neutral',
      title: 'Direct IP Host (Domain Lookup Not Applicable)',
      explanation:
        'Target destination is a direct numeric IP address. Domain registration and RDAP lookup are not applicable.',
    });
    return findings;
  }

  // 1. Domain Age Findings
  if (rdap.status === 'available' && typeof rdap.domainAgeDays === 'number') {
    if (rdap.domainAgeDays <= 30) {
      findings.push({
        id: 'recon-nrd',
        category: 'domain_age',
        severity: 'warning',
        title: 'Newly Registered Domain (NRD)',
        explanation: `Domain was registered ${rdap.domainAgeDays} day(s) ago (${new Date(rdap.registrationDate!).toLocaleDateString()}). Newly registered domains represent an elevated risk because phishing and fraud campaigns frequently spin up fresh domains. Note: this alone does not prove malicious intent.`,
      });
    } else {
      const years = (rdap.domainAgeDays / 365.25).toFixed(1);
      findings.push({
        id: 'recon-established-domain',
        category: 'domain_age',
        severity: 'neutral',
        title: 'Established Domain Age',
        explanation: `Domain was registered ${rdap.domainAgeDays} days ago (~${years} years ago). Well-established domains are historically less likely to be ephemeral phishing lures, but domain longevity does not guarantee safety.`,
      });
    }
  } else if (rdap.status === 'redacted') {
    findings.push({
      id: 'recon-rdap-redacted',
      category: 'notice',
      severity: 'neutral',
      title: 'Registration Date Explicitly Redacted',
      explanation:
        'Registration date is explicitly redacted or withheld by the registry under privacy policies. This is standard and does not indicate malicious intent.',
    });
  } else if (rdap.status === 'unavailable') {
    findings.push({
      id: 'recon-rdap-unavailable',
      category: 'notice',
      severity: 'neutral',
      title: 'Registration Date Unavailable',
      explanation:
        'Registration date could not be determined from the available RDAP response. This is common for certain TLDs and does not indicate malicious intent.',
    });
  } else if (rdap.status === 'unsupported') {
    findings.push({
      id: 'recon-rdap-unsupported',
      category: 'notice',
      severity: 'neutral',
      title: 'RDAP Information Unavailable for TLD',
      explanation:
        'The registry for this top-level domain does not operate a publicly queryable RDAP service. This is standard for several ccTLDs and is not a sign of risk.',
    });
  }

  // 2. DNS Resolution Findings
  if (dns.status === 'nxdomain' || dns.status === 'nodata') {
    findings.push({
      id: 'recon-dns-nxdomain',
      category: 'dns',
      severity: 'neutral',
      title: 'No Active DNS Records (NXDOMAIN / NODATA)',
      explanation:
        'Domain does not currently resolve to active A or AAAA IP addresses. The server infrastructure may be offline, parked, or decommissioned. Missing DNS records do not prove malicious intent.',
    });
  } else if (dns.status === 'resolved') {
    findings.push({
      id: 'recon-dns-resolved',
      category: 'dns',
      severity: 'info',
      title: 'Active DNS Resolution',
      explanation: `Domain resolves to ${dns.aCount} IPv4 endpoint(s) and ${dns.aaaaCount} IPv6 endpoint(s).`,
    });

    if (dns.hasMailExchange) {
      findings.push({
        id: 'recon-mx-present',
        category: 'dns',
        severity: 'info',
        title: 'Mail Exchange (MX) Configured',
        explanation: `Domain has ${dns.mxCount} configured mail exchange server(s), indicating active email service routing.`,
      });
    } else {
      findings.push({
        id: 'recon-mx-missing',
        category: 'dns',
        severity: 'neutral',
        title: 'No Mail Exchange (MX) Records',
        explanation:
          'No MX records were found for this domain. Many legitimate web-only services do not configure email routing; missing MX records do not indicate malicious intent.',
      });
    }
  }

  return findings;
}

/**
 * Primary reconnaissance coordinator.
 */
export async function performFullRecon(
  hostname: string,
  resolver: DnsResolverInterface = defaultDnsResolver,
  fetchFn: typeof fetch = fetch
): Promise<ReconResult> {
  const isIp = isIpv4(hostname) || isIpv6(hostname);
  const isSpecial = isSpecialUseHostname(hostname);

  if (isSpecial) {
    return {
      hostname,
      isIpAddress: isIp,
      isSpecialUse: true,
      dns: {
        status: 'skipped',
        aRecords: [],
        aaaaRecords: [],
        mxRecords: [],
        aCount: 0,
        aaaaCount: 0,
        mxCount: 0,
        hasMailExchange: false,
        message: 'Lookups skipped: destination is a special-use, loopback, or private address.',
      },
      rdap: {
        status: 'skipped',
        message: 'RDAP skipped for special-use or private destinations.',
      },
      findings: [
        {
          id: 'recon-special-use',
          category: 'infrastructure',
          severity: 'warning',
          title: 'Special-Use / Private Destination',
          explanation:
            'The requested destination is a local loopback, private network, or reserved address. External DNS and RDAP queries are prohibited.',
        },
      ],
      evaluatedAt: new Date().toISOString(),
    };
  }

  if (isIp) {
    // Direct IP address: DNS and RDAP are not applicable
    const dnsData: DnsRecordsData = {
      status: 'skipped',
      aRecords: [hostname],
      aaaaRecords: [],
      mxRecords: [],
      aCount: isIpv4(hostname) ? 1 : 0,
      aaaaCount: isIpv6(hostname) ? 1 : 0,
      mxCount: 0,
      hasMailExchange: false,
      message: 'Direct IP address destination. Hostname resolution skipped.',
    };

    const rdapData: RdapRegistrationData = {
      status: 'skipped',
      message: 'RDAP domain lookup not applicable for direct IP addresses.',
    };

    return {
      hostname,
      isIpAddress: true,
      isSpecialUse: false,
      dns: dnsData,
      rdap: rdapData,
      findings: generateReconFindings(hostname, true, dnsData, rdapData),
      evaluatedAt: new Date().toISOString(),
    };
  }

  // Domain lookup: Run DNS and RDAP concurrently
  const [dnsData, rdapData] = await Promise.all([
    performDnsRecon(hostname, resolver),
    performRdapLookup(hostname, fetchFn, resolver),
  ]);

  // SSRF guard on resolved IP addresses: Check if ANY resolved IP is private/loopback
  const allIps = [...dnsData.aRecords, ...dnsData.aaaaRecords];
  if (allIps.length > 0 && allIps.some((ip) => isSpecialUseIpv4(ip) || isSpecialUseIpv6(ip))) {
    const hasPublicIp = allIps.some((ip) => !isSpecialUseIpv4(ip) && !isSpecialUseIpv6(ip));
    return {
      hostname,
      isIpAddress: false,
      isSpecialUse: true,
      dns: {
        ...dnsData,
        message: hasPublicIp
          ? 'Domain resolves to mixed addresses including private or special-use endpoints (potential DNS rebinding).'
          : 'Domain resolves exclusively to private or special-use addresses.',
      },
      rdap: {
        status: 'skipped',
        message: 'RDAP skipped: domain points to private infrastructure.',
      },
      findings: [
        {
          id: 'recon-resolved-private',
          category: 'infrastructure',
          severity: 'warning',
          title: hasPublicIp ? 'Resolves to Restricted / Private Address (DNS Rebinding Risk)' : 'Resolves Exclusively to Private Addresses',
          explanation:
            'This domain resolves to internal loopback, private network, or special-use IP addresses. Outbound requests are blocked.',
        },
      ],
      evaluatedAt: new Date().toISOString(),
    };
  }

  return {
    hostname,
    isIpAddress: false,
    isSpecialUse: false,
    dns: dnsData,
    rdap: rdapData,
    findings: generateReconFindings(hostname, false, dnsData, rdapData),
    evaluatedAt: new Date().toISOString(),
  };
}
