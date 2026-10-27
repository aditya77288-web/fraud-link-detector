import http from 'node:http';
import https from 'node:https';
import {
  ChainInspectionStatus,
  ChainFinding,
  RedirectHop,
  RedirectChainResult,
} from '../types/redirect.js';
import {
  isSpecialUseIpv4,
  isSpecialUseIpv6,
  isSpecialUseHostname,
  isIpv4,
  isIpv6,
  DnsResolverInterface,
  defaultDnsResolver,
} from './dnsRecon.js';
import { redactSensitiveUrl } from '../utils/historyStorage.js';

export const MAX_HOPS = 5;
export const PER_HOP_TIMEOUT_MS = 2000;
export const OVERALL_TIMEOUT_MS = 6000;

export interface HopResponse {
  statusCode: number;
  statusText: string;
  headers: Record<string, string | string[] | undefined>;
  durationMs: number;
}

export type HttpRequester = (
  targetUrl: URL,
  pinnedIp: string,
  method: 'HEAD' | 'GET',
  timeoutMs: number
) => Promise<HopResponse>;

/**
 * Standard HTTP requester using Node.js http/https with IP connection pinning.
 * Pinned connection ensures that the socket dials the validated public IP directly,
 * preventing DNS rebinding/TOCTOU attacks.
 * Only headers are read; the response stream is destroyed immediately without buffering bodies.
 */
export const defaultHttpRequester: HttpRequester = (
  targetUrl: URL,
  pinnedIp: string,
  method: 'HEAD' | 'GET',
  timeoutMs: number
): Promise<HopResponse> => {
  return new Promise((resolve, reject) => {
    const isHttps = targetUrl.protocol === 'https:';
    const client = isHttps ? https : http;
    const isIpV6 = pinnedIp.includes(':');
    const family = isIpV6 ? 6 : 4;
    const port = targetUrl.port ? Number(targetUrl.port) : isHttps ? 443 : 80;

    const startTime = Date.now();
    let settled = false;

    const requestOptions: http.RequestOptions = {
      protocol: targetUrl.protocol,
      hostname: targetUrl.hostname,
      port,
      path: `${targetUrl.pathname || '/'}${targetUrl.search || ''}`,
      method,
      headers: {
        Host: targetUrl.host,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) FraudLinkDetector/1.0',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'identity',
        Connection: 'close',
      },
      // Connection Pinning: custom lookup bypasses OS resolver at connect time
      lookup: ((
        _hostname: string,
        optionsOrCallback: unknown,
        callback?: (err: NodeJS.ErrnoException | null, address: string | Array<{ address: string; family: number }>, family?: number) => void
      ) => {
        const cb = (
          typeof optionsOrCallback === 'function' ? optionsOrCallback : callback
        ) as ((err: NodeJS.ErrnoException | null, address: string | Array<{ address: string; family: number }>, family?: number) => void) | undefined;
        if (!cb) return;

        const opts = typeof optionsOrCallback === 'object' && optionsOrCallback ? optionsOrCallback : {};
        if ((opts as { all?: boolean }).all) {
          cb(null, [{ address: pinnedIp, family }]);
        } else {
          cb(null, pinnedIp, family);
        }
      }) as unknown as http.RequestOptions['lookup'],
      timeout: timeoutMs,
    };

    if (isHttps) {
      (requestOptions as https.RequestOptions).servername = targetUrl.hostname;
    }

    const req = client.request(requestOptions, (res) => {
      const durationMs = Date.now() - startTime;
      const statusCode = res.statusCode || 0;
      const statusText = res.statusMessage || '';
      const headers = res.headers;

      // Discard and destroy response stream immediately - never buffer bodies
      res.resume();
      req.destroy();

      if (!settled) {
        settled = true;
        resolve({
          statusCode,
          statusText,
          headers,
          durationMs,
        });
      }
    });

    req.on('timeout', () => {
      req.destroy(new Error('HOP_TIMEOUT'));
    });

    req.on('error', (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });

    req.end();
  });
};

/**
 * Removes embedded basic auth credentials from a URL string before processing.
 */
export function stripCredentials(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    parsed.username = '';
    parsed.password = '';
    return parsed.toString();
  } catch {
    return rawUrl;
  }
}

/**
 * Resolves a hostname to IP addresses and checks every address against special-use IP ranges.
 * Returns the first safe public IP for connection pinning, or null if special-use/unresolvable.
 */
export async function resolveAndValidateHost(
  hostname: string,
  dnsResolver: DnsResolverInterface = defaultDnsResolver
): Promise<{ safe: boolean; pinnedIp: string | null; errorReason?: string }> {
  const normalizedHost = hostname.toLowerCase().trim();
  const unbracketedHost = normalizedHost.replace(/^\[|\]$/g, '');

  // 1. Check special-use hostnames (localhost, .local, .internal, etc.)
  if (isSpecialUseHostname(normalizedHost) || isSpecialUseHostname(unbracketedHost)) {
    return {
      safe: false,
      pinnedIp: null,
      errorReason: `Target host "${normalizedHost}" is a restricted local or special-use domain.`,
    };
  }

  // 2. Direct IPv4
  if (isIpv4(unbracketedHost)) {
    if (isSpecialUseIpv4(unbracketedHost)) {
      return {
        safe: false,
        pinnedIp: null,
        errorReason: `Destination IP address ${unbracketedHost} is in a private, loopback, or link-local range.`,
      };
    }
    return { safe: true, pinnedIp: unbracketedHost };
  }

  // 3. Direct IPv6
  if (isIpv6(unbracketedHost)) {
    if (isSpecialUseIpv6(unbracketedHost)) {
      return {
        safe: false,
        pinnedIp: null,
        errorReason: `Destination IPv6 address ${unbracketedHost} is in a private or loopback range.`,
      };
    }
    return { safe: true, pinnedIp: unbracketedHost };
  }

  // 4. Domain name DNS resolution
  let resolvedAddresses: string[] = [];
  try {
    const [v4Results, v6Results] = await Promise.allSettled([
      dnsResolver.resolve4(normalizedHost),
      dnsResolver.resolve6(normalizedHost),
    ]);

    if (v4Results.status === 'fulfilled' && Array.isArray(v4Results.value)) {
      resolvedAddresses.push(...v4Results.value);
    }
    if (v6Results.status === 'fulfilled' && Array.isArray(v6Results.value)) {
      resolvedAddresses.push(...v6Results.value);
    }
  } catch {
    // Handled below if empty
  }

  if (resolvedAddresses.length === 0) {
    return {
      safe: false,
      pinnedIp: null,
      errorReason: `Could not resolve IP addresses for host "${normalizedHost}".`,
    };
  }

  // Check EVERY resolved address against SSRF ranges
  for (const ip of resolvedAddresses) {
    if (isSpecialUseIpv4(ip) || isSpecialUseIpv6(ip)) {
      return {
        safe: false,
        pinnedIp: null,
        errorReason: `Host "${normalizedHost}" resolves to restricted special-use IP (${ip}).`,
      };
    }
  }

  // Pin connection to the first verified public address
  return {
    safe: true,
    pinnedIp: resolvedAddresses[0],
  };
}

/**
 * Known URL shortener domains for chain analysis findings.
 */
const KNOWN_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'cutt.ly',
  'rb.gy',
  'shorturl.at',
]);

/**
 * Inspects HTTP redirect chain for a validated URL with strict security controls.
 */
export async function inspectRedirectChain(
  initialInputUrl: string,
  options?: {
    dnsResolver?: DnsResolverInterface;
    httpRequester?: HttpRequester;
    maxHops?: number;
    perHopTimeoutMs?: number;
    overallTimeoutMs?: number;
  }
): Promise<RedirectChainResult> {
  const dnsResolver = options?.dnsResolver || defaultDnsResolver;
  const httpRequester = options?.httpRequester || defaultHttpRequester;
  const maxHops = options?.maxHops ?? MAX_HOPS;
  const hopTimeout = options?.perHopTimeoutMs ?? PER_HOP_TIMEOUT_MS;
  const overallTimeout = options?.overallTimeoutMs ?? OVERALL_TIMEOUT_MS;

  const inspectedAt = new Date().toISOString();
  const startTime = Date.now();

  const cleanedInitial = stripCredentials(initialInputUrl.trim());
  const sanitizedInitial = redactSensitiveUrl(cleanedInitial);

  // Validate initial URL format
  let currentUrlObj: URL;
  try {
    currentUrlObj = new URL(cleanedInitial);
    if (currentUrlObj.protocol !== 'http:' && currentUrlObj.protocol !== 'https:') {
      return {
        initialUrl: sanitizedInitial,
        finalDestination: sanitizedInitial,
        totalRedirects: 0,
        status: 'UNSUPPORTED_PROTOCOL',
        statusMessage: `Protocol "${currentUrlObj.protocol}" is not supported. Only HTTP and HTTPS are permitted.`,
        hops: [],
        findings: [],
        inspectedAt,
      };
    }
  } catch {
    return {
      initialUrl: sanitizedInitial,
      finalDestination: sanitizedInitial,
      totalRedirects: 0,
      status: 'NETWORK_ERROR',
      statusMessage: 'Invalid URL structure provided for redirect inspection.',
      hops: [],
      findings: [],
      inspectedAt,
    };
  }

  const hops: RedirectHop[] = [];
  const findings: ChainFinding[] = [];
  const visitedUrls = new Set<string>();

  let status: ChainInspectionStatus = 'COMPLETED';
  let statusMessage = 'Redirect chain inspected successfully.';
  let currentRawUrl = cleanedInitial;
  let hopIndex = 0;

  while (hopIndex <= maxHops) {
    // Check overall timeout
    if (Date.now() - startTime >= overallTimeout) {
      status = 'TIMEOUT';
      statusMessage = `Inspection timed out after exceeding ${overallTimeout / 1000} seconds overall.`;
      break;
    }

    const currentSanitizedUrl = redactSensitiveUrl(currentRawUrl);
    visitedUrls.add(currentRawUrl);

    // Validate and resolve host to a pinned public IP
    const hostValidation = await resolveAndValidateHost(currentUrlObj.hostname, dnsResolver);

    if (!hostValidation.safe || !hostValidation.pinnedIp) {
      status = 'BLOCKED_SPECIAL_USE_IP';
      statusMessage = hostValidation.errorReason || 'Destination host points to a restricted IP address.';
      
      hops.push({
        hopIndex: hopIndex + 1,
        url: currentSanitizedUrl,
        statusCode: 0,
        statusText: 'Blocked (Restricted Destination)',
        locationHeader: null,
        resolvedIp: null,
        isHttps: currentUrlObj.protocol === 'https:',
        serverHeader: null,
        durationMs: 0,
      });

      findings.push({
        id: `blocked-ip-${hopIndex}`,
        severity: 'critical',
        title: 'Restricted Address Blocked',
        description: statusMessage,
      });
      break;
    }

    const pinnedIp = hostValidation.pinnedIp;

    // Issue request to pinned IP (HEAD first, fallback to GET if 405)
    let hopRes: HopResponse;
    try {
      try {
        hopRes = await httpRequester(currentUrlObj, pinnedIp, 'HEAD', hopTimeout);
        if (hopRes.statusCode === 405) {
          hopRes = await httpRequester(currentUrlObj, pinnedIp, 'GET', hopTimeout);
        }
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        if (errorMsg.includes('HOP_TIMEOUT')) {
          status = 'TIMEOUT';
          statusMessage = `Hop ${hopIndex + 1} timed out after ${hopTimeout / 1000} seconds.`;
        } else {
          status = 'NETWORK_ERROR';
          statusMessage = `Network error connecting to destination host: ${errorMsg}`;
        }

        hops.push({
          hopIndex: hopIndex + 1,
          url: currentSanitizedUrl,
          statusCode: 0,
          statusText: status === 'TIMEOUT' ? 'Timeout' : 'Network Error',
          locationHeader: null,
          resolvedIp: pinnedIp,
          isHttps: currentUrlObj.protocol === 'https:',
          serverHeader: null,
          durationMs: Date.now() - startTime,
        });
        break;
      }
    } catch {
      status = 'NETWORK_ERROR';
      statusMessage = 'Uncaught error during hop execution.';
      break;
    }

    const isRedirect = [301, 302, 303, 307, 308].includes(hopRes.statusCode);
    const rawLocation = hopRes.headers['location'];
    const locationStr = Array.isArray(rawLocation) ? rawLocation[0] : rawLocation;
    const serverHeader = Array.isArray(hopRes.headers['server'])
      ? hopRes.headers['server'][0]
      : hopRes.headers['server'] || null;

    hops.push({
      hopIndex: hopIndex + 1,
      url: currentSanitizedUrl,
      statusCode: hopRes.statusCode,
      statusText: hopRes.statusText,
      locationHeader: locationStr ? redactSensitiveUrl(locationStr) : null,
      resolvedIp: pinnedIp,
      isHttps: currentUrlObj.protocol === 'https:',
      serverHeader,
      durationMs: hopRes.durationMs,
    });

    // Check if this hop used a known URL shortener
    if (KNOWN_SHORTENERS.has(currentUrlObj.hostname.toLowerCase())) {
      findings.push({
        id: `shortener-${hopIndex}`,
        severity: 'info',
        title: 'URL Shortener Detected',
        description: `Hop ${hopIndex + 1} uses known link shortener service (${currentUrlObj.hostname}).`,
      });
    }

    // If not a redirect, we reached our final destination
    if (!isRedirect || !locationStr) {
      status = 'COMPLETED';
      statusMessage = hops.length === 1
        ? 'No redirects found. Direct terminal destination reached.'
        : `Chain completed across ${hops.length - 1} redirect(s).`;
      break;
    }

    // If it is a redirect, we need to inspect the next hop
    hopIndex += 1;

    if (hopIndex > maxHops) {
      status = 'MAX_HOPS_EXCEEDED';
      statusMessage = `Redirect limit exceeded (${maxHops} hops maximum allowed).`;
      findings.push({
        id: 'max-hops-exceeded',
        severity: 'warning',
        title: 'Maximum Hops Exceeded',
        description: `The redirect chain was stopped after ${maxHops} redirects to prevent resource exhaustion.`,
      });
      break;
    }

    // Resolve Location header (supports relative paths like /login or ?query)
    let nextUrlObj: URL;
    try {
      nextUrlObj = new URL(locationStr, currentUrlObj.toString());
    } catch {
      status = 'NETWORK_ERROR';
      statusMessage = `Invalid Location header returned at hop ${hopIndex}: "${locationStr}".`;
      break;
    }

    // Strip credentials from resolved target
    nextUrlObj.username = '';
    nextUrlObj.password = '';

    // Verify next protocol
    if (nextUrlObj.protocol !== 'http:' && nextUrlObj.protocol !== 'https:') {
      status = 'UNSUPPORTED_PROTOCOL';
      statusMessage = `Redirect destination specifies unsupported protocol: "${nextUrlObj.protocol}".`;
      findings.push({
        id: `unsupported-protocol-${hopIndex}`,
        severity: 'critical',
        title: 'Dangerous Protocol Redirect',
        description: `Redirect attempted to navigate to unsupported protocol "${nextUrlObj.protocol}".`,
      });
      break;
    }

    // Check for HTTPS -> HTTP downgrade
    if (currentUrlObj.protocol === 'https:' && nextUrlObj.protocol === 'http:') {
      findings.push({
        id: `https-downgrade-${hopIndex}`,
        severity: 'critical',
        title: 'HTTPS-to-HTTP Protocol Downgrade',
        description: `Hop ${hopIndex} downgraded security from encrypted HTTPS to unencrypted HTTP (${nextUrlObj.hostname}).`,
      });
    }

    // Check for domain change
    if (currentUrlObj.hostname.toLowerCase() !== nextUrlObj.hostname.toLowerCase()) {
      findings.push({
        id: `domain-change-${hopIndex}`,
        severity: 'info',
        title: 'Domain Transition',
        description: `Redirect transferred from ${currentUrlObj.hostname} to ${nextUrlObj.hostname}.`,
      });
    }

    // Check for redirect loop
    const nextRawUrl = nextUrlObj.toString();
    if (visitedUrls.has(nextRawUrl)) {
      status = 'REDIRECT_LOOP';
      statusMessage = `Redirect loop detected at hop ${hopIndex + 1}. URL has already been visited.`;
      findings.push({
        id: `loop-detected-${hopIndex}`,
        severity: 'warning',
        title: 'Redirect Loop Detected',
        description: `The chain repeatedly cycles back to "${redactSensitiveUrl(nextRawUrl)}".`,
      });
      break;
    }

    currentRawUrl = nextRawUrl;
    currentUrlObj = nextUrlObj;
  }

  const lastHop = hops[hops.length - 1];
  const finalDestination = lastHop ? lastHop.url : sanitizedInitial;
  const totalRedirects = Math.max(0, hops.length - 1);

  return {
    initialUrl: sanitizedInitial,
    finalDestination,
    totalRedirects,
    status,
    statusMessage,
    hops,
    findings,
    inspectedAt,
  };
}
