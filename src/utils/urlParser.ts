/**
 * Safe client-side URL parsing utilities for Fraud Link Detector.
 * Performs zero network requests and does not transmit URL data.
 */

export interface ParsedUrlDetails {
  rawInput: string;
  normalizedUrl: string;
  isValid: boolean;
  errorMessage?: string;
  protocol: string;
  isHttps: boolean;
  hostname: string;
  port: string;
  explicitPort: string;
  isNonStandardPort: boolean;
  pathname: string;
  search: string;
  hash: string;
  paramCount: number;
  paramsList: Array<{ key: string; value: string }>;
  isIpAddress: boolean;
  isIpv4: boolean;
  isIpv6: boolean;
  username: string;
  password: string;
  hasAuthorityCredentials: boolean;
  hasAtSymbol: boolean; // Retained for compatibility, strictly checks authority credentials
  hasPunycode: boolean;
  subdomainCount: number;
  scannedAt: string;
}

/**
 * Checks whether a given host string is a valid IPv4 address.
 * Validates 4 decimal octets between 0 and 255 with no invalid leading zeros.
 */
export function isIpv4Address(host: string): boolean {
  if (!host) return false;
  const parts = host.split('.');
  if (parts.length !== 4) return false;

  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = Number(part);
    if (num < 0 || num > 255) return false;
    // Disallow leading zeros (e.g., "01" or "001")
    if (part.length > 1 && part.startsWith('0')) return false;
  }
  return true;
}

/**
 * Checks whether a given host string is an IPv6 address.
 */
export function isIpv6Address(host: string): boolean {
  if (!host) return false;
  return (host.startsWith('[') && host.endsWith(']')) || (host.includes(':') && !host.includes('.'));
}

/**
 * Checks whether a hostname contains any label beginning with 'xn--' (Punycode / IDN).
 */
export function hasPunycodeLabel(hostname: string): boolean {
  if (!hostname) return false;
  const labels = hostname.split('.');
  return labels.some((label) => label.toLowerCase().startsWith('xn--'));
}

/**
 * Normalizes user input by trimming whitespace and ensuring a protocol scheme is present.
 */
export function normalizeUrlString(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return '';

  // If no scheme is present, default to https:// for safe parsing
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    return `https://${trimmed}`;
  }
  return trimmed;
}

/**
 * Checks whether an input string can be parsed into a valid web URL.
 */
export function isValidUrl(input: string): boolean {
  if (!input || !input.trim()) return false;
  try {
    const normalized = normalizeUrlString(input);
    const parsed = new URL(normalized);
    // Ensure protocol is http or https and hostname exists
    return (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      parsed.hostname.length > 0
    );
  } catch {
    return false;
  }
}

/**
 * Parses and breaks down the structure of a URL completely client-side.
 */
export function parseUrl(input: string): ParsedUrlDetails | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  try {
    const normalized = normalizeUrlString(trimmed);
    const parsed = new URL(normalized);

    // Validate that protocol is http or https
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`Unsupported protocol scheme "${parsed.protocol}". Only HTTP and HTTPS are supported.`);
    }

    if (!parsed.hostname || parsed.hostname.length === 0) {
      throw new Error('No valid hostname could be parsed from the URL.');
    }

    const isHttps = parsed.protocol === 'https:';
    const hostname = parsed.hostname;

    // 1. IP Address Detection
    const isIpv4 = isIpv4Address(hostname);
    const isIpv6 = isIpv6Address(hostname);
    const isIpAddress = isIpv4 || isIpv6;

    // 2. URL Authority Credentials
    // In WHATWG URL, credentials embedded in authority (userinfo before @) populate username/password
    const username = parsed.username || '';
    const password = parsed.password || '';
    const hasAuthorityCredentials = Boolean(username || password);

    // 3. Port Detection
    // Default ports: 80 for HTTP, 443 for HTTPS.
    // When port matches default, WHATWG URL normalizes parsed.port to empty string.
    const defaultPort = isHttps ? '443' : '80';
    const explicitPort = parsed.port;
    const isNonStandardPort = Boolean(explicitPort && explicitPort !== defaultPort);
    const displayPort = explicitPort ? explicitPort : `${defaultPort} (default)`;

    // 4. Punycode Detection: Check if any label begins with 'xn--'
    const hasPunycode = hasPunycodeLabel(hostname);

    // 5. Subdomain calculation:
    // Only calculate subdomains for domain names. IP addresses have 0 subdomains!
    let subdomainCount = 0;
    if (!isIpAddress) {
      const parts = hostname.split('.');
      subdomainCount = parts.length > 2 ? parts.length - 2 : 0;
    }

    // Search parameters
    const paramsList: Array<{ key: string; value: string }> = [];
    parsed.searchParams.forEach((value, key) => {
      paramsList.push({ key, value });
    });

    const now = new Date();
    const formattedTime = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    return {
      rawInput: trimmed,
      normalizedUrl: parsed.href,
      isValid: true,
      protocol: parsed.protocol,
      isHttps,
      hostname,
      port: displayPort,
      explicitPort,
      isNonStandardPort,
      pathname: parsed.pathname || '/',
      search: parsed.search || '',
      hash: parsed.hash || '',
      paramCount: paramsList.length,
      paramsList,
      isIpAddress,
      isIpv4,
      isIpv6,
      username,
      password,
      hasAuthorityCredentials,
      hasAtSymbol: hasAuthorityCredentials,
      hasPunycode,
      subdomainCount,
      scannedAt: formattedTime,
    };
  } catch (err) {
    return {
      rawInput: trimmed,
      normalizedUrl: trimmed,
      isValid: false,
      errorMessage: err instanceof Error ? err.message : 'Invalid URL format',
      protocol: 'Unknown',
      isHttps: false,
      hostname: 'Unparseable',
      port: '',
      explicitPort: '',
      isNonStandardPort: false,
      pathname: '',
      search: '',
      hash: '',
      paramCount: 0,
      paramsList: [],
      isIpAddress: false,
      isIpv4: false,
      isIpv6: false,
      username: '',
      password: '',
      hasAuthorityCredentials: false,
      hasAtSymbol: false,
      hasPunycode: false,
      subdomainCount: 0,
      scannedAt: new Date().toLocaleTimeString(),
    };
  }
}
