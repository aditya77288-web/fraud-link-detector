import dnsPromises from 'node:dns/promises';
import {
  ReconResult,
  DnsRecordsData,
  RdapRegistrationData,
  ReconFinding,
} from '../types/recon.js';

// Trusted RDAP base endpoints allowlist
const TRUSTED_RDAP_BASE_URLS = [
  'https://rdap.org/domain/',
];

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
  // 0.0.0.0/8 - Current network
  if (a === 0) return true;
  // 224.0.0.0/4 - Multicast (224.0.0.0 - 239.255.255.255)
  if (a >= 224 && a <= 239) return true;
  // 240.0.0.0/4 - Reserved (240.0.0.0 - 255.255.255.255)
  if (a >= 240) return true;

  return false;
}

/**
 * Checks whether an IPv6 address is in a reserved, private, loopback, or IPv4-mapped range.
 */
export function isSpecialUseIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase().trim();

  // Loopback (::1) and Unspecified (::)
  if (normalized === '::1' || normalized === '::') return true;

  // IPv4-mapped IPv6: ::ffff:127.0.0.1 or ::ffff:7f00:1
  if (normalized.startsWith('::ffff:') || normalized.startsWith('0:0:0:0:0:ffff:')) {
    const v4Part = normalized.split(':').pop() || '';
    if (v4Part.includes('.')) {
      return isSpecialUseIpv4(v4Part);
    }
    // Hex IPv4 representation e.g. 7f000001
    return true;
  }

  // Unique Local Addresses (fc00::/7 - starts with fc or fd)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;

  // Link-local unicast (fe80::/10 - starts with fe8, fe9, fea, feb)
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

  if (lower === 'localhost') return true;
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

  // Direct IP checks
  if (isSpecialUseIpv4(lower)) return true;
  if (isSpecialUseIpv6(lower)) return true;

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

  // Check errors
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

/**
 * Queries RDAP for domain registration information.
 */
export async function performRdapLookup(
  domain: string,
  fetchFn: typeof fetch = fetch
): Promise<RdapRegistrationData> {
  // Validate domain format before constructing URL to prevent injection
  const trimmed = domain.trim().toLowerCase();
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(trimmed)) {
    return {
      status: 'unsupported',
      message: 'Domain format is not eligible for RDAP lookup.',
    };
  }

  // Construct request using trusted allowlist base
  const rdapEndpoint = `${TRUSTED_RDAP_BASE_URLS[0]}${encodeURIComponent(trimmed)}`;

  try {
    const response = await fetchFn(rdapEndpoint, {
      method: 'GET',
      headers: {
        Accept: 'application/rdap+json, application/json',
      },
      signal: AbortSignal.timeout(4000), // 4-second timeout
    });

    if (response.status === 404 || response.status === 501) {
      return {
        status: 'unsupported',
        message: 'RDAP information is not supported or not available for this TLD.',
      };
    }

    if (!response.ok) {
      return {
        status: 'error',
        message: `RDAP service returned status ${response.status}.`,
      };
    }

    // Response size guard: check Content-Length if present (> 512KB rejected)
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > 524288) {
      return {
        status: 'error',
        message: 'RDAP response exceeded safety size limit.',
      };
    }

    const json = await response.json();
    if (!json || typeof json !== 'object') {
      return {
        status: 'error',
        message: 'Invalid RDAP JSON payload received.',
      };
    }

    // Extract registration and expiration events
    const events = Array.isArray(json.events) ? json.events : [];
    const regEvent = events.find((e: { eventAction?: string }) => e.eventAction === 'registration');
    const expEvent = events.find((e: { eventAction?: string }) => e.eventAction === 'expiration');

    const registrationDate: string | undefined = regEvent?.eventDate;
    const expirationDate: string | undefined = expEvent?.eventDate;

    // Extract registrar entity
    let registrar: string | undefined;
    const entities = Array.isArray(json.entities) ? json.entities : [];
    const registrarEntity = entities.find((ent: { roles?: string[] }) =>
      Array.isArray(ent.roles) && ent.roles.includes('registrar')
    );

    if (registrarEntity) {
      if (registrarEntity.vcardArray && Array.isArray(registrarEntity.vcardArray[1])) {
        const fnCard = registrarEntity.vcardArray[1].find((card: unknown[]) => card[0] === 'fn');
        if (fnCard && typeof fnCard[3] === 'string') {
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
      return {
        status: 'redacted',
        registrar,
        expirationDate,
        message: 'Registration date is not published by registry or is redacted for privacy.',
      };
    }

    return {
      status: 'available',
      registrationDate,
      expirationDate,
      domainAgeDays,
      registrar,
    };
  } catch (err: unknown) {
    const isTimeout =
      err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
    return {
      status: isTimeout ? 'timeout' : 'error',
      message: isTimeout
        ? 'RDAP lookup timed out after 4 seconds.'
        : 'Unable to connect to RDAP service.',
    };
  }
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
      title: 'Registration Date Redacted',
      explanation:
        'Registration dates are not published or are withheld under registry privacy policies. This is common and does not indicate malicious intent.',
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
    performRdapLookup(hostname, fetchFn),
  ]);

  // SSRF guard on resolved IP addresses: Check if resolved IPs are all private/loopback
  const allIps = [...dnsData.aRecords, ...dnsData.aaaaRecords];
  if (allIps.length > 0 && allIps.every((ip) => isSpecialUseIpv4(ip) || isSpecialUseIpv6(ip))) {
    return {
      hostname,
      isIpAddress: false,
      isSpecialUse: true,
      dns: {
        ...dnsData,
        message: 'Domain resolves exclusively to private or special-use addresses.',
      },
      rdap: {
        status: 'skipped',
        message: 'RDAP skipped: domain points exclusively to private infrastructure.',
      },
      findings: [
        {
          id: 'recon-resolved-private',
          category: 'infrastructure',
          severity: 'warning',
          title: 'Resolves Exclusively to Private Addresses',
          explanation:
            'This domain resolves exclusively to internal loopback or RFC 1918 private IP addresses. Outbound requests are blocked.',
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
