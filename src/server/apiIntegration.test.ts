import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp } from './app.js';
import { DnsResolverInterface } from './dnsRecon.js';
import { HttpRequester, HopResponse } from './redirectInspector.js';
import { FetchFunction, ScreenshotHostResolver } from './screenshotService.js';

// Valid 1x1 JPEG pixel with valid magic bytes (FF D8 FF E0 00 10 4A 46 49 46)
const VALID_JPEG_BUFFER = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46]);

// Mock state controllers for deterministic integration tests
let mockSafeBrowsingFetch: typeof fetch | undefined;
let mockReconResolver: DnsResolverInterface | undefined;
let mockReconFetch: typeof fetch | undefined;
let mockRedirectResolver: DnsResolverInterface | undefined;
let mockRedirectRequester: HttpRequester | undefined;
let mockScreenshotFetch: FetchFunction | undefined;
let mockScreenshotResolver: ScreenshotHostResolver | undefined;

// Dynamic delegating options passed into createApp()
const appOptions = {
  safeBrowsingFetch: async (input: RequestInfo | URL, init?: RequestInit) => {
    if (mockSafeBrowsingFetch) return mockSafeBrowsingFetch(input, init);
    throw new Error(`Unexpected unmocked Safe Browsing fetch call to ${String(input)}`);
  },
  reconResolver: {
    resolve4: async (h: string) => {
      if (!mockReconResolver) throw new Error(`Unexpected unmocked Recon DNS resolve4 call for ${h}`);
      return mockReconResolver.resolve4(h);
    },
    resolve6: async (h: string) => {
      if (!mockReconResolver) throw new Error(`Unexpected unmocked Recon DNS resolve6 call for ${h}`);
      return mockReconResolver.resolve6(h);
    },
    resolveMx: async (h: string) => {
      if (!mockReconResolver) throw new Error(`Unexpected unmocked Recon DNS resolveMx call for ${h}`);
      return mockReconResolver.resolveMx(h);
    },
  },
  reconFetch: async (input: RequestInfo | URL, init?: RequestInit) => {
    if (mockReconFetch) return mockReconFetch(input, init);
    throw new Error(`Unexpected unmocked Recon fetch call to ${String(input)}`);
  },
  redirectResolver: {
    resolve4: async (h: string) => {
      if (!mockRedirectResolver) throw new Error(`Unexpected unmocked Redirect DNS resolve4 call for ${h}`);
      return mockRedirectResolver.resolve4(h);
    },
    resolve6: async (h: string) => {
      if (!mockRedirectResolver) throw new Error(`Unexpected unmocked Redirect DNS resolve6 call for ${h}`);
      return mockRedirectResolver.resolve6(h);
    },
    resolveMx: async (h: string) => {
      if (!mockRedirectResolver) throw new Error(`Unexpected unmocked Redirect DNS resolveMx call for ${h}`);
      return mockRedirectResolver.resolveMx(h);
    },
  },
  redirectRequester: async (targetUrl: URL, pinnedIp: string, method: 'HEAD' | 'GET', timeoutMs: number) => {
    if (mockRedirectRequester) return mockRedirectRequester(targetUrl, pinnedIp, method, timeoutMs);
    throw new Error(`Unexpected unmocked Redirect requester call to ${targetUrl.href}`);
  },
  screenshotFetch: async (input: string | URL | Request, init?: RequestInit) => {
    if (mockScreenshotFetch) return mockScreenshotFetch(input, init);
    throw new Error(`Unexpected unmocked Screenshot fetch call to ${String(input)}`);
  },
  screenshotResolver: async (hostname: string) => {
    if (mockScreenshotResolver) return mockScreenshotResolver(hostname);
    throw new Error(`Unexpected unmocked Screenshot DNS resolution for ${hostname}`);
  },
  disableRateLimiting: true,
};

let server: http.Server;
let baseUrl: string;

before(async () => {
  const app = createApp(appOptions);
  server = http.createServer(app);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const addr = server.address() as { port: number };
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

after(() => {
  if (server) {
    server.close();
  }
});


// Explicit public DNS fixture: tests that need outbound-path simulation must opt in.
function publicDnsResolver(): DnsResolverInterface {
  return {
    resolve4: async () => ['93.184.215.14'],
    resolve6: async () => [],
    resolveMx: async () => [],
  };
}

// Helper for standard JSON POST requests
async function postJson(endpoint: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(`${baseUrl}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  return { status: res.status, headers: res.headers, data };
}

// Helper for raw POST requests (e.g. malformed JSON strings)
async function postRaw(endpoint: string, rawBody: string, headers: Record<string, string> = {}) {
  const res = await fetch(`${baseUrl}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: rawBody,
  });
  const data = await res.json();
  return { status: res.status, headers: res.headers, data };
}

// ============================================================================
// 1. POST /api/threat-check Integration Tests
// ============================================================================

test('POST /api/threat-check: Valid public URL - Clean domain returns isThreat false', async () => {
  const originalKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  process.env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-mock-key';

  mockSafeBrowsingFetch = async (url) => {
    assert.ok(String(url).includes('urls[]=') && String(url).includes('clean-example.com'));
    assert.ok(String(url).includes('key=test-mock-key'));
    return new Response(JSON.stringify({ threats: [], cacheDuration: '3600s' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  try {
    const res = await postJson('/api/threat-check', { url: 'https://clean-example.com/login' });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.data.configured, true);
    assert.equal(res.data.checked, true);
    assert.equal(res.data.isThreat, false);
    assert.deepEqual(res.data.threatTypes, []);
    assert.equal(res.data.cacheDuration, '3600s');
  } finally {
    process.env.GOOGLE_SAFE_BROWSING_API_KEY = originalKey;
    mockSafeBrowsingFetch = undefined;
  }
});

test('POST /api/threat-check: Valid public URL - Confirmed malicious threat returns isThreat true', async () => {
  const originalKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  process.env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-mock-key';

  mockSafeBrowsingFetch = async () => {
    return new Response(
      JSON.stringify({
        threats: [{ url: 'https://malicious-phish.net/', threatTypes: ['SOCIAL_ENGINEERING'] }],
        cacheDuration: '300s',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };

  try {
    const res = await postJson('/api/threat-check', { url: 'https://malicious-phish.net/' });
    assert.equal(res.status, 200);
    assert.equal(res.data.configured, true);
    assert.equal(res.data.checked, true);
    assert.equal(res.data.isThreat, true);
    assert.deepEqual(res.data.threatTypes, ['SOCIAL_ENGINEERING']);
  } finally {
    process.env.GOOGLE_SAFE_BROWSING_API_KEY = originalKey;
    mockSafeBrowsingFetch = undefined;
  }
});

test('POST /api/threat-check: Unconfigured API key returns configured false without erroring', async () => {
  const originalKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  try {
    const res = await postJson('/api/threat-check', { url: 'https://example.com' });
    assert.equal(res.status, 200);
    assert.equal(res.data.configured, false);
    assert.equal(res.data.status, 'unconfigured');
    assert.ok(res.data.message?.includes('not configured'));
  } finally {
    process.env.GOOGLE_SAFE_BROWSING_API_KEY = originalKey;
  }
});

test('POST /api/threat-check: Rejects invalid URL schemes (javascript:, ftp:, file:)', async () => {
  const schemes = [
    'javascript:alert(document.cookie)',
    'ftp://files.example.com/malware.exe',
    'file:///etc/passwd',
    'data:text/html,<b>pwned</b>',
  ];

  for (const badScheme of schemes) {
    const res = await postJson('/api/threat-check', { url: badScheme });
    assert.equal(res.status, 400);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.ok(res.data.error?.includes('protocol') || res.data.error?.includes('Invalid'));
  }
});

test('POST /api/threat-check: Rejects malformed JSON syntax with HTTP 400 and no-store', async () => {
  const res = await postRaw('/api/threat-check', '{"url": "https://example.com" invalid syntax');
  assert.equal(res.status, 400);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.data.error, 'Malformed JSON payload.');
});

test('POST /api/threat-check: Rejects missing URL fields (empty object, empty string, non-string)', async () => {
  // Empty object
  const r1 = await postJson('/api/threat-check', {});
  assert.equal(r1.status, 400);
  assert.ok(r1.data.error?.includes('required'));

  // Empty string
  const r2 = await postJson('/api/threat-check', { url: '' });
  assert.equal(r2.status, 400);
  assert.ok(r2.data.error?.includes('empty'));

  // Non-string
  const r3 = await postJson('/api/threat-check', { url: 12345 });
  assert.equal(r3.status, 400);
  assert.ok(r3.data.error?.includes('valid string'));

  // Missing field with other keys
  const r4 = await postJson('/api/threat-check', { target: 'https://example.com' });
  assert.equal(r4.status, 400);
  assert.ok(r4.data.error?.includes('required'));
});

test('POST /api/threat-check: Rejects URLs exceeding 2048 characters with HTTP 400', async () => {
  const oversized = 'https://example.com/query?' + 'x'.repeat(2048);
  const res = await postJson('/api/threat-check', { url: oversized });
  assert.equal(res.status, 400);
  assert.ok(res.data.error?.includes('2048'));
});

test('POST /api/threat-check: External service failure (HTTP 500/502/403/400) returns 502 without leaking secrets', async () => {
  const originalKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  process.env.GOOGLE_SAFE_BROWSING_API_KEY = 'super-secret-key-xyz';

  mockSafeBrowsingFetch = async () => {
    return new Response(
      JSON.stringify({ error: { code: 500, message: 'Internal upstream Google error with key super-secret-key-xyz' } }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  };

  try {
    const res = await postJson('/api/threat-check', { url: 'https://secret-domain.org/path' });
    assert.equal(res.status, 502);
    assert.equal(res.data.configured, true);
    assert.equal(res.data.checked, false);
    assert.equal(res.data.error, 'Threat intelligence service is temporarily unavailable.');
    assert.ok(!JSON.stringify(res.data).includes('super-secret-key-xyz'));
    assert.ok(!JSON.stringify(res.data).includes('secret-domain.org'));
  } finally {
    process.env.GOOGLE_SAFE_BROWSING_API_KEY = originalKey;
    mockSafeBrowsingFetch = undefined;
  }
});

test('POST /api/threat-check: Upstream timeout scenario returns 504 with generic error', async () => {
  const originalKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  process.env.GOOGLE_SAFE_BROWSING_API_KEY = 'test-key';

  mockSafeBrowsingFetch = async () => {
    const err = new Error('The operation was aborted');
    err.name = 'TimeoutError';
    throw err;
  };

  try {
    const res = await postJson('/api/threat-check', { url: 'https://example.com' });
    assert.equal(res.status, 504);
    assert.equal(res.data.configured, true);
    assert.equal(res.data.checked, false);
    assert.ok(res.data.error?.includes('timed out'));
  } finally {
    process.env.GOOGLE_SAFE_BROWSING_API_KEY = originalKey;
    mockSafeBrowsingFetch = undefined;
  }
});

// ============================================================================
// 2. POST /api/recon Integration Tests
// ============================================================================

test('POST /api/recon: Valid public URL - Established domain returns full DNS, RDAP, and findings', async () => {
  mockReconResolver = {
    resolve4: async () => ['93.184.215.14'],
    resolve6: async () => ['2606:2800:220:1:248:1893:25c8:1946'],
    resolveMx: async () => [{ exchange: 'mail.example.com', priority: 10 }],
  };

  mockReconFetch = async (url) => {
    const urlStr = String(url);
    if (urlStr.includes('iana.org')) {
      return new Response(JSON.stringify({
        version: '1.0',
        publication: '2026-01-01',
        services: [[['com'], ['https://rdap.verisign.com/com/v1/']]],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(JSON.stringify({
      events: [{ eventAction: 'registration', eventDate: '2010-03-15T00:00:00Z' }],
      entities: [{ roles: ['registrar'], handle: 'Verisign Inc' }],
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };

  try {
    const res = await postJson('/api/recon', { url: 'https://example.com/about' });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal(res.data.hostname, 'example.com');
    assert.equal(res.data.isIpAddress, false);
    assert.equal(res.data.isSpecialUse, false);
    assert.equal(res.data.dns.status, 'resolved');
    assert.equal(res.data.dns.aCount, 1);
    assert.equal(res.data.dns.aaaaCount, 1);
    assert.equal(res.data.dns.hasMailExchange, true);
    assert.equal(res.data.rdap.status, 'available');
    assert.equal(res.data.rdap.registrationDate, '2010-03-15T00:00:00Z');
    assert.ok(Array.isArray(res.data.findings));
    assert.ok(res.data.findings.some((f: { id: string }) => f.id === 'recon-established-domain'));
  } finally {
    mockReconResolver = undefined;
    mockReconFetch = undefined;
  }
});

test('POST /api/recon: Valid public URL - Direct numeric IP host skips DNS/RDAP and marks direct IP', async () => {
  const res = await postJson('/api/recon', { url: 'http://93.184.215.14:8080/login' });
  assert.equal(res.status, 200);
  assert.equal(res.data.isIpAddress, true);
  assert.equal(res.data.hostname, '93.184.215.14');
  assert.equal(res.data.dns.status, 'skipped');
  assert.equal(res.data.rdap.status, 'skipped');
  assert.ok(res.data.findings.some((f: { id: string }) => f.id === 'recon-direct-ip'));
});

test('POST /api/recon: Rejects invalid URL schemes (javascript:, ftp:, file:)', async () => {
  const schemes = ['javascript:alert(1)', 'ftp://ftp.example.com', 'file:///etc/hosts'];
  for (const s of schemes) {
    const res = await postJson('/api/recon', { url: s });
    assert.equal(res.status, 400);
    assert.equal(res.headers.get('cache-control'), 'no-store');
  }
});

test('POST /api/recon: Rejects malformed JSON syntax with HTTP 400', async () => {
  const res = await postRaw('/api/recon', '{ "url": broken');
  assert.equal(res.status, 400);
  assert.equal(res.data.error, 'Malformed JSON payload.');
});

test('POST /api/recon: Rejects missing URL fields (empty object, empty string)', async () => {
  const r1 = await postJson('/api/recon', {});
  assert.equal(r1.status, 400);

  const r2 = await postJson('/api/recon', { url: '' });
  assert.equal(r2.status, 400);
});

test('POST /api/recon SSRF Protection: Loopback and private destinations marked special-use and skipped', async () => {
  const destinations = [
    'http://127.0.0.1:8080/admin',
    'http://localhost:3000',
    'http://10.0.0.1/status',
    'http://192.168.1.1/setup',
    'http://169.254.169.254/latest/meta-data',
    'http://[::1]:8080/test',
  ];

  for (const dest of destinations) {
    const res = await postJson('/api/recon', { url: dest });
    assert.equal(res.status, 200);
    assert.equal(res.data.isSpecialUse, true);
    assert.equal(res.data.dns.status, 'skipped');
    assert.equal(res.data.rdap.status, 'skipped');
    assert.ok(res.data.findings.some((f: { id: string }) => f.id === 'recon-special-use'));
  }
});

test('POST /api/recon SSRF Protection: Hostname resolving to private IP triggers DNS rebinding block', async () => {
  mockReconResolver = {
    resolve4: async () => ['127.0.0.1'],
    resolve6: async () => [],
    resolveMx: async () => [],
  };

  try {
    const res = await postJson('/api/recon', { url: 'https://rebind-attacker.org/login' });
    assert.equal(res.status, 200);
    assert.equal(res.data.isSpecialUse, true);
    assert.equal(res.data.rdap.status, 'skipped');
    assert.ok(res.data.findings.some((f: { id: string }) => f.id === 'recon-resolved-private'));
  } finally {
    mockReconResolver = undefined;
  }
});

test('POST /api/recon: DNS failure (NXDOMAIN / NODATA) handled safely', async () => {
  mockReconResolver = {
    resolve4: async () => {
      const err = new Error('getaddrinfo ENOTFOUND non-existent.org');
      (err as unknown as { code: string }).code = 'ENOTFOUND';
      throw err;
    },
    resolve6: async () => {
      const err = new Error('getaddrinfo ENOTFOUND non-existent.org');
      (err as unknown as { code: string }).code = 'ENOTFOUND';
      throw err;
    },
    resolveMx: async () => [],
  };

  try {
    const res = await postJson('/api/recon', { url: 'https://non-existent.org' });
    assert.equal(res.status, 200);
    assert.equal(res.data.dns.status, 'nxdomain');
    assert.equal(res.data.dns.aCount, 0);
    assert.equal(res.data.dns.aaaaCount, 0);
    assert.ok(res.data.findings.some((f: { id: string }) => f.id === 'recon-dns-nxdomain'));
  } finally {
    mockReconResolver = undefined;
  }
});

test('POST /api/recon: DNS timeout scenario handled safely', async () => {
  mockReconResolver = {
    resolve4: async () => new Promise((resolve) => setTimeout(() => resolve([]), 5000)),
    resolve6: async () => new Promise((resolve) => setTimeout(() => resolve([]), 5000)),
    resolveMx: async () => [],
  };

  try {
    const res = await postJson('/api/recon', { url: 'https://slow-dns.org' });
    assert.equal(res.status, 200);
    assert.equal(res.data.dns.status, 'timeout');
    assert.ok(res.data.dns.message?.includes('timed out'));
  } finally {
    mockReconResolver = undefined;
  }
});

test('POST /api/recon: RDAP upstream failure (HTTP 500 / malformed JSON) handled safely', async () => {
  mockReconFetch = async () => new Response('Internal Registry Crash', { status: 500 });

  try {
    const res = await postJson('/api/recon', { url: 'https://rdap-500.org' });
    assert.equal(res.status, 200);
    assert.equal(res.data.rdap.status, 'error');
    assert.ok(res.data.rdap.message?.includes('500') || res.data.rdap.message?.includes('error'));
  } finally {
    mockReconFetch = undefined;
  }
});

// ============================================================================
// 3. POST /api/redirect-chain Integration Tests
// ============================================================================

test('POST /api/redirect-chain: Valid public URL - Direct terminal destination (0 redirects)', async () => {
  mockRedirectResolver = {
    resolve4: async () => ['93.184.215.14'],
    resolve6: async () => [],
    resolveMx: async () => [],
  };

  mockRedirectRequester = async () => ({
    statusCode: 200,
    statusText: 'OK',
    headers: {},
    durationMs: 30,
  });

  try {
    const res = await postJson('/api/redirect-chain', { url: 'https://example.com' });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal(res.data.status, 'COMPLETED');
    assert.equal(res.data.totalRedirects, 0);
    assert.equal(res.data.hops.length, 1);
    assert.equal(res.data.hops[0].statusCode, 200);
  } finally {
    mockRedirectResolver = undefined;
    mockRedirectRequester = undefined;
  }
});

test('POST /api/redirect-chain: Valid public URL - Multi-hop redirect completed successfully', async () => {
  let hopCount = 0;
  mockRedirectResolver = {
    resolve4: async () => ['93.184.215.14'],
    resolve6: async () => [],
    resolveMx: async () => [],
  };

  mockRedirectRequester = async (targetUrl) => {
    hopCount++;
    if (hopCount === 1) {
      return {
        statusCode: 301,
        statusText: 'Moved Permanently',
        headers: { location: 'https://example.com/target' },
        durationMs: 20,
      };
    }
    return {
      statusCode: 200,
      statusText: 'OK',
      headers: {},
      durationMs: 25,
    };
  };

  try {
    const res = await postJson('/api/redirect-chain', { url: 'https://example.com/start' });
    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'COMPLETED');
    assert.equal(res.data.totalRedirects, 1);
    assert.equal(res.data.hops.length, 2);
    assert.equal(res.data.hops[0].statusCode, 301);
    assert.equal(res.data.hops[1].statusCode, 200);
  } finally {
    mockRedirectResolver = undefined;
    mockRedirectRequester = undefined;
  }
});

test('POST /api/redirect-chain: Rejects invalid URL schemes (javascript:, ftp:)', async () => {
  const schemes = ['javascript:alert(1)', 'ftp://files.example.com'];
  for (const s of schemes) {
    const res = await postJson('/api/redirect-chain', { url: s });
    assert.equal(res.status, 400);
  }
});

test('POST /api/redirect-chain: Rejects malformed JSON payload with HTTP 400', async () => {
  const res = await postRaw('/api/redirect-chain', '{"url": invalid');
  assert.equal(res.status, 400);
  assert.equal(res.data.error, 'Malformed JSON payload.');
});

test('POST /api/redirect-chain: Rejects missing URL fields', async () => {
  const r1 = await postJson('/api/redirect-chain', {});
  assert.equal(r1.status, 400);

  const r2 = await postJson('/api/redirect-chain', { url: '' });
  assert.equal(r2.status, 400);
});

test('POST /api/redirect-chain SSRF Protection: Blocks loopback and private IP initial destinations', async () => {
  const privateUrls = [
    'http://127.0.0.1:8080/admin',
    'http://192.168.1.1/setup',
    'http://10.0.0.1/metrics',
    'http://169.254.169.254/latest/meta-data',
  ];

  for (const pUrl of privateUrls) {
    const res = await postJson('/api/redirect-chain', { url: pUrl });
    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'BLOCKED_SPECIAL_USE_IP');
    assert.equal(res.data.totalRedirects, 0);
  }
});

test('POST /api/redirect-chain SSRF Protection: Blocks mid-chain redirect to loopback or private addresses', async () => {
  mockRedirectResolver = publicDnsResolver();
  mockRedirectRequester = async () => ({
    statusCode: 302,
    statusText: 'Found',
    headers: { location: 'http://127.0.0.1:8080/admin' },
    durationMs: 15,
  });

  try {
    const res = await postJson('/api/redirect-chain', { url: 'https://example.com/step1' });
    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'BLOCKED_SPECIAL_USE_IP');
    assert.ok(res.data.findings.some((f: { id: string }) => f.id.includes('blocked-ip')));
  } finally {
    mockRedirectResolver = undefined;
    mockRedirectRequester = undefined;
  }
});

test('POST /api/redirect-chain: Detects and stops infinite redirect loops', async () => {
  mockRedirectResolver = publicDnsResolver();
  mockRedirectRequester = async () => ({
    statusCode: 302,
    statusText: 'Found',
    headers: { location: 'https://example.com/loop' },
    durationMs: 10,
  });

  try {
    const res = await postJson('/api/redirect-chain', { url: 'https://example.com/loop' });
    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'REDIRECT_LOOP');
    assert.ok(res.data.findings.some((f: { id: string }) => f.id.includes('loop-detected')));
  } finally {
    mockRedirectResolver = undefined;
    mockRedirectRequester = undefined;
  }
});

test('POST /api/redirect-chain: Enforces maximum 5 hops limit safely', async () => {
  mockRedirectResolver = publicDnsResolver();
  let hopNum = 0;
  mockRedirectRequester = async () => {
    hopNum++;
    return {
      statusCode: 302,
      statusText: 'Found',
      headers: { location: `https://example.com/hop-${hopNum}` },
      durationMs: 10,
    };
  };

  try {
    const res = await postJson('/api/redirect-chain', { url: 'https://example.com/hop-0' });
    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'MAX_HOPS_EXCEEDED');
    assert.ok(res.data.findings.some((f: { id: string }) => f.id === 'max-hops-exceeded'));
  } finally {
    mockRedirectResolver = undefined;
    mockRedirectRequester = undefined;
  }
});

test('POST /api/redirect-chain: Hop timeout scenario returns TIMEOUT status safely', async () => {
  mockRedirectResolver = publicDnsResolver();
  mockRedirectRequester = async () => {
    const err = new Error('HOP_TIMEOUT');
    throw err;
  };

  try {
    const res = await postJson('/api/redirect-chain', { url: 'https://slow-redirect.org' });
    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'TIMEOUT');
    assert.ok(res.data.statusMessage?.includes('timed out'));
  } finally {
    mockRedirectResolver = undefined;
    mockRedirectRequester = undefined;
  }
});

// ============================================================================
// 4. POST /api/screenshot Integration Tests
// ============================================================================

test('POST /api/screenshot: Valid public URL - Successful direct binary capture returns image data URI', async () => {
  mockScreenshotResolver = async () => ['93.184.215.14'];
  mockScreenshotFetch = async (url) => {
    assert.ok(String(url).includes('api.microlink.io'));
    return new Response(VALID_JPEG_BUFFER, {
      status: 200,
      headers: { 'Content-Type': 'image/jpeg' },
    });
  };

  try {
    const res = await postJson('/api/screenshot', { url: 'https://example.com' });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal(res.data.status, 'success');
    assert.ok(res.data.imageDataUri?.startsWith('data:image/jpeg;base64,'));
    assert.equal(res.data.viewport?.width, 1280);
    assert.equal(res.data.viewport?.height, 800);
    assert.ok(res.data.capturedAt);
  } finally {
    mockScreenshotResolver = undefined;
    mockScreenshotFetch = undefined;
  }
});

test('POST /api/screenshot: Valid public URL - Successful capture via JSON provider response with CDN URL', async () => {
  mockScreenshotResolver = async () => ['93.184.215.14'];
  mockScreenshotFetch = async (url) => {
    const urlStr = String(url);
    if (urlStr.includes('api.microlink.io')) {
      return new Response(
        JSON.stringify({
          status: 'success',
          data: { screenshot: { url: 'https://cdn.microlink.io/mock-screenshot.jpg' } },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    // CDN image download
    return new Response(VALID_JPEG_BUFFER, {
      status: 200,
      headers: { 'Content-Type': 'image/jpeg' },
    });
  };

  try {
    const res = await postJson('/api/screenshot', { url: 'https://example.com' });
    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'success');
    assert.ok(res.data.imageDataUri?.startsWith('data:image/jpeg;base64,'));
  } finally {
    mockScreenshotResolver = undefined;
    mockScreenshotFetch = undefined;
  }
});

test('POST /api/screenshot: Rejects invalid URL schemes (javascript:, ftp:)', async () => {
  const schemes = ['javascript:alert(1)', 'ftp://example.com/pic.png'];
  for (const s of schemes) {
    const res = await postJson('/api/screenshot', { url: s });
    assert.equal(res.status, 400);
    assert.equal(res.data.status, 'error');
  }
});

test('POST /api/screenshot: Rejects malformed JSON syntax with HTTP 400', async () => {
  const res = await postRaw('/api/screenshot', '{"url": malformed');
  assert.equal(res.status, 400);
  assert.equal(res.data.error, 'Malformed JSON payload.');
});

test('POST /api/screenshot: Rejects missing URL fields', async () => {
  const r1 = await postJson('/api/screenshot', {});
  assert.equal(r1.status, 400);
  assert.equal(r1.data.status, 'error');

  const r2 = await postJson('/api/screenshot', { url: '' });
  assert.equal(r2.status, 400);
  assert.equal(r2.data.status, 'error');
});

test('POST /api/screenshot SSRF Protection: Blocks loopback, localhost, and private RFC 1918 addresses', async () => {
  const privateUrls = [
    'http://127.0.0.1:8080/admin',
    'http://localhost:3000',
    'http://10.0.0.1/dashboard',
    'http://192.168.1.1/setup',
    'http://169.254.169.254/latest/meta-data',
  ];

  for (const pUrl of privateUrls) {
    const res = await postJson('/api/screenshot', { url: pUrl });
    assert.equal(res.status, 400);
    assert.equal(res.data.status, 'blocked_special_use');
    assert.ok(res.data.error?.includes('public IP addresses'));
  }
});

test('POST /api/screenshot SSRF Protection: Pre-flight DNS check blocks hostnames resolving to private/mixed IPs', async () => {
  mockScreenshotResolver = async () => ['93.184.215.14', '10.0.0.5']; // Mixed public + private
  let providerCalled = false;
  mockScreenshotFetch = async () => {
    providerCalled = true;
    return new Response('unexpected', { status: 500 });
  };

  try {
    const res = await postJson('/api/screenshot', { url: 'https://rebinding-host.attacker.org' });
    assert.equal(res.status, 400);
    assert.equal(res.data.status, 'blocked_special_use');
    assert.equal(providerCalled, false, 'External rendering provider must never be called for restricted IP targets');
  } finally {
    mockScreenshotResolver = undefined;
    mockScreenshotFetch = undefined;
  }
});

test('POST /api/screenshot SSRF Protection: Rejects provider returning CDN URL pointing to internal IP', async () => {
  mockScreenshotResolver = async (hostname) => {
    if (hostname.includes('169.254')) return ['169.254.169.254'];
    return ['93.184.215.14'];
  };

  mockScreenshotFetch = async () => {
    return new Response(
      JSON.stringify({
        status: 'success',
        data: { screenshot: { url: 'http://169.254.169.254/computeMetadata/v1/token' } },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };

  try {
    const res = await postJson('/api/screenshot', { url: 'https://normal-example.org' });
    assert.equal(res.status, 502);
    assert.equal(res.data.status, 'error');
    assert.ok(res.data.error?.includes('Insecure') || res.data.error?.includes('restricted'));
  } finally {
    mockScreenshotResolver = undefined;
    mockScreenshotFetch = undefined;
  }
});

test('POST /api/screenshot: Upstream provider rate limit (HTTP 429) returns 429', async () => {
  mockScreenshotResolver = async () => ['93.184.215.14'];
  mockScreenshotFetch = async () => new Response('Too Many Requests', { status: 429 });

  try {
    const res = await postJson('/api/screenshot', { url: 'https://example.com' });
    assert.equal(res.status, 429);
    assert.equal(res.data.status, 'error');
    assert.ok(res.data.error?.includes('rate limit'));
  } finally {
    mockScreenshotResolver = undefined;
    mockScreenshotFetch = undefined;
  }
});

test('POST /api/screenshot: Upstream provider render failure (HTTP 500/502) returns 502', async () => {
  mockScreenshotResolver = async () => ['93.184.215.14'];
  mockScreenshotFetch = async () => new Response('Headless Render Crashed', { status: 500 });

  try {
    const res = await postJson('/api/screenshot', { url: 'https://crash-test.com' });
    assert.equal(res.status, 502);
    assert.equal(res.data.status, 'error');
    assert.ok(res.data.error?.includes('500'));
  } finally {
    mockScreenshotResolver = undefined;
    mockScreenshotFetch = undefined;
  }
});

test('POST /api/screenshot: Magic bytes validation rejects SVG or text pretending to be image', async () => {
  mockScreenshotResolver = async () => ['93.184.215.14'];
  mockScreenshotFetch = async () => {
    return new Response(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), {
      status: 200,
      headers: { 'Content-Type': 'image/jpeg' },
    });
  };

  try {
    const res = await postJson('/api/screenshot', { url: 'https://fake-image.com' });
    assert.equal(res.status, 502);
    assert.equal(res.data.status, 'error');
    assert.ok(res.data.error?.includes('Only JPEG, PNG, and WebP'));
  } finally {
    mockScreenshotResolver = undefined;
    mockScreenshotFetch = undefined;
  }
});

test('POST /api/screenshot: Streaming byte limit aborts responses exceeding 2MB limit', async () => {
  mockScreenshotResolver = async () => ['93.184.215.14'];
  mockScreenshotFetch = async () => {
    return new Response(Buffer.alloc(100), {
      status: 200,
      headers: {
        'Content-Type': 'image/jpeg',
        'Content-Length': '3000000', // 3MB exceeds 2MB limit
      },
    });
  };

  try {
    const res = await postJson('/api/screenshot', { url: 'https://oversized-image.com' });
    assert.equal(res.status, 502);
    assert.equal(res.data.status, 'error');
    assert.ok(res.data.error?.includes('maximum size limit'));
  } finally {
    mockScreenshotResolver = undefined;
    mockScreenshotFetch = undefined;
  }
});

test('POST /api/screenshot: Upstream timeout scenario returns 504 timeout', async () => {
  mockScreenshotResolver = async () => ['93.184.215.14'];
  mockScreenshotFetch = async () => {
    const err = new Error('The operation was aborted');
    err.name = 'AbortError';
    throw err;
  };

  try {
    const res = await postJson('/api/screenshot', { url: 'https://timeout-screenshot.com' });
    assert.equal(res.status, 504);
    assert.equal(res.data.status, 'timeout');
    assert.ok(res.data.error?.includes('timed out'));
  } finally {
    mockScreenshotResolver = undefined;
    mockScreenshotFetch = undefined;
  }
});
