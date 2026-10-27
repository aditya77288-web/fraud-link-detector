import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  inspectRedirectChain,
  resolveAndValidateHost,
  stripCredentials,
  HttpRequester,
} from './redirectInspector.js';
import { DnsResolverInterface } from './dnsRecon.js';

// Safe mock public resolver
function createMockDns(records: Record<string, { v4?: string[]; v6?: string[] }>): DnsResolverInterface {
  return {
    resolve4: async (host: string) => {
      const entry = records[host.toLowerCase()];
      if (entry?.v4) return entry.v4;
      throw new Error('ENOTFOUND');
    },
    resolve6: async (host: string) => {
      const entry = records[host.toLowerCase()];
      if (entry?.v6) return entry.v6;
      throw new Error('ENOTFOUND');
    },
    resolveMx: async () => [],
  };
}

test('Redirect Inspector: Single hop with direct 200 OK (no redirects)', async () => {
  const mockDns = createMockDns({
    'example.com': { v4: ['93.184.216.34'] },
  });

  const mockHttp: HttpRequester = async (_url, pinnedIp, method) => {
    assert.equal(pinnedIp, '93.184.216.34');
    assert.equal(method, 'HEAD');
    return {
      statusCode: 200,
      statusText: 'OK',
      headers: {
        server: 'ECS (iad/182A)',
      },
      durationMs: 45,
    };
  };

  const result = await inspectRedirectChain('https://example.com/target', {
    dnsResolver: mockDns,
    httpRequester: mockHttp,
  });

  assert.equal(result.status, 'COMPLETED');
  assert.equal(result.totalRedirects, 0);
  assert.equal(result.hops.length, 1);
  assert.equal(result.hops[0].statusCode, 200);
  assert.equal(result.hops[0].resolvedIp, '93.184.216.34');
  assert.equal(result.hops[0].isHttps, true);
  assert.equal(result.finalDestination, 'https://example.com/target');
});

test('Redirect Inspector: Follows normal 2-hop redirect chain (shortener to destination)', async () => {
  const mockDns = createMockDns({
    'bit.ly': { v4: ['67.199.248.10'] },
    'destination.org': { v4: ['104.18.2.1'] },
  });

  const mockHttp: HttpRequester = async (url) => {
    if (url.hostname === 'bit.ly') {
      return {
        statusCode: 301,
        statusText: 'Moved Permanently',
        headers: {
          location: 'https://destination.org/welcome',
        },
        durationMs: 30,
      };
    }
    return {
      statusCode: 200,
      statusText: 'OK',
      headers: {},
      durationMs: 25,
    };
  };

  const result = await inspectRedirectChain('https://bit.ly/test-link', {
    dnsResolver: mockDns,
    httpRequester: mockHttp,
  });

  assert.equal(result.status, 'COMPLETED');
  assert.equal(result.totalRedirects, 1);
  assert.equal(result.hops.length, 2);
  assert.equal(result.hops[0].statusCode, 301);
  assert.equal(result.hops[0].url, 'https://bit.ly/test-link');
  assert.equal(result.hops[1].statusCode, 200);
  assert.equal(result.hops[1].url, 'https://destination.org/welcome');
  assert.equal(result.finalDestination, 'https://destination.org/welcome');

  // Shortener finding and domain transition finding
  const hasShortenerFinding = result.findings.some((f) => f.id.includes('shortener'));
  const hasDomainChangeFinding = result.findings.some((f) => f.id.includes('domain-change'));
  assert.equal(hasShortenerFinding, true);
  assert.equal(hasDomainChangeFinding, true);
});

test('Redirect Inspector: Resolves relative redirect Location headers safely', async () => {
  const mockDns = createMockDns({
    'example.com': { v4: ['93.184.216.34'] },
  });

  const mockHttp: HttpRequester = async (url) => {
    if (url.pathname === '/login') {
      return {
        statusCode: 302,
        statusText: 'Found',
        headers: {
          location: '/app/dashboard?user=active',
        },
        durationMs: 20,
      };
    }
    return {
      statusCode: 200,
      statusText: 'OK',
      headers: {},
      durationMs: 18,
    };
  };

  const result = await inspectRedirectChain('https://example.com/login', {
    dnsResolver: mockDns,
    httpRequester: mockHttp,
  });

  assert.equal(result.status, 'COMPLETED');
  assert.equal(result.totalRedirects, 1);
  assert.equal(result.hops[1].url, 'https://example.com/app/dashboard?user=active');
  assert.equal(result.finalDestination, 'https://example.com/app/dashboard?user=active');
});

test('Redirect Inspector: Stops and reports when maximum hops (5) exceeded', async () => {
  const mockDns = createMockDns({
    'chain.org': { v4: ['93.184.216.34'] },
  });

  let counter = 0;
  const mockHttp: HttpRequester = async () => {
    counter++;
    return {
      statusCode: 302,
      statusText: 'Found',
      headers: {
        location: `https://chain.org/step-${counter}`,
      },
      durationMs: 10,
    };
  };

  const result = await inspectRedirectChain('https://chain.org/step-0', {
    dnsResolver: mockDns,
    httpRequester: mockHttp,
    maxHops: 5,
  });

  assert.equal(result.status, 'MAX_HOPS_EXCEEDED');
  assert.equal(result.hops.length, 6); // initial hop + 5 redirect hops
  const hasMaxHopFinding = result.findings.some((f) => f.id === 'max-hops-exceeded');
  assert.equal(hasMaxHopFinding, true);
});

test('Redirect Inspector: Detects cyclic redirect loops (A -> B -> A)', async () => {
  const mockDns = createMockDns({
    'loop.com': { v4: ['93.184.216.34'] },
  });

  const mockHttp: HttpRequester = async (url) => {
    if (url.pathname === '/a') {
      return {
        statusCode: 302,
        statusText: 'Found',
        headers: { location: 'https://loop.com/b' },
        durationMs: 15,
      };
    }
    return {
      statusCode: 302,
      statusText: 'Found',
      headers: { location: 'https://loop.com/a' },
      durationMs: 15,
    };
  };

  const result = await inspectRedirectChain('https://loop.com/a', {
    dnsResolver: mockDns,
    httpRequester: mockHttp,
  });

  assert.equal(result.status, 'REDIRECT_LOOP');
  assert.match(result.statusMessage, /Redirect loop detected/);
  const hasLoopFinding = result.findings.some((f) => f.id.includes('loop-detected'));
  assert.equal(hasLoopFinding, true);
});

test('Redirect Inspector: Flags critical HTTPS-to-HTTP downgrade', async () => {
  const mockDns = createMockDns({
    'secure.com': { v4: ['93.184.216.34'] },
    'insecure.com': { v4: ['93.184.216.35'] },
  });

  const mockHttp: HttpRequester = async (url) => {
    if (url.protocol === 'https:') {
      return {
        statusCode: 301,
        statusText: 'Moved Permanently',
        headers: { location: 'http://insecure.com/landing' },
        durationMs: 25,
      };
    }
    return {
      statusCode: 200,
      statusText: 'OK',
      headers: {},
      durationMs: 20,
    };
  };

  const result = await inspectRedirectChain('https://secure.com/portal', {
    dnsResolver: mockDns,
    httpRequester: mockHttp,
  });

  assert.equal(result.status, 'COMPLETED');
  const downgradeFinding = result.findings.find((f) => f.id.includes('https-downgrade'));
  assert.ok(downgradeFinding);
  assert.equal(downgradeFinding.severity, 'critical');
  assert.equal(result.hops[1].isHttps, false);
});

test('Redirect Inspector SSRF: Rejects localhost and loopback destination (127.0.0.1)', async () => {
  const result = await inspectRedirectChain('http://127.0.0.1:8080/admin');
  assert.equal(result.status, 'BLOCKED_SPECIAL_USE_IP');
  assert.equal(result.hops.length, 1);
  assert.equal(result.hops[0].statusCode, 0);
  assert.match(result.statusMessage, /restricted/);
});

test('Redirect Inspector SSRF: Rejects Cloud Metadata IP (169.254.169.254)', async () => {
  const result = await inspectRedirectChain('http://169.254.169.254/latest/meta-data/');
  assert.equal(result.status, 'BLOCKED_SPECIAL_USE_IP');
  assert.equal(result.hops.length, 1);
  assert.equal(result.hops[0].statusCode, 0);
});

test('Redirect Inspector SSRF: Rejects RFC 1918 private IPv4 and Unique Local IPv6', async () => {
  const resPrivateV4 = await inspectRedirectChain('http://10.200.1.5/internal');
  assert.equal(resPrivateV4.status, 'BLOCKED_SPECIAL_USE_IP');

  const resPrivateV6 = await inspectRedirectChain('http://[fc00::1]/internal');
  assert.equal(resPrivateV6.status, 'BLOCKED_SPECIAL_USE_IP');
});

test('Redirect Inspector SSRF: Rejects IPv4-mapped IPv6 loopback [::ffff:127.0.0.1]', async () => {
  const result = await inspectRedirectChain('http://[::ffff:127.0.0.1]/test');
  assert.equal(result.status, 'BLOCKED_SPECIAL_USE_IP');
});

test('Redirect Inspector SSRF: Blocks redirect hop pointing to domain resolving to private IP (DNS Rebinding Guard)', async () => {
  const mockDns = createMockDns({
    'initial-site.com': { v4: ['93.184.216.34'] },
    'attacker-rebind.com': { v4: ['127.0.0.1'] },
  });

  const mockHttp: HttpRequester = async (url) => {
    if (url.hostname === 'initial-site.com') {
      return {
        statusCode: 302,
        statusText: 'Found',
        headers: { location: 'http://attacker-rebind.com/exploit' },
        durationMs: 15,
      };
    }
    throw new Error('Should not connect to rebind target');
  };

  const result = await inspectRedirectChain('https://initial-site.com/gate', {
    dnsResolver: mockDns,
    httpRequester: mockHttp,
  });

  assert.equal(result.status, 'BLOCKED_SPECIAL_USE_IP');
  assert.equal(result.hops.length, 2);
  assert.equal(result.hops[1].statusCode, 0);
  assert.match(result.statusMessage, /restricted special-use IP/);
});

test('Redirect Inspector: Rejects dangerous non-HTTP/HTTPS protocols in redirects', async () => {
  const mockDns = createMockDns({
    'legit-start.com': { v4: ['93.184.216.34'] },
  });

  const mockHttp: HttpRequester = async () => {
    return {
      statusCode: 302,
      statusText: 'Found',
      headers: { location: 'javascript:alert(1)' },
      durationMs: 10,
    };
  };

  const result = await inspectRedirectChain('https://legit-start.com/home', {
    dnsResolver: mockDns,
    httpRequester: mockHttp,
  });

  assert.equal(result.status, 'UNSUPPORTED_PROTOCOL');
  assert.match(result.statusMessage, /unsupported protocol/i);
  const protoFinding = result.findings.find((f) => f.id.includes('unsupported-protocol'));
  assert.ok(protoFinding);
  assert.equal(protoFinding.severity, 'critical');
});

test('Redirect Inspector: Handles per-hop and overall timeouts gracefully', async () => {
  const mockDns = createMockDns({
    'hanging-server.com': { v4: ['93.184.216.34'] },
  });

  const mockHttp: HttpRequester = async () => {
    throw new Error('HOP_TIMEOUT');
  };

  const result = await inspectRedirectChain('https://hanging-server.com/slow', {
    dnsResolver: mockDns,
    httpRequester: mockHttp,
    perHopTimeoutMs: 100,
  });

  assert.equal(result.status, 'TIMEOUT');
  assert.match(result.statusMessage, /timed out/);
  assert.equal(result.hops[0].statusText, 'Timeout');
});

test('Redirect Inspector: Redacts sensitive query tokens in hop URLs and locations', async () => {
  const mockDns = createMockDns({
    'login-gateway.com': { v4: ['93.184.216.34'] },
    'account.org': { v4: ['93.184.216.35'] },
  });

  const mockHttp: HttpRequester = async (url) => {
    if (url.hostname === 'login-gateway.com') {
      return {
        statusCode: 302,
        statusText: 'Found',
        headers: {
          location: 'https://account.org/session?token=supersecret1234567890&user=alice',
        },
        durationMs: 20,
      };
    }
    return {
      statusCode: 200,
      statusText: 'OK',
      headers: {},
      durationMs: 15,
    };
  };

  const result = await inspectRedirectChain(
    'https://login-gateway.com/auth?password=hunter2&apikey=key987654321',
    {
      dnsResolver: mockDns,
      httpRequester: mockHttp,
    }
  );

  assert.equal(result.status, 'COMPLETED');
  // Initial URL query parameters redacted
  assert.doesNotMatch(result.initialUrl, /hunter2/);
  assert.doesNotMatch(result.initialUrl, /key987654321/);
  assert.match(result.initialUrl, /%5BREDACTED%5D|\[REDACTED\]/);

  // Hop 0 Location header redacted
  assert.doesNotMatch(result.hops[0].locationHeader || '', /supersecret1234567890/);
  assert.match(result.hops[0].locationHeader || '', /%5BREDACTED%5D|\[REDACTED\]/);

  // Hop 1 URL redacted
  assert.doesNotMatch(result.hops[1].url, /supersecret1234567890/);
  assert.match(result.hops[1].url, /%5BREDACTED%5D|\[REDACTED\]/);
});

test('stripCredentials removes embedded username and password from authority', () => {
  const cleaned = stripCredentials('https://admin:secret123@example.com/portal');
  assert.equal(cleaned, 'https://example.com/portal');
  assert.doesNotMatch(cleaned, /secret123/);
});
