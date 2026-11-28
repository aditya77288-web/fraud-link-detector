import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isSpecialUseIpv4,
  isSpecialUseIpv6,
  isSpecialUseHostname,
  performDnsRecon,
  performRdapLookup,
  performFullRecon,
  generateReconFindings,
  DnsResolverInterface,
  constructRdapQueryUrl,
  validateRdapOutboundUrl,
  clearRdapBootstrapCacheForTesting,
  resolveRdapBaseUrl,
} from './dnsRecon.js';

// 1. Valid Domain with A, AAAA, and MX Records
test('DNS Recon: Resolves A, AAAA, and MX records successfully', async () => {
  const mockResolver: DnsResolverInterface = {
    resolve4: async () => ['93.184.215.14'],
    resolve6: async () => ['2606:2800:220:1:248:1893:25c8:1946'],
    resolveMx: async () => [{ exchange: 'mail.example.com', priority: 10 }],
  };

  const result = await performDnsRecon('example.com', mockResolver);
  assert.equal(result.status, 'resolved');
  assert.equal(result.aCount, 1);
  assert.equal(result.aaaaCount, 1);
  assert.equal(result.mxCount, 1);
  assert.equal(result.hasMailExchange, true);
  assert.equal(result.aRecords[0], '93.184.215.14');
});

// 2. Direct IP Address
test('Recon: Direct IP address skips domain DNS and RDAP queries', async () => {
  const result = await performFullRecon('192.0.2.1');
  assert.equal(result.isIpAddress, true);
  assert.equal(result.dns.status, 'skipped');
  assert.equal(result.rdap.status, 'skipped');
  assert.ok(result.findings.some((f) => f.id === 'recon-direct-ip'));
});

// 3. NXDOMAIN / NODATA Handling
test('DNS Recon: Handles NXDOMAIN / NODATA without failing', async () => {
  const nxResolver: DnsResolverInterface = {
    resolve4: async () => {
      const err = new Error('getaddrinfo ENOTFOUND non-existent.domain');
      (err as unknown as { code: string }).code = 'ENOTFOUND';
      throw err;
    },
    resolve6: async () => {
      const err = new Error('getaddrinfo ENOTFOUND non-existent.domain');
      (err as unknown as { code: string }).code = 'ENOTFOUND';
      throw err;
    },
    resolveMx: async () => [],
  };

  const result = await performDnsRecon('non-existent.domain', nxResolver);
  assert.equal(result.status, 'nxdomain');
  assert.equal(result.aCount, 0);
  assert.equal(result.aaaaCount, 0);
});

// 4. DNS Timeout
test('DNS Recon: Handles DNS resolver timeout gracefully', async () => {
  const timeoutResolver: DnsResolverInterface = {
    resolve4: async () => new Promise((resolve) => setTimeout(() => resolve([]), 5000)),
    resolve6: async () => new Promise((resolve) => setTimeout(() => resolve([]), 5000)),
    resolveMx: async () => [],
  };

  const result = await performDnsRecon('slow-dns.test', timeoutResolver);
  assert.equal(result.status, 'timeout');
  assert.ok(result.message?.includes('timed out'));
});

// 5. Newly Registered Domain (<= 30 days)
test('RDAP: Flags newly registered domain under 30 days old', async () => {
  const now = new Date();
  const fiveDaysAgo = new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000).toISOString();

  const mockFetch: typeof fetch = async () => {
    return new Response(
      JSON.stringify({
        events: [
          { eventAction: 'registration', eventDate: fiveDaysAgo },
          { eventAction: 'expiration', eventDate: '2027-10-25T00:00:00Z' },
        ],
        entities: [{ roles: ['registrar'], handle: 'Test Registrar Inc.' }],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };

  const result = await performRdapLookup('brand-new-site.com', mockFetch);
  assert.equal(result.status, 'available');
  assert.ok(result.domainAgeDays! <= 6);

  const mockResolver: DnsResolverInterface = {
    resolve4: async () => ['1.2.3.4'],
    resolve6: async () => [],
    resolveMx: async () => [],
  };

  const full = await performFullRecon('brand-new-site.com', mockResolver, mockFetch);
  const nrdFinding = full.findings.find((f) => f.id === 'recon-nrd');
  assert.ok(nrdFinding, 'Should include NRD warning finding');
  assert.equal(nrdFinding?.severity, 'warning');
});

// 6. Established Domain (> 10 years)
test('RDAP: Recognizes well-established domain registration', async () => {
  const twentyYearsAgo = '2005-01-15T00:00:00Z';

  const mockFetch: typeof fetch = async () => {
    return new Response(
      JSON.stringify({
        events: [
          { eventAction: 'registration', eventDate: twentyYearsAgo },
          { eventAction: 'expiration', eventDate: '2030-01-15T00:00:00Z' },
        ],
        entities: [{ roles: ['registrar'], handle: 'Legacy Registrar' }],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };

  const result = await performRdapLookup('veteran-domain.org', mockFetch);
  assert.equal(result.status, 'available');
  assert.ok(result.domainAgeDays! > 3650);

  const mockResolver: DnsResolverInterface = {
    resolve4: async () => ['8.8.8.8'],
    resolve6: async () => [],
    resolveMx: async () => [],
  };

  const full = await performFullRecon('veteran-domain.org', mockResolver, mockFetch);
  const estFinding = full.findings.find((f) => f.id === 'recon-established-domain');
  assert.ok(estFinding);
  assert.equal(estFinding?.severity, 'neutral');
});

// 7. Unsupported or Redacted RDAP Response
test('RDAP: Handles 404/501 as unsupported and missing dates as redacted', async () => {
  const notFoundFetch: typeof fetch = async () => new Response('Not Found', { status: 404 });
  const unsupported = await performRdapLookup('special-tld.cc', notFoundFetch);
  assert.equal(unsupported.status, 'unsupported');

  const redactedFetch: typeof fetch = async () => {
    return new Response(
      JSON.stringify({
        entities: [{ roles: ['registrar'], handle: 'Privacy Registrar' }],
        events: [],
        remarks: [{ description: ['redacted for privacy'] }],
      }),
      { status: 200 }
    );
  };
  const redacted = await performRdapLookup('private-domain.com', redactedFetch);
  assert.equal(redacted.status, 'redacted');
});

// 8. Malformed RDAP Response
test('RDAP: Handles malformed JSON payload safely', async () => {
  const malformedFetch: typeof fetch = async () => new Response('{ invalid json :::', { status: 200 });
  const result = await performRdapLookup('bad-json.com', malformedFetch);
  assert.equal(result.status, 'error');
  assert.ok(result.message);
});

// 9. RDAP Timeout
test('RDAP: Handles network timeout gracefully', async () => {
  const timeoutFetch: typeof fetch = async () => {
    const err = new Error('The operation was aborted');
    err.name = 'TimeoutError';
    throw err;
  };
  const result = await performRdapLookup('slow-rdap.com', timeoutFetch);
  assert.equal(result.status, 'timeout');
  assert.ok(result.message?.includes('timed out'));
});

// 10. Private & Special-Use Addresses Protection (SSRF)
test('SSRF Protection: Rejects localhost, 127.0.0.1, and RFC 1918 private ranges', () => {
  // IPv4 checks
  assert.equal(isSpecialUseIpv4('127.0.0.1'), true);
  assert.equal(isSpecialUseIpv4('10.0.5.1'), true);
  assert.equal(isSpecialUseIpv4('192.168.1.100'), true);
  assert.equal(isSpecialUseIpv4('172.16.0.1'), true);
  assert.equal(isSpecialUseIpv4('172.31.255.255'), true);
  assert.equal(isSpecialUseIpv4('169.254.1.1'), true);
  assert.equal(isSpecialUseIpv4('8.8.8.8'), false);
  assert.equal(isSpecialUseIpv4('93.184.215.14'), false);

  // Hostname checks
  assert.equal(isSpecialUseHostname('localhost'), true);
  assert.equal(isSpecialUseHostname('sub.localhost'), true);
  assert.equal(isSpecialUseHostname('service.internal'), true);
  assert.equal(isSpecialUseHostname('test.local'), true);
  assert.equal(isSpecialUseHostname('example.com'), false);
});

// 11. IPv4-Mapped IPv6
test('SSRF Protection: Identifies IPv4-mapped IPv6 loopback and private addresses', () => {
  assert.equal(isSpecialUseIpv6('::ffff:127.0.0.1'), true);
  assert.equal(isSpecialUseIpv6('::ffff:192.168.1.1'), true);
  assert.equal(isSpecialUseIpv6('::ffff:7f00:1'), true); // Hex loopback
  assert.equal(isSpecialUseIpv6('::ffff:8.8.8.8'), false); // Public IPv4 mapped
  assert.equal(isSpecialUseIpv6('::ffff:0808:0808'), false); // Public hex IPv4 mapped
  assert.equal(isSpecialUseIpv6('::1'), true);
  assert.equal(isSpecialUseIpv6('fe80::1'), true);
  assert.equal(isSpecialUseIpv6('fc00::1'), true);
  assert.equal(isSpecialUseIpv6('2606:2800:220:1:248:1893:25c8:1946'), false);
});

// 12. SSRF Protection: Domains resolving exclusively to private IPs are blocked
test('SSRF Protection: Domains resolving exclusively to 127.0.0.1 are marked special-use', async () => {
  const privateResolver: DnsResolverInterface = {
    resolve4: async () => ['127.0.0.1'],
    resolve6: async () => [],
    resolveMx: async () => [],
  };

  const result = await performFullRecon('local-spoof.com', privateResolver);
  assert.equal(result.isSpecialUse, true);
  assert.equal(result.rdap.status, 'skipped');
  assert.ok(result.findings.some((f) => f.id === 'recon-resolved-private'));
});

// 13. Upstream HTTP 500 error in RDAP
test('RDAP: Handles upstream 500 error without throwing', async () => {
  const serverErrorFetch: typeof fetch = async () => new Response('Internal Server Error', { status: 500 });
  const result = await performRdapLookup('server-error.com', serverErrorFetch);
  assert.equal(result.status, 'error');
  assert.ok(result.message?.includes('500'));
});

// 14. SSRF Protection: Carrier-Grade NAT (RFC 6598) and Benchmark (RFC 2544) Ranges
test('SSRF Protection: Rejects Carrier-Grade NAT (100.64.0.0/10) and Benchmark (198.18.0.0/15) ranges', () => {
  assert.equal(isSpecialUseIpv4('100.64.0.1'), true);
  assert.equal(isSpecialUseIpv4('100.127.255.254'), true);
  assert.equal(isSpecialUseIpv4('100.63.255.255'), false); // Just outside CGNAT
  assert.equal(isSpecialUseIpv4('100.128.0.1'), false); // Just outside CGNAT
  assert.equal(isSpecialUseIpv4('198.18.0.1'), true);
  assert.equal(isSpecialUseIpv4('198.19.255.254'), true);
});

// 15. SSRF Protection: IPv4-compatible IPv6 notation
test('SSRF Protection: Rejects IPv4-compatible IPv6 notation with private addresses', () => {
  assert.equal(isSpecialUseIpv6('::127.0.0.1'), true);
  assert.equal(isSpecialUseIpv6('::192.168.1.1'), true);
  assert.equal(isSpecialUseIpv6('::10.0.0.1'), true);
  assert.equal(isSpecialUseIpv6('::93.184.215.14'), false);
});

// 16. SSRF Protection: Mixed public and private IP resolution (DNS rebinding)
test('SSRF Protection: Detects mixed public and private IP resolution (DNS rebinding)', async () => {
  const mixedResolver: DnsResolverInterface = {
    resolve4: async () => ['93.184.215.14', '127.0.0.1'],
    resolve6: async () => [],
    resolveMx: async () => [],
  };

  const result = await performFullRecon('rebind-test.com', mixedResolver);
  assert.equal(result.isSpecialUse, true);
  assert.equal(result.rdap.status, 'skipped');
  assert.ok(result.findings.some((f) => f.id === 'recon-resolved-private'));
  assert.ok(result.findings.some((f) => f.title.includes('DNS Rebinding Risk')));
});

// 17. Comprehensive RDAP Status Contract Tests (available, redacted, unavailable, unsupported, timeout, error)
test('RDAP Status Contract: Distinguishes available, redacted, unavailable, unsupported, timeout, and error', async () => {
  // 1. available
  const availableFetch: typeof fetch = async () => new Response(JSON.stringify({
    events: [{ eventAction: 'registration', eventDate: '2015-06-15T00:00:00Z' }]
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  const r1 = await performRdapLookup('test.com', availableFetch);
  assert.equal(r1.status, 'available');
  assert.ok(r1.registrationDate);

  // 2. redacted (explicit redaction property or notice/remark)
  const redactedFetch: typeof fetch = async () => new Response(JSON.stringify({
    events: [],
    remarks: [{ description: ['Registration data withheld under privacy policy'] }]
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  const r2 = await performRdapLookup('test.com', redactedFetch);
  assert.equal(r2.status, 'redacted');

  // 3. unavailable (no registration date and no explicit redaction metadata)
  const unavailableFetch: typeof fetch = async () => new Response(JSON.stringify({
    events: [],
    remarks: []
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  const r3 = await performRdapLookup('test.com', unavailableFetch);
  assert.equal(r3.status, 'unavailable');

  // Findings generation tests for redacted and unavailable
  const findingsRedacted = generateReconFindings('test.com', false, { status: 'resolved', aRecords: ['1.2.3.4'], aaaaRecords: [], mxRecords: [], aCount: 1, aaaaCount: 0, mxCount: 0, hasMailExchange: false }, { status: 'redacted' });
  assert.ok(findingsRedacted.some(f => f.id === 'recon-rdap-redacted'));

  const findingsUnavailable = generateReconFindings('test.com', false, { status: 'resolved', aRecords: ['1.2.3.4'], aaaaRecords: [], mxRecords: [], aCount: 1, aaaaCount: 0, mxCount: 0, hasMailExchange: false }, { status: 'unavailable' });
  assert.ok(findingsUnavailable.some(f => f.id === 'recon-rdap-unavailable'));

  // 4. unsupported (404/501)
  const unsupportedFetch: typeof fetch = async () => new Response('Not Found', { status: 404 });
  const r4 = await performRdapLookup('test.cc', unsupportedFetch);
  assert.equal(r4.status, 'unsupported');

  // 5. timeout
  const timeoutFetch: typeof fetch = async () => {
    const err = new Error('Timeout');
    err.name = 'TimeoutError';
    throw err;
  };
  const r5 = await performRdapLookup('test.com', timeoutFetch);
  assert.equal(r5.status, 'timeout');

  // 6. error (HTTP 500)
  const errorFetch: typeof fetch = async () => new Response('Error', { status: 500 });
  const r6 = await performRdapLookup('test.com', errorFetch);
  assert.equal(r6.status, 'error');
  assert.ok(!r6.message?.includes('privacy'));
});

// 18. Correct /domain/{domain} RDAP Path Construction
test('RDAP Endpoint Construction: constructRdapQueryUrl correctly builds /domain/{domain} path', () => {
  assert.equal(
    constructRdapQueryUrl('https://rdap.verisign.com/com/v1/', 'example.com'),
    'https://rdap.verisign.com/com/v1/domain/example.com'
  );
  assert.equal(
    constructRdapQueryUrl('https://rdap.org', 'test.org'),
    'https://rdap.org/domain/test.org'
  );
  assert.equal(
    constructRdapQueryUrl('https://rdap.org/', 'test.org'),
    'https://rdap.org/domain/test.org'
  );
  assert.equal(
    constructRdapQueryUrl('https://rdap.org/domain/', 'sub.domain.co'),
    'https://rdap.org/domain/sub.domain.co'
  );
});

test('RDAP Endpoint Construction: performRdapLookup queries exact /domain/{domain} path', async () => {
  let requestedUrl = '';
  const mockFetch: typeof fetch = async (url) => {
    requestedUrl = typeof url === 'string' ? url : url.toString();
    return new Response(JSON.stringify({
      events: [{ eventAction: 'registration', eventDate: '2021-05-10T00:00:00Z' }]
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };

  await performRdapLookup('example.com', mockFetch);
  assert.ok(requestedUrl.includes('/domain/example.com'), `Requested URL "${requestedUrl}" must contain /domain/example.com`);
  assert.ok(!requestedUrl.includes('/domain/domain/'), 'Must not duplicate /domain/');
});

// 19. IANA Bootstrap RFC 9224 Longest-Match TLD Selection
test('IANA Bootstrap: RFC 9224 longest-match TLD selection matches most specific suffix', async () => {
  clearRdapBootstrapCacheForTesting();
  const mockBootstrap = {
    version: '1.0',
    publication: '2026-01-01',
    services: [
      [['uk'], ['https://rdap.nominet.uk/']],
      [['co.uk'], ['https://rdap.specific.uk/']],
      [['fed.us'], ['https://rdap.fed.gov/']],
      [['us'], ['https://rdap.us/']],
    ],
  };

  const mockFetch: typeof fetch = async () => {
    return new Response(JSON.stringify(mockBootstrap), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };

  // 'example.co.uk' has 2 matching labels for 'co.uk' vs 1 for 'uk' -> selects co.uk server
  const urlCoUk = await resolveRdapBaseUrl('example.co.uk', mockFetch);
  assert.equal(urlCoUk, 'https://rdap.specific.uk/');

  // 'example.uk' only matches 'uk' (1 label)
  clearRdapBootstrapCacheForTesting();
  const urlUk = await resolveRdapBaseUrl('example.uk', mockFetch);
  assert.equal(urlUk, 'https://rdap.nominet.uk/');

  // 'sub.dept.fed.us' matches 'fed.us' (2 labels) over 'us' (1 label)
  clearRdapBootstrapCacheForTesting();
  const urlFedUs = await resolveRdapBaseUrl('sub.dept.fed.us', mockFetch);
  assert.equal(urlFedUs, 'https://rdap.fed.gov/');

  clearRdapBootstrapCacheForTesting();
});

// 20. Invalid and Oversized Bootstrap Responses
test('IANA Bootstrap: Handles oversized bootstrap response (> 1MB) safely and falls back', async () => {
  clearRdapBootstrapCacheForTesting();
  const oversizedData = 'x'.repeat(1048577);
  const oversizedFetch: typeof fetch = async () => {
    return new Response(oversizedData, {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Content-Length': '1048577' },
    });
  };

  // Should not throw, should fall back to TLD default
  const fallbackUrl = await resolveRdapBaseUrl('test.com', oversizedFetch);
  assert.equal(fallbackUrl, 'https://rdap.verisign.com/com/v1/');
  clearRdapBootstrapCacheForTesting();
});

test('IANA Bootstrap: Handles malformed and non-JSON bootstrap responses safely', async () => {
  clearRdapBootstrapCacheForTesting();
  const badJsonFetch: typeof fetch = async () => {
    return new Response('<html>502 Bad Gateway</html>', { status: 502, headers: { 'Content-Type': 'text/html' } });
  };

  const fallbackUrl = await resolveRdapBaseUrl('test.org', badJsonFetch);
  assert.equal(fallbackUrl, 'https://rdap.publicinterestregistry.org/rdap/');
  clearRdapBootstrapCacheForTesting();

  // Malformed structure (missing services)
  const malformedStructureFetch: typeof fetch = async () => {
    return new Response(JSON.stringify({ notServices: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  const fallbackUrl2 = await resolveRdapBaseUrl('test.net', malformedStructureFetch);
  assert.equal(fallbackUrl2, 'https://rdap.verisign.com/com/v1/');
  clearRdapBootstrapCacheForTesting();
});

// 21. Redirects to Private or Untrusted Destinations
test('RDAP Security: Rejects redirects to HTTP (unencrypted downgrade)', async () => {
  const redirectHttpFetch: typeof fetch = async (url) => {
    const urlStr = url.toString();
    if (urlStr.startsWith('https://')) {
      return new Response(null, {
        status: 302,
        headers: { Location: 'http://insecure-rdap.example.org/domain/example.com' },
      });
    }
    return new Response('Insecure response', { status: 200 });
  };

  const result = await performRdapLookup('example.com', redirectHttpFetch);
  assert.equal(result.status, 'error');
  assert.ok(result.message?.includes('Only HTTPS') || result.message?.includes('security policy'));
});

test('RDAP Security: Rejects redirects to loopback (127.0.0.1) and private IPs', async () => {
  const loopbackTargets = [
    'https://127.0.0.1/domain/example.com',
    'https://localhost:8443/domain/example.com',
    'https://169.254.169.254/latest/meta-data',
    'https://192.168.1.1/domain/example.com',
    'https://10.0.0.1/domain/example.com',
  ];

  for (const target of loopbackTargets) {
    const redirectFetch: typeof fetch = async () => {
      return new Response(null, {
        status: 302,
        headers: { Location: target },
      });
    };

    const result = await performRdapLookup('example.com', redirectFetch);
    assert.equal(result.status, 'error');
    assert.ok(result.message?.includes('reserved') || result.message?.includes('private') || result.message?.includes('security policy'));
  }
});

test('RDAP Security: Rejects redirects to domains resolving to private IPs (DNS rebinding)', async () => {
  const rebindingResolver: DnsResolverInterface = {
    resolve4: async (hostname) => {
      if (hostname === 'rebind-rdap.attacker-registry.org') return ['127.0.0.1'];
      return ['93.184.215.14'];
    },
    resolve6: async () => [],
    resolveMx: async () => [],
  };

  const redirectFetch: typeof fetch = async () => {
    return new Response(null, {
      status: 302,
      headers: { Location: 'https://rebind-rdap.attacker-registry.org/domain/example.com' },
    });
  };

  const result = await performRdapLookup('example.com', redirectFetch, rebindingResolver);
  assert.equal(result.status, 'error');
  assert.ok(result.message?.includes('restricted') || result.message?.includes('security policy'));
});

test('RDAP Security: Follows valid HTTPS redirect to trustworthy endpoint', async () => {
  let hop = 0;
  const validRedirectFetch: typeof fetch = async (url) => {
    hop++;
    if (hop === 1) {
      return new Response(null, {
        status: 302,
        headers: { Location: 'https://rdap.authoritative-registry.com/domain/example.com' },
      });
    }
    return new Response(JSON.stringify({
      events: [{ eventAction: 'registration', eventDate: '2018-03-20T00:00:00Z' }]
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };

  const safeResolver: DnsResolverInterface = {
    resolve4: async () => ['93.184.215.14'],
    resolve6: async () => [],
    resolveMx: async () => [],
  };

  const result = await performRdapLookup('example.com', validRedirectFetch, safeResolver);
  assert.equal(result.status, 'available');
  assert.equal(result.registrationDate, '2018-03-20T00:00:00Z');
  assert.equal(hop, 2);
});

test('RDAP Security: Aborts infinite redirect loop safely', async () => {
  const infiniteLoopFetch: typeof fetch = async () => {
    return new Response(null, {
      status: 302,
      headers: { Location: 'https://rdap.loop.example.com/domain/example.com' },
    });
  };

  const safeResolver: DnsResolverInterface = {
    resolve4: async () => ['93.184.215.14'],
    resolve6: async () => [],
    resolveMx: async () => [],
  };

  const result = await performRdapLookup('example.com', infiniteLoopFetch, safeResolver);
  assert.equal(result.status, 'error');
  assert.ok(result.message?.includes('redirect hops'));
});

// 22. Oversized RDAP Response Body Safety
test('RDAP: Handles oversized RDAP response body safely (> 512KB)', async () => {
  const oversizedData = 'a'.repeat(524289);
  const oversizedFetch: typeof fetch = async () => {
    return new Response(oversizedData, {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Content-Length': '524289' },
    });
  };

  const result = await performRdapLookup('example.com', oversizedFetch);
  assert.equal(result.status, 'error');
  assert.ok(result.message?.includes('size limit'));
});



