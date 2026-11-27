import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateThreatCheckUrl,
  querySafeBrowsing,
} from './server/safeBrowsing.js';
import { performRdapLookup } from './server/dnsRecon.js';

const SERVER_BASE = 'http://localhost:3000';

// 1. Existing Health Endpoint Test
test('GET /api/health returns status ok and service identifier', async () => {
  const response = await fetch(`${SERVER_BASE}/api/health`);
  assert.equal(response.status, 200);

  const data = await response.json();
  assert.equal(data.status, 'ok');
  assert.equal(data.service, 'fraud-link-detector-api');
});

// 2. Missing API Key Test (via HTTP endpoint)
test('POST /api/threat-check: Returns unconfigured response when API key is missing', async () => {
  // Ensure the environment variable is not set during this test
  const originalKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  delete process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  try {
    const response = await fetch(`${SERVER_BASE}/api/threat-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com/test' }),
    });

    assert.equal(response.status, 200);
    const data = await response.json();
    assert.equal(data.configured, false);
    assert.equal(data.status, 'unconfigured');
    assert.ok(data.message.includes('not configured'));
  } finally {
    if (originalKey) {
      process.env.GOOGLE_SAFE_BROWSING_API_KEY = originalKey;
    }
  }
});

// 3. Empty URL Test
test('POST /api/threat-check: Rejects empty or missing URL with HTTP 400', async () => {
  const emptyRes = await fetch(`${SERVER_BASE}/api/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: '' }),
  });
  assert.equal(emptyRes.status, 400);
  const emptyData = await emptyRes.json();
  assert.ok(emptyData.error.includes('empty') || emptyData.error.includes('required'));

  const missingRes = await fetch(`${SERVER_BASE}/api/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(missingRes.status, 400);
});

// 4. Invalid URL Format Test
test('POST /api/threat-check: Rejects malformed URL with HTTP 400', async () => {
  const response = await fetch(`${SERVER_BASE}/api/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'invalid URL with spaces and symbols ::::' }),
  });

  assert.equal(response.status, 400);
  const data = await response.json();
  assert.ok(data.error.includes('Invalid') || data.error.includes('URL'));
});

// 5. Unsupported Protocol Test
test('POST /api/threat-check: Rejects unsupported protocols (javascript:, ftp:, file:)', async () => {
  const jsRes = await fetch(`${SERVER_BASE}/api/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'javascript:alert(1)' }),
  });
  assert.equal(jsRes.status, 400);
  const jsData = await jsRes.json();
  assert.ok(jsData.error.includes('protocol'));

  const ftpRes = await fetch(`${SERVER_BASE}/api/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'ftp://ftp.example.com/file.zip' }),
  });
  assert.equal(ftpRes.status, 400);
});

// 6. Size Limit Test (> 2048 characters)
test('POST /api/threat-check: Rejects URL exceeding 2048 characters with HTTP 400', async () => {
  const oversizedUrl = 'https://example.com/path?' + 'a'.repeat(2040);
  assert.ok(oversizedUrl.length > 2048);

  const response = await fetch(`${SERVER_BASE}/api/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: oversizedUrl }),
  });

  assert.equal(response.status, 400);
  const data = await response.json();
  assert.ok(data.error.includes('2048'));
});

// 7. Unit Validation: Authority credentials stripping
test('validateThreatCheckUrl removes embedded user credentials before sending upstream', () => {
  const result = validateThreatCheckUrl('https://admin:secretPass@192.0.2.1/login');
  assert.equal(result.valid, true);
  assert.ok(!result.sanitizedUrl?.includes('admin'));
  assert.ok(!result.sanitizedUrl?.includes('secretPass'));
  assert.equal(result.sanitizedUrl, 'https://192.0.2.1/login');
});

// 8. Mocked Upstream Tests: Safe handling of threat detection, clean results, and errors
test('querySafeBrowsing: Mocked upstream v5 threat match returns isThreat true', async () => {
  const mockFetch: typeof fetch = async (url) => {
    // Assert request is GET with correct v5 URL search parameter and key
    assert.ok(typeof url === 'string');
    assert.ok(url.startsWith('https://safebrowsing.googleapis.com/v5/urls:search?'));
    assert.ok(url.includes('urls[]='));
    assert.ok(url.includes('key=test-fake-key'));

    return new Response(
      JSON.stringify({
        threats: [
          {
            url: 'https://malicious-phish.net/login',
            threatTypes: ['SOCIAL_ENGINEERING'],
          },
        ],
        cacheDuration: '300s',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };

  const result = await querySafeBrowsing('https://malicious-phish.net/login', 'test-fake-key', mockFetch);
  assert.equal(result.status, 200);
  assert.equal(result.body.configured, true);
  assert.equal(result.body.checked, true);
  assert.equal(result.body.isThreat, true);
  assert.deepEqual(result.body.threatTypes, ['SOCIAL_ENGINEERING']);
  assert.equal(result.body.cacheDuration, '300s');
});

test('querySafeBrowsing: Mocked upstream v5 multiple threat types returns deduplicated list', async () => {
  const mockFetch: typeof fetch = async () => {
    return new Response(
      JSON.stringify({
        threats: [
          {
            url: 'https://multi-threat.net/',
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
          },
          {
            url: 'https://multi-threat.net/path',
            threatTypes: ['MALWARE', 'UNWANTED_SOFTWARE'],
          },
        ],
        cacheDuration: '60s',
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };

  const result = await querySafeBrowsing('https://multi-threat.net/', 'test-fake-key', mockFetch);
  assert.equal(result.status, 200);
  assert.equal(result.body.isThreat, true);
  assert.deepEqual(result.body.threatTypes?.sort(), ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'].sort());
});

test('querySafeBrowsing: Mocked upstream v5 clean result returns isThreat false', async () => {
  const mockFetch: typeof fetch = async (url) => {
    assert.ok(typeof url === 'string');
    assert.ok(url.includes('urls[]='));

    return new Response(JSON.stringify({ threats: [], cacheDuration: '3600s' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  const result = await querySafeBrowsing('https://clean-example.com/about', 'test-fake-key', mockFetch);
  assert.equal(result.status, 200);
  assert.equal(result.body.configured, true);
  assert.equal(result.body.checked, true);
  assert.equal(result.body.isThreat, false);
  assert.deepEqual(result.body.threatTypes, []);
  assert.equal(result.body.cacheDuration, '3600s');
});

test('querySafeBrowsing: Mocked upstream 500 error returns generic temporary unavailability error without leaking key or raw upstream message', async () => {
  const mockFetch: typeof fetch = async (url, options) => {
    assert.equal(options?.method, 'GET');
    assert.ok(typeof url === 'string');
    assert.ok(url.includes('/v5/urls:search'));
    assert.ok(url.includes('urls[]='));
    return new Response(JSON.stringify({ error: { code: 400, message: 'Invalid argument: raw upstream error detail' } }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  };

  const result = await querySafeBrowsing('https://example.com', 'test-fake-key', mockFetch);
  assert.equal(result.status, 502);
  assert.equal(result.body.configured, true);
  assert.equal(result.body.checked, false);
  assert.equal(result.body.error, 'Threat intelligence service is temporarily unavailable.');
  assert.ok(!JSON.stringify(result.body).includes('test-fake-key'));
  assert.ok(!JSON.stringify(result.body).includes('raw upstream error detail'));
});

test('querySafeBrowsing: Mocked timeout error returns safe 504 without crashing', async () => {
  const mockFetch: typeof fetch = async () => {
    const error = new Error('The operation was aborted');
    error.name = 'TimeoutError';
    throw error;
  };

  const result = await querySafeBrowsing('https://example.com', 'test-fake-key', mockFetch);
  assert.equal(result.status, 504);
  assert.equal(result.body.configured, true);
  assert.equal(result.body.checked, false);
  assert.ok(result.body.error?.includes('timed out'));
});

// 12. POST /api/recon Integration Tests
test('POST /api/recon: Rejects empty or missing URL with HTTP 400', async () => {
  const response = await fetch(`${SERVER_BASE}/api/recon`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: '' }),
  });
  assert.equal(response.status, 400);
});

test('POST /api/recon: Rejects unsupported protocol (javascript:, ftp:)', async () => {
  const response = await fetch(`${SERVER_BASE}/api/recon`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'javascript:alert(1)' }),
  });
  assert.equal(response.status, 400);
});

test('POST /api/recon: Handles direct IP address safely', async () => {
  const response = await fetch(`${SERVER_BASE}/api/recon`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'http://192.0.2.1:8080/login' }),
  });
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.isIpAddress, true);
  assert.equal(data.hostname, '192.0.2.1');
  assert.equal(data.dns.status, 'skipped');
  assert.equal(data.rdap.status, 'skipped');
});

test('POST /api/recon: Detects special-use / loopback destination and blocks outbound query', async () => {
  const response = await fetch(`${SERVER_BASE}/api/recon`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'http://localhost:3000/test' }),
  });
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.isSpecialUse, true);
  assert.equal(data.rdap.status, 'skipped');
});

// 12. POST /api/redirect-chain Integration Tests
test('POST /api/redirect-chain: Rejects empty URL with HTTP 400', async () => {
  const response = await fetch(`${SERVER_BASE}/api/redirect-chain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: '' }),
  });
  assert.equal(response.status, 400);
});

test('POST /api/redirect-chain: Rejects unsupported protocol (javascript:, ftp:)', async () => {
  const response = await fetch(`${SERVER_BASE}/api/redirect-chain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'javascript:alert(1)' }),
  });
  assert.equal(response.status, 400);
});

test('POST /api/redirect-chain: Rejects loopback address (127.0.0.1) with BLOCKED_SPECIAL_USE_IP', async () => {
  const response = await fetch(`${SERVER_BASE}/api/redirect-chain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'http://127.0.0.1:8080/admin' }),
  });
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.status, 'BLOCKED_SPECIAL_USE_IP');
  assert.equal(data.totalRedirects, 0);
  assert.equal(data.hops[0].statusCode, 0);
});

test('POST /api/redirect-chain: Rejects private RFC 1918 destination (192.168.1.1)', async () => {
  const response = await fetch(`${SERVER_BASE}/api/redirect-chain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'http://192.168.1.1/setup' }),
  });
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.status, 'BLOCKED_SPECIAL_USE_IP');
});

// 13. Security Headers and Cache-Control
test('API Security Headers: Endpoints include protective headers and Cache-Control: no-store', async () => {
  const response = await fetch(`${SERVER_BASE}/api/health`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.equal(response.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
  assert.equal(response.headers.get('cache-control'), 'no-store');

  const reconRes = await fetch(`${SERVER_BASE}/api/recon`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'http://127.0.0.1/test' }),
  });
  assert.equal(reconRes.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(reconRes.headers.get('cache-control'), 'no-store');

  // Verify error responses (HTTP 400) also carry Cache-Control: no-store
  const errRes = await fetch(`${SERVER_BASE}/api/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: '' }),
  });
  assert.equal(errRes.status, 400);
  assert.equal(errRes.headers.get('cache-control'), 'no-store');
  assert.equal(errRes.headers.get('x-content-type-options'), 'nosniff');
});

// 14. RDAP States and Safe Browsing Error Handling
test('performRdapLookup: distinguishes available state when registration date is present', async () => {
  const mockFetch: typeof fetch = async () => {
    return new Response(
      JSON.stringify({
        events: [{ eventAction: 'registration', eventDate: '2020-01-01T00:00:00Z' }],
        entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Test Registrar']]] }],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };
  const result = await performRdapLookup('example.com', mockFetch);
  assert.equal(result.status, 'available');
  assert.equal(result.registrationDate, '2020-01-01T00:00:00Z');
  assert.equal(result.registrar, 'Test Registrar');
});

test('performRdapLookup: distinguishes redacted state when registration date is missing', async () => {
  const mockFetch: typeof fetch = async () => {
    return new Response(
      JSON.stringify({
        events: [],
        entities: [],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };
  const result = await performRdapLookup('example.com', mockFetch);
  assert.equal(result.status, 'redacted');
});

test('performRdapLookup: distinguishes unsupported state on 404', async () => {
  const mockFetch: typeof fetch = async () => {
    return new Response('Not Found', { status: 404 });
  };
  const result = await performRdapLookup('example.test', mockFetch);
  assert.equal(result.status, 'unsupported');
});

test('performRdapLookup: distinguishes timeout state', async () => {
  const mockFetch: typeof fetch = async () => {
    const err = new Error('Timeout');
    err.name = 'TimeoutError';
    throw err;
  };
  const result = await performRdapLookup('example.com', mockFetch);
  assert.equal(result.status, 'timeout');
});



