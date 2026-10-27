import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateThreatCheckUrl,
  querySafeBrowsing,
} from './server/safeBrowsing.js';

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
test('querySafeBrowsing: Mocked upstream threat match returns isThreat true', async () => {
  const mockFetch: typeof fetch = async (url, options) => {
    // Assert request includes correct payload schema
    const body = JSON.parse(options?.body as string);
    assert.equal(body.client.clientId, 'fraud-link-detector');
    assert.ok(body.threatInfo.threatTypes.includes('SOCIAL_ENGINEERING'));

    return new Response(
      JSON.stringify({
        matches: [
          {
            threatType: 'SOCIAL_ENGINEERING',
            platformType: 'ANY_PLATFORM',
            threat: { url: 'https://malicious-phish.net/login' },
            cacheDuration: '300s',
          },
        ],
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
});

test('querySafeBrowsing: Mocked upstream clean result returns isThreat false', async () => {
  const mockFetch: typeof fetch = async () => {
    // Upstream returns empty object when no threat matches found
    return new Response(JSON.stringify({}), {
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
});

test('querySafeBrowsing: Mocked upstream 500 error returns safe 502 without leaking key', async () => {
  const mockFetch: typeof fetch = async () => {
    return new Response('Internal Server Error', { status: 500 });
  };

  const result = await querySafeBrowsing('https://example.com', 'test-fake-key', mockFetch);
  assert.equal(result.status, 502);
  assert.equal(result.body.configured, true);
  assert.equal(result.body.checked, false);
  assert.ok(result.body.error);
  assert.ok(!JSON.stringify(result.body).includes('test-fake-key'));
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

