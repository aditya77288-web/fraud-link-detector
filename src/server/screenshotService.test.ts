import test from 'node:test';
import assert from 'node:assert/strict';
import { captureWebsiteScreenshot } from './screenshotService.js';

// 1. SSRF Guard: Localhost & 127.0.0.1
test('captureWebsiteScreenshot SSRF: Blocks localhost and loopback destination (127.0.0.1)', async () => {
  const result = await captureWebsiteScreenshot('http://127.0.0.1:8080/admin');
  assert.equal(result.status, 400);
  assert.equal(result.body.status, 'blocked_special_use');
  assert.ok(result.body.error?.includes('special-use'));

  const hostResult = await captureWebsiteScreenshot('http://localhost:3000/api');
  assert.equal(hostResult.status, 400);
  assert.equal(hostResult.body.status, 'blocked_special_use');
});

// 2. SSRF Guard: RFC 1918 Private Ranges (10.0.0.0/8, 192.168.0.0/16)
test('captureWebsiteScreenshot SSRF: Blocks private RFC 1918 IPv4 destinations', async () => {
  const result10 = await captureWebsiteScreenshot('http://10.1.2.3/status');
  assert.equal(result10.status, 400);
  assert.equal(result10.body.status, 'blocked_special_use');

  const result192 = await captureWebsiteScreenshot('http://192.168.1.1/setup');
  assert.equal(result192.status, 400);
  assert.equal(result192.body.status, 'blocked_special_use');
});

// 3. SSRF Guard: Cloud Metadata Endpoint (169.254.169.254)
test('captureWebsiteScreenshot SSRF: Blocks Cloud Metadata Link-Local address (169.254.169.254)', async () => {
  const result = await captureWebsiteScreenshot('http://169.254.169.254/computeMetadata/v1/');
  assert.equal(result.status, 400);
  assert.equal(result.body.status, 'blocked_special_use');
});

// 4. Input Validation: Malformed & Unsupported Protocols
test('captureWebsiteScreenshot Validation: Rejects malformed and unsupported protocols', async () => {
  const emptyRes = await captureWebsiteScreenshot('');
  assert.equal(emptyRes.status, 400);
  assert.equal(emptyRes.body.status, 'error');

  const jsRes = await captureWebsiteScreenshot('javascript:alert(1)');
  assert.equal(jsRes.status, 400);
  assert.equal(jsRes.body.status, 'error');

  const ftpRes = await captureWebsiteScreenshot('ftp://files.example.com/file.zip');
  assert.equal(ftpRes.status, 400);
  assert.equal(ftpRes.body.status, 'error');
});

// 5. Successful Visual Capture (Mocked Upstream Fetch)
test('captureWebsiteScreenshot: Returns base64 data URI and metadata on successful snapshot', async () => {
  const dummyPixel = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46]);
  const mockFetch: typeof fetch = async (url) => {
    const urlStr = String(url);
    if (urlStr.includes('api.microlink.io')) {
      return new Response(
        JSON.stringify({
          status: 'success',
          data: {
            screenshot: {
              url: 'https://cdn.microlink.io/mock-screenshot.jpg',
            },
          },
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }
    // Mock image download
    return new Response(dummyPixel, {
      status: 200,
      headers: { 'Content-Type': 'image/jpeg' },
    });
  };

  const result = await captureWebsiteScreenshot(
    'https://www.example.com/login',
    undefined,
    mockFetch
  );

  assert.equal(result.status, 200);
  assert.equal(result.body.status, 'success');
  assert.ok(result.body.imageDataUri?.startsWith('data:image/jpeg;base64,'));
  assert.equal(result.body.viewport?.width, 1280);
  assert.equal(result.body.viewport?.height, 800);
  assert.ok(result.body.capturedAt);
});

// 6. Upstream Timeout Handling
test('captureWebsiteScreenshot: Gracefully handles upstream provider timeout (504)', async () => {
  const timeoutFetch: typeof fetch = async () => {
    const err = new Error('The operation was aborted');
    err.name = 'AbortError';
    throw err;
  };

  const result = await captureWebsiteScreenshot(
    'https://very-slow-site.com',
    undefined,
    timeoutFetch
  );

  assert.equal(result.status, 504);
  assert.equal(result.body.status, 'timeout');
  assert.ok(result.body.error?.includes('timed out'));
});

// 7. Upstream Rate Limit Handling
test('captureWebsiteScreenshot: Handles upstream 429 provider quota saturation', async () => {
  const rateLimitFetch: typeof fetch = async () => {
    return new Response('Rate limit reached', { status: 429 });
  };

  const result = await captureWebsiteScreenshot(
    'https://example.com/site',
    undefined,
    rateLimitFetch
  );

  assert.equal(result.status, 429);
  assert.equal(result.body.status, 'error');
  assert.ok(result.body.error?.includes('rate limit'));
});

// 8. Upstream 502 / Render Failure
test('captureWebsiteScreenshot: Handles upstream 502 failure without throwing unhandled exceptions', async () => {
  const failFetch: typeof fetch = async () => {
    return new Response('Internal Render Crash', { status: 500 });
  };

  const result = await captureWebsiteScreenshot(
    'https://crash-test.org',
    undefined,
    failFetch
  );

  assert.equal(result.status, 502);
  assert.equal(result.body.status, 'error');
  assert.ok(result.body.error?.includes('500'));
});

// 9. Secondary Image URL SSRF Guard
test('captureWebsiteScreenshot SSRF: Blocks provider returning non-HTTPS or internal image URLs', async () => {
  // Provider returns an internal metadata IP for the image URL
  const internalCdnFetch: typeof fetch = async () => {
    return new Response(
      JSON.stringify({
        status: 'success',
        data: {
          screenshot: {
            url: 'http://169.254.169.254/computeMetadata/v1/token',
          },
        },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };

  const result = await captureWebsiteScreenshot(
    'https://normal-site.org',
    undefined,
    internalCdnFetch
  );

  assert.equal(result.status, 502);
  assert.equal(result.body.status, 'error');
  assert.ok(result.body.error?.includes('Insecure') || result.body.error?.includes('restricted'));
});

// 10. Magic Bytes Validation: Rejects SVG/HTML or non-raster image payloads
test('captureWebsiteScreenshot: Rejects SVG or text payloads pretending to be images', async () => {
  const fakeImageBytes = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
  const fakeFetch: typeof fetch = async () => {
    return new Response(fakeImageBytes, {
      status: 200,
      headers: { 'Content-Type': 'image/jpeg' },
    });
  };

  const result = await captureWebsiteScreenshot(
    'https://test-svg.org',
    undefined,
    fakeFetch
  );

  assert.equal(result.status, 502);
  assert.equal(result.body.status, 'error');
  assert.ok(result.body.error?.includes('Only JPEG, PNG, and WebP'));
});

// 11. Oversized Stream Limit Protection
test('captureWebsiteScreenshot: Aborts responses exceeding maximum allowed size (2MB)', async () => {
  const oversizedFetch: typeof fetch = async () => {
    return new Response(Buffer.alloc(100), {
      status: 200,
      headers: {
        'Content-Type': 'image/jpeg',
        'Content-Length': '3000000', // 3 MB declared
      },
    });
  };

  const result = await captureWebsiteScreenshot(
    'https://giant-image.org',
    undefined,
    oversizedFetch
  );

  assert.equal(result.status, 502);
  assert.equal(result.body.status, 'error');
  assert.ok(result.body.error?.includes('maximum size limit'));
});

