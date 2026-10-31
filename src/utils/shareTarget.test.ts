import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseShareTargetParams,
  cleanShareQueryParams,
} from './shareTarget.js';

// 1. Empty / Missing Parameters
test('parseShareTargetParams: Returns hasShare false when no share parameters are present', () => {
  const emptyParams = new URLSearchParams('');
  const result = parseShareTargetParams(emptyParams);
  assert.equal(result.hasShare, false);
  assert.equal(result.urls.length, 0);
  assert.equal(result.primaryUrl, null);

  const unrelatedParams = new URLSearchParams('theme=dark&tab=history');
  const unrelatedResult = parseShareTargetParams(unrelatedParams);
  assert.equal(unrelatedResult.hasShare, false);
});

// 2. Direct URL Parameter
test('parseShareTargetParams: Extracts valid single URL from url parameter', () => {
  const params = new URLSearchParams('url=https%3A%2F%2Fwww.example.com%2Fabout-us');
  const result = parseShareTargetParams(params);
  assert.equal(result.hasShare, true);
  assert.equal(result.urls.length, 1);
  assert.equal(result.primaryUrl, 'https://www.example.com/about-us');
});

// 3. Natural Message Text with Embedded URL
test('parseShareTargetParams: Extracts clean URL from natural chat/SMS text in text parameter', () => {
  const params = new URLSearchParams(
    'text=URGENT%3A+Verify+your+identity+at+https%3A%2F%2Fsecure-auth.example%2Flogin%21+Immediate+action+required.'
  );
  const result = parseShareTargetParams(params);
  assert.equal(result.hasShare, true);
  assert.equal(result.urls.length, 1);
  assert.equal(result.primaryUrl, 'https://secure-auth.example/login');
});

// 4. Multiple URLs in Shared Message
test('parseShareTargetParams: Extracts multiple unique URLs from text parameter', () => {
  const params = new URLSearchParams(
    'text=Compare+https%3A%2F%2Fsite-a.org+with+https%3A%2F%2Fsite-b.org+before+entering+credentials.'
  );
  const result = parseShareTargetParams(params);
  assert.equal(result.hasShare, true);
  assert.equal(result.urls.length, 2);
  assert.equal(result.primaryUrl, 'https://site-a.org');
  assert.equal(result.urls[1], 'https://site-b.org');
});

// 5. Deduplication across url and text parameters
test('parseShareTargetParams: Deduplicates identical URLs across url and text parameters', () => {
  const params = new URLSearchParams({
    url: 'https://example.com/login',
    text: 'Click here: https://example.com/login',
  });
  const result = parseShareTargetParams(params);
  assert.equal(result.hasShare, true);
  assert.equal(result.urls.length, 1);
  assert.equal(result.primaryUrl, 'https://example.com/login');
});

// 6. Plain Text Without URLs
test('parseShareTargetParams: Handles plain text without any web links gracefully', () => {
  const params = new URLSearchParams('text=Hello+friend%2C+how+are+you+doing+today%3F');
  const result = parseShareTargetParams(params);
  assert.equal(result.hasShare, true);
  assert.equal(result.urls.length, 0);
  assert.equal(result.primaryUrl, null);
  assert.ok(result.message?.includes('did not contain'));
});

// 7. Dangerous / Unsupported Protocols
test('parseShareTargetParams: Ignores unsupported schemes (javascript:) in share parameters', () => {
  const params = new URLSearchParams('url=javascript%3Aalert(1)');
  const result = parseShareTargetParams(params);
  assert.equal(result.hasShare, true);
  assert.equal(result.urls.length, 0);
  assert.equal(result.primaryUrl, null);
});

// 8. cleanShareQueryParams: Removes share parameters and preserves others
test('cleanShareQueryParams: Cleans share parameters from address bar while preserving other query keys', () => {
  let replacedUrl = '';
  const mockLocation = {
    search: '?url=https%3A%2F%2Fexample.com&tab=recent',
    pathname: '/',
  };
  const mockHistory = {
    replaceState: (_data: unknown, _unused: string, newUrl?: string | URL | null) => {
      replacedUrl = String(newUrl);
    },
  };

  cleanShareQueryParams(mockLocation, mockHistory);
  assert.equal(replacedUrl, '/?tab=recent');
});

// 9. cleanShareQueryParams: Returns clean root path when only share parameters were present
test('cleanShareQueryParams: Cleans address bar to / when only share parameters were present', () => {
  let replacedUrl = '';
  const mockLocation = {
    search: '?url=https%3A%2F%2Fexample.com&text=Check+this',
    pathname: '/',
  };
  const mockHistory = {
    replaceState: (_data: unknown, _unused: string, newUrl?: string | URL | null) => {
      replacedUrl = String(newUrl);
    },
  };

  cleanShareQueryParams(mockLocation, mockHistory);
  assert.equal(replacedUrl, '/');
});
