import test from 'node:test';
import assert from 'node:assert/strict';
import {
  cleanExtractedUrl,
  extractUrlsFromText,
  readClipboardSafely,
} from './clipboardUrl.js';

// 1. cleanExtractedUrl
test('cleanExtractedUrl: Strips trailing punctuation and enclosing brackets', () => {
  assert.equal(cleanExtractedUrl('https://example.com/test.'), 'https://example.com/test');
  assert.equal(cleanExtractedUrl('https://example.com/test!'), 'https://example.com/test');
  assert.equal(cleanExtractedUrl('https://example.com/test?'), 'https://example.com/test'); // trailing question mark stripped as sentence punctuation
  assert.equal(cleanExtractedUrl('https://example.com/test?id=123.'), 'https://example.com/test?id=123'); // query parameter preserved while trailing period stripped
  assert.equal(cleanExtractedUrl('(https://example.com/test)'), 'https://example.com/test');
  assert.equal(cleanExtractedUrl('<https://example.com/test>'), 'https://example.com/test');
  assert.equal(cleanExtractedUrl('"https://example.com/test"'), 'https://example.com/test');
  assert.equal(cleanExtractedUrl(''), '');
});

// 2. extractUrlsFromText: Empty and Whitespace
test('extractUrlsFromText: Handles empty and whitespace text safely', () => {
  const resEmpty = extractUrlsFromText('');
  assert.equal(resEmpty.status, 'empty');
  assert.equal(resEmpty.urls.length, 0);
  assert.equal(resEmpty.primaryUrl, null);

  const resWhitespace = extractUrlsFromText('    \n\t  ');
  assert.equal(resWhitespace.status, 'empty');
  assert.equal(resWhitespace.urls.length, 0);
});

// 3. extractUrlsFromText: Plain Text Without URLs
test('extractUrlsFromText: Handles plain text without any web URLs', () => {
  const result = extractUrlsFromText('Hello, this is just a normal text message with no links at all.');
  assert.equal(result.status, 'no_url');
  assert.equal(result.urls.length, 0);
  assert.equal(result.primaryUrl, null);
  assert.ok(result.message?.includes('No valid web link'));
});

// 4. extractUrlsFromText: Single Direct URL
test('extractUrlsFromText: Extracts single direct URL cleanly', () => {
  const result = extractUrlsFromText('https://www.example.com/security-check');
  assert.equal(result.status, 'single_url');
  assert.equal(result.urls.length, 1);
  assert.equal(result.primaryUrl, 'https://www.example.com/security-check');
});

// 5. extractUrlsFromText: Natural Language Surrounding URL
test('extractUrlsFromText: Extracts URL embedded within message text and removes punctuation', () => {
  const message = 'Urgent: Please verify your account at https://secure-bank.example/verify! Contact support immediately.';
  const result = extractUrlsFromText(message);
  assert.equal(result.status, 'single_url');
  assert.equal(result.primaryUrl, 'https://secure-bank.example/verify');
});

// 6. extractUrlsFromText: Domain Without Scheme
test('extractUrlsFromText: Detects bare domain/path without http prefix', () => {
  const result = extractUrlsFromText('bank-update.com/login');
  assert.equal(result.status, 'single_url');
  assert.equal(result.primaryUrl, 'bank-update.com/login');
});

// 7. extractUrlsFromText: Multiple URLs with Deduplication
test('extractUrlsFromText: Extracts multiple unique URLs safely', () => {
  const message = 'Compare https://first-site.org/info with https://second-site.org/login and https://first-site.org/info';
  const result = extractUrlsFromText(message);
  assert.equal(result.status, 'multiple_urls');
  assert.equal(result.urls.length, 2);
  assert.equal(result.primaryUrl, 'https://first-site.org/info');
  assert.equal(result.urls[1], 'https://second-site.org/login');
});

// 8. extractUrlsFromText: Dangerous & Unsupported Protocols
test('extractUrlsFromText: Safely ignores javascript: and unsupported protocols in text', () => {
  const message = 'Click here: javascript:alert(document.cookie) or ftp://files.example.com';
  const result = extractUrlsFromText(message);
  assert.equal(result.status, 'no_url');
  assert.equal(result.urls.length, 0);
});

// 9. readClipboardSafely: Success
test('readClipboardSafely: Reads and extracts URL when browser clipboard returns URL text', async () => {
  const mockClipboard = {
    readText: async () => 'Check out https://verify-identity.test/portal for details.',
  };

  const result = await readClipboardSafely(mockClipboard);
  assert.equal(result.status, 'success');
  assert.equal(result.primaryUrl, 'https://verify-identity.test/portal');
  assert.equal(result.urls.length, 1);
});

// 10. readClipboardSafely: Permission Denied
test('readClipboardSafely: Gracefully handles permission denial without throwing', async () => {
  const mockClipboard = {
    readText: async () => {
      throw new Error('NotAllowedError: Read permission denied.');
    },
  };

  const result = await readClipboardSafely(mockClipboard);
  assert.equal(result.status, 'denied');
  assert.equal(result.urls.length, 0);
  assert.equal(result.primaryUrl, null);
  assert.ok(result.message.includes('blocked or denied'));
});

// 11. readClipboardSafely: Unsupported Environment
test('readClipboardSafely: Gracefully handles unsupported browser environment', async () => {
  const result = await readClipboardSafely(undefined);
  assert.equal(result.status, 'unsupported');
  assert.equal(result.urls.length, 0);
  assert.ok(result.message.includes('not supported'));
});

// 12. readClipboardSafely: Empty Clipboard
test('readClipboardSafely: Reports friendly message when clipboard is empty', async () => {
  const mockClipboard = {
    readText: async () => '   ',
  };

  const result = await readClipboardSafely(mockClipboard);
  assert.equal(result.status, 'empty');
  assert.equal(result.urls.length, 0);
  assert.ok(result.message.includes('Clipboard is empty'));
});
