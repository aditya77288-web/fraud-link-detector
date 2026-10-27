import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeUrlString,
  isValidUrl,
  parseUrl,
  isIpv4Address,
  isIpv6Address,
  hasPunycodeLabel,
} from './urlParser.js';

test('normalizeUrlString adds https:// when protocol scheme is missing', () => {
  assert.equal(normalizeUrlString('example.com'), 'https://example.com');
  assert.equal(normalizeUrlString('https://secure-site.org/path'), 'https://secure-site.org/path');
  assert.equal(normalizeUrlString('http://insecure-site.org'), 'http://insecure-site.org');
  assert.equal(normalizeUrlString('   google.com/search?q=test  '), 'https://google.com/search?q=test');
  assert.equal(normalizeUrlString(''), '');
});

test('isValidUrl validates URLs correctly', () => {
  assert.equal(isValidUrl('https://example.com'), true);
  assert.equal(isValidUrl('http://subdomain.bank-portal.co.uk/login'), true);
  assert.equal(isValidUrl('telegram.me/channel_invite'), true);
  assert.equal(isValidUrl(''), false);
  assert.equal(isValidUrl('   '), false);
  assert.equal(isValidUrl('not a url at all :::'), false);
});

test('isIpv4Address distinguishes valid IPv4 addresses from domains', () => {
  assert.equal(isIpv4Address('192.0.2.1'), true);
  assert.equal(isIpv4Address('10.0.0.1'), true);
  assert.equal(isIpv4Address('127.0.0.1'), true);
  assert.equal(isIpv4Address('256.0.0.1'), false); // Octet > 255
  assert.equal(isIpv4Address('192.168.1'), false); // Only 3 octets
  assert.equal(isIpv4Address('example.com'), false);
  assert.equal(isIpv4Address('192.0.2.1.com'), false);
  assert.equal(isIpv4Address('01.02.03.04'), false); // Leading zeros
});

test('hasPunycodeLabel identifies labels beginning with xn--', () => {
  assert.equal(hasPunycodeLabel('xn--e1afmkfd.example'), true);
  assert.equal(hasPunycodeLabel('sub.xn--pple-43d.com'), true);
  assert.equal(hasPunycodeLabel('example.com'), false);
  assert.equal(hasPunycodeLabel('domain-xn.com'), false);
});

test('parseUrl accurately extracts authority credentials and does not misclassify @ in path', () => {
  // Credentials in authority: https://example.com@192.0.2.1/login
  const authResult = parseUrl('https://example.com@192.0.2.1/login');
  assert.ok(authResult);
  assert.equal(authResult.hostname, '192.0.2.1'); // Hostname is the IP, not example.com!
  assert.equal(authResult.username, 'example.com');
  assert.equal(authResult.hasAuthorityCredentials, true);
  assert.equal(authResult.isIpAddress, true);
  assert.equal(authResult.subdomainCount, 0); // IP addresses have 0 subdomains

  // @ in path (e.g. social profile): https://medium.com/@author/story
  const pathAtResult = parseUrl('https://medium.com/@author/story');
  assert.ok(pathAtResult);
  assert.equal(pathAtResult.hostname, 'medium.com');
  assert.equal(pathAtResult.username, '');
  assert.equal(pathAtResult.hasAuthorityCredentials, false); // NOT flagged as authority credentials!
});

test('parseUrl accurately detects standard vs nonstandard ports', () => {
  // Non-standard port 8080 on HTTP
  const nonStd = parseUrl('http://192.0.2.1:8080/login');
  assert.ok(nonStd);
  assert.equal(nonStd.explicitPort, '8080');
  assert.equal(nonStd.isNonStandardPort, true);
  assert.equal(nonStd.port, '8080');

  // Standard port 80 on HTTP
  const stdHttp = parseUrl('http://192.0.2.1/login');
  assert.ok(stdHttp);
  assert.equal(stdHttp.explicitPort, '');
  assert.equal(stdHttp.isNonStandardPort, false);
  assert.equal(stdHttp.port, '80 (default)');

  // Standard port 443 on HTTPS
  const stdHttps = parseUrl('https://example.com/login');
  assert.ok(stdHttps);
  assert.equal(stdHttps.explicitPort, '');
  assert.equal(stdHttps.isNonStandardPort, false);
  assert.equal(stdHttps.port, '443 (default)');
});
