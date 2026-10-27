import test from 'node:test';
import assert from 'node:assert/strict';
import { redactSensitiveUrl } from './historyStorage.js';

test('redactSensitiveUrl redacts sensitive query keys like token, password, and session', () => {
  const urlWithSecrets =
    'https://portal.bank.com/verify?token=secretToken12345&pkg=99281&password=MyPassword!&user=john';
  const redacted = redactSensitiveUrl(urlWithSecrets);

  assert.ok(!redacted.includes('secretToken12345'), 'Should not contain sensitive token value');
  assert.ok(!redacted.includes('MyPassword!'), 'Should not contain password value');
  assert.ok(redacted.includes('token=%5BREDACTED%5D') || redacted.includes('token=[REDACTED]'));
  assert.ok(redacted.includes('password=%5BREDACTED%5D') || redacted.includes('password=[REDACTED]'));
  assert.ok(redacted.includes('pkg=99281'), 'Should preserve non-sensitive parameter pkg');
  assert.ok(redacted.includes('user=john'), 'Should preserve non-sensitive parameter user');
});

test('redactSensitiveUrl redacts authority credentials password', () => {
  const urlWithAuthPass = 'http://admin:superSecretPass@192.0.2.1/login';
  const redacted = redactSensitiveUrl(urlWithAuthPass);

  assert.ok(!redacted.includes('superSecretPass'), 'Should not leak authority password');
  assert.ok(redacted.includes('[REDACTED]') || redacted.includes('%5BREDACTED%5D'));
  assert.ok(redacted.includes('admin:'));
});

test('redactSensitiveUrl leaves clean URLs without sensitive parameters unchanged', () => {
  const cleanUrl = 'https://www.example.com/about-us?section=team&lang=en';
  const result = redactSensitiveUrl(cleanUrl);

  assert.equal(result, 'https://www.example.com/about-us?section=team&lang=en');
});

test('redactSensitiveUrl redacts long JWT or hex token strings', () => {
  const jwtUrl = 'https://site.com/auth?data=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature';
  const result = redactSensitiveUrl(jwtUrl);

  assert.ok(!result.includes('doNotLeakThisSignature'));
  assert.ok(result.includes('[REDACTED]') || result.includes('%5BREDACTED%5D'));
});
