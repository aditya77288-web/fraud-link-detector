import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import routeHandler, { app as routeApp } from '../../api/[...route].js';
import indexHandler, { app as indexApp } from '../../api/index.js';

let server: http.Server;
let baseUrl: string;

before(async () => {
  server = http.createServer(routeApp);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address() as { port: number };
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(() => {
  if (server) {
    server.close();
  }
});

test('Vercel Entrypoint: api/[...route].ts exports callable handler and Express app without listen()', () => {
  assert.equal(typeof routeHandler, 'function', 'Default export of api/[...route].ts must be a function');
  assert.equal(typeof routeApp, 'function', 'Named export app of api/[...route].ts must be a function');
  assert.equal(typeof routeApp.use, 'function', 'Exported app must have Express router methods');
});

test('Vercel Entrypoint: api/index.ts exports callable handler and Express app without listen()', () => {
  assert.equal(typeof indexHandler, 'function', 'Default export of api/index.ts must be a function');
  assert.equal(typeof indexApp, 'function', 'Named export app of api/index.ts must be a function');
  assert.equal(typeof indexApp.use, 'function', 'Exported app must have Express router methods');
});

test('Vercel Config: vercel.json contains valid Vite build settings and non-destructive rewrites', () => {
  const vercelJsonPath = path.resolve(process.cwd(), 'vercel.json');
  assert.ok(fs.existsSync(vercelJsonPath), 'vercel.json must exist in project root');

  const content = JSON.parse(fs.readFileSync(vercelJsonPath, 'utf8'));
  assert.equal(content.framework, 'vite');
  assert.equal(content.buildCommand, 'npm run lint && npm run build');
  assert.equal(content.outputDirectory, 'dist');
  assert.ok(Array.isArray(content.rewrites), 'rewrites must be an array');

  // Verify that there is NO rewrite collapsing /api/(.*) to /api (which destroyed paths)
  const collapsingRewrite = content.rewrites.find(
    (r: { source: string; destination: string }) =>
      r.source === '/api/(.*)' && r.destination === '/api'
  );
  assert.equal(collapsingRewrite, undefined, 'Must NOT contain a destructive rewrite collapsing /api/(.*) to /api');

  // Verify SPA fallback rewrite protecting both /api and /api/*
  const spaRewrite = content.rewrites.find(
    (r: { source: string; destination: string }) =>
      r.source === '/((?!api(?:/|$)).*)' || r.source === '/((?!api/).*)'
  );
  assert.ok(spaRewrite, 'Must contain SPA fallback rewrite protecting API paths');
  assert.equal(spaRewrite.destination, '/index.html', 'SPA fallback must point to /index.html');
});

test('Endpoint 0: GET /api returns 200 with service index and endpoints list', async () => {
  const res = await fetch(`${baseUrl}/api`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const data = await res.json();
  assert.equal(data.status, 'ok');
  assert.equal(data.service, 'fraud-link-detector-api');
  assert.ok(Array.isArray(data.endpoints), 'endpoints must be an array');
  assert.ok(data.endpoints.includes('/api/health'));
  assert.ok(data.endpoints.includes('/api/threat-check'));
  assert.ok(data.endpoints.includes('/api/recon'));
  assert.ok(data.endpoints.includes('/api/redirect-chain'));
  assert.ok(data.endpoints.includes('/api/screenshot'));
});

test('Endpoint 0: GET /api/ returns 200 with service index via trailing slash', async () => {
  const res = await fetch(`${baseUrl}/api/`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const data = await res.json();
  assert.equal(data.status, 'ok');
  assert.equal(data.service, 'fraud-link-detector-api');
});

test('Endpoint 1: GET /api/health returns 200 with status ok and security headers via natural path', async () => {
  const res = await fetch(`${baseUrl}/api/health`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');

  const data = await res.json();
  assert.equal(data.status, 'ok');
  assert.equal(data.service, 'fraud-link-detector-api');
});

test('Endpoint 2: POST /api/threat-check rejects empty URL with 400 and no-store via natural path', async () => {
  const res = await fetch(`${baseUrl}/api/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: '' }),
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const data = await res.json();
  assert.ok(data.error);
});

test('Endpoint 2: POST /api/threat-check accepts valid URL and returns 200 via natural path', async () => {
  const res = await fetch(`${baseUrl}/api/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com' }),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const data = await res.json();
  assert.equal(typeof data.configured, 'boolean');
});

test('Endpoint 3: POST /api/recon rejects malformed URL with 400 via natural path', async () => {
  const res = await fetch(`${baseUrl}/api/recon`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'invalid URL with spaces' }),
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('Endpoint 3: POST /api/recon handles valid destination safely via natural path', async () => {
  const res = await fetch(`${baseUrl}/api/recon`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'http://192.0.2.1/login' }),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const data = await res.json();
  assert.equal(data.isIpAddress, true);
});

test('Endpoint 4: POST /api/redirect-chain rejects empty URL with 400 via natural path', async () => {
  const res = await fetch(`${baseUrl}/api/redirect-chain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: '' }),
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('Endpoint 4: POST /api/redirect-chain blocks loopback IP destination with 200 and status flag via natural path', async () => {
  const res = await fetch(`${baseUrl}/api/redirect-chain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'http://127.0.0.1:8080/admin' }),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const data = await res.json();
  assert.equal(data.status, 'BLOCKED_SPECIAL_USE_IP');
});

test('Endpoint 5: POST /api/screenshot rejects empty URL with 400 via natural path', async () => {
  const res = await fetch(`${baseUrl}/api/screenshot`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: '' }),
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('Path Normalization: GET /health without /api prefix normalizes and returns 200', async () => {
  const res = await fetch(`${baseUrl}/health`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const data = await res.json();
  assert.equal(data.status, 'ok');
});

test('Path Normalization: POST /threat-check without /api prefix normalizes and processes request', async () => {
  const res = await fetch(`${baseUrl}/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: '' }),
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('Defensive Fallback: Recovers subpath when upstream proxy collapsed URL to /api with original URL header', async () => {
  const res = await fetch(`${baseUrl}/api`, {
    method: 'GET',
    headers: {
      'x-vercel-original-url': '/api/health',
    },
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const data = await res.json();
  assert.equal(data.status, 'ok');
});

test('Security & Headers: 404 on unmapped API path retains security headers and no-store', async () => {
  const res = await fetch(`${baseUrl}/api/nonexistent-endpoint-test`);
  assert.equal(res.status, 404);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
});

test('Security & Headers: Malformed payload retains security headers and no-store', async () => {
  const res = await fetch(`${baseUrl}/api/threat-check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'javascript:alert(1)' }),
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
});
