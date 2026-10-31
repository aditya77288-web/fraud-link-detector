/**
 * Fraud Link Detector - Minimal Installability Service Worker
 * Satisfies Chromium PWA installability requirements for Web Share Target support.
 * Does not aggressively cache dynamic requests or API endpoints.
 */

const SW_VERSION = 'v1.0.0';

self.addEventListener('install', (_event) => {
  // Activate immediately without waiting for existing clients to close
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  // Claim control of open clients immediately
  event.waitUntil(self.clients.claim());
});

// Pass-through fetch listener satisfying PWA criteria without aggressive caching
self.addEventListener('fetch', (event) => {
  // Standard network pass-through
  event.respondWith(fetch(event.request));
});
