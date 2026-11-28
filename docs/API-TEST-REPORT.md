# Fraud Link Detector — Backend API Integration Test Report

## 1. Executive Summary

This report documents the design, implementation, and execution results of comprehensive backend integration tests for the **Fraud Link Detector** application. The test suite verifies the four primary server endpoints against edge cases, malicious payloads, protocol violations, SSRF vectors, DNS rebinding attacks, external API failures, and upstream timeouts.

All 42 newly implemented integration tests pass alongside all 181 pre-existing unit and service tests, totaling **223 passed tests with 0 failures**.

```
Total Test Suites: 13
Total Tests: 223
Passed: 223
Failed: 0
Execution Time: ~8.8s
TypeScript Check: 0 Errors (tsc --noEmit)
Production Build: Clean (vite build)
```

---

## 2. Tested Endpoints & Scope

| Endpoint | Method | Primary Functionality | Security Safeguards Tested |
| :--- | :--- | :--- | :--- |
| `/api/threat-check` | `POST` | Google Safe Browsing v5 threat lookup | Key redaction in logs, generic client errors, URL length limit, scheme validation |
| `/api/recon` | `POST` | DNS reconnaissance & RFC 9224 RDAP lookup | Loopback/RFC 1918 blocking, DNS rebinding defense, NXDOMAIN handling, RDAP stream byte limits |
| `/api/redirect-chain` | `POST` | Connection-pinned hop-by-hop HTTP redirect inspection | Private destination rejection (initial & intermediate hops), infinite loop detection, 5-hop cap |
| `/api/screenshot` | `POST` | Ephemeral rendering preview via Microlink | Pre-flight DNS resolution, RFC 1918 block, image magic-byte verification (JPEG/PNG/WebP), 2MB stream limit |

---

## 3. Test Architecture & Deterministic Mocking Strategy

The integration tests run directly against an Express application instance created via `createApp()` and mounted on an in-memory HTTP server (`http.createServer(app)`) bound to `127.0.0.1` on port `0` (ephemeral port allocation).

### Dependency Injection & Isolation
To eliminate flakiness, dependency on external networks, rate limit quotas, or third-party outages, `src/server/app.ts` provides dependency injection hooks (`ApiRouterOptions`) for:
- `safeBrowsingFetch`: Intercepts Google Safe Browsing v5 REST queries.
- `reconResolver` & `reconFetch`: Controls DNS resolution (A, AAAA, MX) and IANA/RDAP bootstrap HTTP fetching.
- `redirectResolver` & `redirectRequester`: Controls DNS resolution and socket-pinned HTTP requests for redirect hops.
- `screenshotResolver` & `screenshotFetch`: Controls pre-flight IP resolution and upstream screenshot provider fetches.
- `disableRateLimiting`: Disables test runner IP throttling on high-throughput sequential assertions while preserving production rate limiter configurations.

In `apiIntegration.test.ts`, every injected external dependency is fail-fast by default: Safe Browsing, RDAP/recon fetch, DNS resolution for recon and redirects, redirect HTTP requests, screenshot DNS resolution, and screenshot-provider fetches throw immediately unless a test explicitly installs a mock. Tests that need a simulated public destination opt in through a named public-DNS fixture. This prevents accidental use of permissive success defaults and ensures the suite never makes live third-party network calls. Production runtime paths retain their normal system implementations when test options are not supplied.

---

## 4. Security & Safety Invariants Verified

1. **SSRF & Private Network Isolation:**
   - Loopback (`127.0.0.1`, `localhost`, `[::1]`), RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and Cloud Metadata (`169.254.169.254`) are systematically rejected with HTTP 400 or classified as `special-use` across all endpoints.
   - Hostnames resolving to private IP ranges trigger DNS rebinding protection and immediately abort outbound requests.
2. **Secret Non-Leakage:**
   - Upstream Google Safe Browsing API keys and raw upstream error payloads are never echoed in client HTTP responses or debug objects (`isThreat: false, checked: false, error: 'Threat intelligence service is temporarily unavailable.'`).
3. **Payload Sanitization & Syntax Rejection:**
   - Malformed JSON payloads return `400 Bad Request` with `{ "error": "Malformed JSON payload." }` and `Cache-Control: no-store`, preventing internal stack traces or 500 crashes.
   - Invalid URI schemes (`javascript:`, `ftp:`, `file:`, `data:`) are rejected immediately before network activity.
4. **Buffer & Resource Protection:**
   - Streaming byte limits prevent memory exhaustion:
     - RDAP server responses: 512 KB
     - IANA bootstrap catalog: 1 MB
     - Screenshot images: 2 MB
   - Magic byte validation ensures only authentic image payloads (JPEG `FF D8 FF`, PNG `89 50 4E 47`, WebP `52 49 46 46...57 45 42 50`) are converted to base64 Data URIs, rejecting disguised HTML/SVG/text payloads.

---

## 5. Integration Test Execution Matrix (42 Cases)

### 5.1 `POST /api/threat-check` (9 Cases)

| Test ID | Test Name / Scenario | Input Payload | Expected Response | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `TC-01` | Valid public URL — Clean domain | `{"url": "https://clean-example.com/login"}` | HTTP 200, `configured: true`, `isThreat: false`, `threatTypes: []`, `cache-control: no-store` | HTTP 200, clean response verified | **PASS** |
| `TC-02` | Valid public URL — Malicious domain | `{"url": "https://malicious-phish.net/"}` | HTTP 200, `configured: true`, `isThreat: true`, `threatTypes: ["SOCIAL_ENGINEERING"]` | HTTP 200, threat detected | **PASS** |
| `TC-03` | Unconfigured API key | `{"url": "https://example.com"}` (no env key) | HTTP 200, `configured: false`, `status: "unconfigured"` | HTTP 200, graceful fallback | **PASS** |
| `TC-04` | Invalid URL schemes (`javascript:`, `ftp:`, `file:`, `data:`) | `{"url": "javascript:alert(1)"}`, etc. | HTTP 400, `error: "Only HTTP and HTTPS protocols are supported."` | HTTP 400, blocked | **PASS** |
| `TC-05` | Malformed JSON syntax | `{"url": "https://example.com" invalid` | HTTP 400, `error: "Malformed JSON payload."`, `Cache-Control: no-store` | HTTP 400, caught by parser | **PASS** |
| `TC-06` | Missing URL fields (empty obj, empty str, number) | `{}`, `{"url": ""}`, `{"url": 12345}` | HTTP 400, descriptive field requirement error | HTTP 400, validated | **PASS** |
| `TC-07` | URL exceeding 2048 characters | `{"url": "https://example.com/..." > 2048 chars}` | HTTP 400, `error: "URL exceeds maximum length of 2048 characters."` | HTTP 400, length enforced | **PASS** |
| `TC-08` | Upstream Google service error (HTTP 500/403/400) | `{"url": "https://secret-domain.org"}` | HTTP 502, generic error message, no API key or URL leak | HTTP 502, sanitized | **PASS** |
| `TC-09` | Upstream Google timeout (AbortError) | `{"url": "https://example.com"}` | HTTP 504, `error: "Threat check request timed out."` | HTTP 504, timed out safely | **PASS** |

### 5.2 `POST /api/recon` (10 Cases)

| Test ID | Test Name / Scenario | Input Payload | Expected Response | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `RC-01` | Valid public URL — Established domain | `{"url": "https://example.com/about"}` | HTTP 200, `dns.status: "resolved"`, `rdap.status: "available"`, established finding | HTTP 200, full recon resolved | **PASS** |
| `RC-02` | Valid public URL — Numeric IP host | `{"url": "http://93.184.215.14:8080/login"}` | HTTP 200, `isIpAddress: true`, `dns.status: "skipped"`, `rdap.status: "skipped"`, direct-ip finding | HTTP 200, numeric IP processed | **PASS** |
| `RC-03` | Invalid URL schemes (`javascript:`, `ftp:`, `file:`) | `{"url": "ftp://ftp.example.com"}` | HTTP 400, protocol validation error | HTTP 400, rejected | **PASS** |
| `RC-04` | Malformed JSON payload | `{"url": broken` | HTTP 400, `error: "Malformed JSON payload."` | HTTP 400, caught | **PASS** |
| `RC-05` | Missing URL fields (`{}`, `{"url": ""}`) | `{}`, `{"url": ""}` | HTTP 400, required field error | HTTP 400, rejected | **PASS** |
| `RC-06` | SSRF Protection — Loopback & RFC 1918 hosts | `http://127.0.0.1:8080`, `http://[::1]:8080`, `http://169.254.169.254` | HTTP 200, `isSpecialUse: true`, `dns.status: "skipped"`, `rdap.status: "skipped"`, special-use finding | HTTP 200, SSRF blocked | **PASS** |
| `RC-07` | SSRF Protection — DNS rebinding to private IP | Hostname resolving to `127.0.0.1` | HTTP 200, `isSpecialUse: true`, `rdap.status: "skipped"`, `recon-resolved-private` finding | HTTP 200, rebinding blocked | **PASS** |
| `RC-08` | DNS Failure — `ENOTFOUND` (NXDOMAIN) | `{"url": "https://non-existent.org"}` | HTTP 200, `dns.status: "nxdomain"`, `recon-dns-nxdomain` finding | HTTP 200, handled gracefully | **PASS** |
| `RC-09` | DNS Resolution Timeout | `{"url": "https://slow-dns.org"}` | HTTP 200, `dns.status: "timeout"`, timeout message | HTTP 200, timed out gracefully | **PASS** |
| `RC-10` | RDAP Upstream Failure (HTTP 500) | `{"url": "https://rdap-500.org"}` | HTTP 200, `rdap.status: "error"`, error details preserved | HTTP 200, error handled | **PASS** |

### 5.3 `POST /api/redirect-chain` (10 Cases)

| Test ID | Test Name / Scenario | Input Payload | Expected Response | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `RD-01` | Valid public URL — Terminal direct hop (0 redirects) | `{"url": "https://example.com"}` | HTTP 200, `status: "COMPLETED"`, `totalRedirects: 0`, 1 hop | HTTP 200, verified | **PASS** |
| `RD-02` | Valid public URL — Multi-hop redirect (301 -> 200) | `{"url": "https://example.com/start"}` | HTTP 200, `status: "COMPLETED"`, `totalRedirects: 1`, 2 hops | HTTP 200, verified | **PASS** |
| `RD-03` | Invalid URL schemes | `{"url": "javascript:alert(1)"}` | HTTP 400, protocol validation error | HTTP 400, rejected | **PASS** |
| `RD-04` | Malformed JSON payload | `{"url": invalid` | HTTP 400, `error: "Malformed JSON payload."` | HTTP 400, caught | **PASS** |
| `RD-05` | Missing URL fields | `{}`, `{"url": ""}` | HTTP 400, required field error | HTTP 400, rejected | **PASS** |
| `RD-06` | SSRF Protection — Initial loopback/private target | `http://127.0.0.1:8080`, `http://169.254.169.254` | HTTP 200, `status: "BLOCKED_SPECIAL_USE_IP"`, `totalRedirects: 0` | HTTP 200, blocked | **PASS** |
| `RD-07` | SSRF Protection — Mid-chain redirect to private IP | Initial public URL redirects to `http://127.0.0.1:8080` | HTTP 200, `status: "BLOCKED_SPECIAL_USE_IP"`, `blocked-ip` finding | HTTP 200, chain halted | **PASS** |
| `RD-08` | Infinite redirect loop detection | `https://example.com/loop` -> `https://example.com/loop` | HTTP 200, `status: "REDIRECT_LOOP"`, `loop-detected` finding | HTTP 200, loop detected | **PASS** |
| `RD-09` | Maximum hops exceeded (cap at 5) | URL redirecting indefinitely to new paths | HTTP 200, `status: "MAX_HOPS_EXCEEDED"`, exactly 5 hops inspected | HTTP 200, cap enforced | **PASS** |
| `RD-10` | Hop timeout scenario | Socket/network request exceeds timeout | HTTP 200, `status: "TIMEOUT"`, `statusMessage: "Request timed out"` | HTTP 200, timed out | **PASS** |

### 5.4 `POST /api/screenshot` (13 Cases)

| Test ID | Test Name / Scenario | Input Payload | Expected Response | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SS-01` | Valid public URL — Direct binary JPEG capture | `{"url": "https://example.com"}` | HTTP 200, `status: "success"`, `imageDataUri: "data:image/jpeg;base64,..."` | HTTP 200, image returned | **PASS** |
| `SS-02` | Valid public URL — JSON provider response + CDN download | `{"url": "https://example.com"}` | HTTP 200, `status: "success"`, secondary CDN download parsed | HTTP 200, image returned | **PASS** |
| `SS-03` | Invalid URL schemes | `{"url": "javascript:alert(1)"}` | HTTP 400, `status: "error"` | HTTP 400, rejected | **PASS** |
| `SS-04` | Malformed JSON payload | `{"url": malformed` | HTTP 400, `error: "Malformed JSON payload."` | HTTP 400, caught | **PASS** |
| `SS-05` | Missing URL fields | `{}`, `{"url": ""}` | HTTP 400, `status: "error"` | HTTP 400, rejected | **PASS** |
| `SS-06` | SSRF Protection — Loopback & RFC 1918 targets | `http://127.0.0.1`, `http://localhost`, `http://169.254.169.254` | HTTP 400, `status: "blocked_special_use"` | HTTP 400, pre-flight blocked | **PASS** |
| `SS-07` | SSRF Protection — Hostname resolving to private/mixed IP | Hostname resolving to `93.184.215.14` and `10.0.0.5` | HTTP 400, `status: "blocked_special_use"`, external provider never contacted | HTTP 400, provider uncalled | **PASS** |
| `SS-08` | SSRF Protection — Provider returning internal CDN IP | Provider JSON returns CDN URL pointing to `169.254.169.254` | HTTP 502, `error: "Insecure or restricted screenshot target URL."` | HTTP 502, CDN blocked | **PASS** |
| `SS-09` | Upstream provider rate limit (HTTP 429) | Upstream provider returns 429 | HTTP 429, `status: "error"`, rate limit message | HTTP 429, returned cleanly | **PASS** |
| `SS-10` | Upstream provider failure (HTTP 500) | Upstream provider returns 500 | HTTP 502, `status: "error"`, failure message | HTTP 502, returned cleanly | **PASS** |
| `SS-11` | Magic byte validation — SVG / HTML payload rejection | Upstream provider returns `<svg>` with image headers | HTTP 502, `error: "Invalid image format. Only JPEG, PNG, and WebP are allowed."` | HTTP 502, SVG rejected | **PASS** |
| `SS-12` | Stream byte limit — Response exceeding 2MB | Upstream provider specifies `Content-Length: 3000000` | HTTP 502, `error: "Screenshot exceeded maximum size limit of 2MB."` | HTTP 502, stream aborted | **PASS** |
| `SS-13` | Upstream provider timeout | Upstream fetch aborts on timeout | HTTP 504, `status: "timeout"`, `error: "Screenshot request timed out."` | HTTP 504, timeout returned | **PASS** |

---

## 6. Complete Test Suite Execution Record

### Test Command
```bash
npm test
```

### Full Test Distribution
```
src/utils/urlParser.test.ts          - 6 tests  (PASS)
src/utils/riskEngine.test.ts         - 8 tests  (PASS)
src/utils/historyStorage.test.ts     - 4 tests  (PASS)
src/server.test.ts                   - 30 tests (PASS)
src/utils/threatStates.test.ts       - 5 tests  (PASS)
src/server/dnsRecon.test.ts          - 39 tests (PASS)
src/server/redirectInspector.test.ts - 16 tests (PASS)
src/utils/clipboardUrl.test.ts       - 13 tests (PASS)
src/utils/shareTarget.test.ts        - 9 tests  (PASS)
src/server/screenshotService.test.ts - 13 tests (PASS)
src/utils/warningEngine.test.ts      - 20 tests (PASS)
src/server/vercelApi.test.ts         - 18 tests (PASS)
src/server/apiIntegration.test.ts    - 42 tests (PASS)
------------------------------------------------------
Total Passed: 223 / 223 (100% Pass Rate)
Failures: 0
Skipped: 0
```

---

## 7. Build and Verification Evidence

### TypeScript Typecheck (`tsc --noEmit`)
```bash
$ npm run lint
> fraud-link-detector@1.0.0 lint
> tsc --noEmit
# Exit Code: 0 (No type errors)
```

### Production Build (`vite build`)
```bash
$ npm run build
> fraud-link-detector@1.0.0 build
> vite build

vite v8.4.0 building client environment for production...
transforming...
✓ 1673 modules transformed.
rendering chunks...
computing gzip size...
dist/index.html                   1.49 kB │ gzip:   0.66 kB
dist/assets/index-Bu_d2VNM.css   50.53 kB │ gzip:   8.59 kB
dist/assets/index-_E3rK2y5.js   585.08 kB │ gzip: 163.88 kB
✓ built in 534ms
```

---

## 8. Limitations & Distinctions: Mocked Integration Tests vs. Live Deployments

1. **Deterministic Mock Boundary:**
   - The integration tests documented above run against in-memory HTTP and DNS mock controllers (`mockSafeBrowsingFetch`, `mockReconResolver`, `mockRedirectRequester`, `mockScreenshotFetch`).
   - These tests prove that the backend API router, input validation pipelines, SSRF filters, error handling mechanisms, rate limiter bindings, and stream parsers behave according to specification under both normal and failure conditions.
   - These tests **do not** prove live external service availability (e.g., whether Google Safe Browsing v5 or Microlink are currently operating without incident on the public Internet).
2. **Third-Party Quotas & Authentication in Production:**
   - In live production, Google Safe Browsing requires an active, unexpired Google Cloud API key (`GOOGLE_SAFE_BROWSING_API_KEY`) with the Web Risk or Safe Browsing APIs enabled and without IP or domain restrictions that conflict with the hosting infrastructure.
   - Live screenshot capturing via Microlink is subject to external network latency, cloud proxy routing, and upstream provider rate limits.
3. **Environment Security Invariant:**
   - No production environment variables, Vercel deployments, or authentication policies were altered during the creation or execution of this test suite.
