# Fraud Link Detector

[![Tests](https://img.shields.io/badge/tests-126%20passing-brightgreen.svg)](#testing--verification)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19.0-61dafb.svg)](https://react.dev/)
[![Express](https://img.shields.io/badge/Express-4.21-lightgrey.svg)](https://expressjs.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An open-source, full-stack cybersecurity investigation workbench for analyzing suspicious links, deceptive URLs, and phishing lures. **Fraud Link Detector** combines client-side deterministic URL heuristics with hardened server-side reconnaissance—including Google Safe Browsing intelligence, asynchronous DNS and RDAP registry telemetry, an SSRF-hardened HTTP redirect chain inspector, an evidence-based Scam Awareness Warning Engine, and an on-demand cloud website screenshot preview.

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Architecture Overview](#architecture-overview)
- [Feature Breakdown & Implementation Status](#feature-breakdown--implementation-status)
  - [1. Implemented Features](#1-implemented-features)
  - [2. Partially Implemented Features](#2-partially-implemented-features)
  - [3. Planned Features](#3-planned-features)
- [Defensive Engineering & Security Posture](#defensive-engineering--security-posture)
  - [SSRF Mitigation & Private IP Blocking](#ssrf-mitigation--private-ip-blocking)
  - [DNS Rebinding Protection & Connection Pinning](#dns-rebinding-protection--connection-pinning)
  - [Stream Disposal & Resource Limiting](#stream-disposal--resource-limiting)
  - [Sensitive Data Sanitization & Redaction](#sensitive-data-sanitization--redaction)
- [Local Heuristic Engine & Scoring Matrix](#local-heuristic-engine--scoring-matrix)
- [Scam Awareness Warning Engine](#scam-awareness-warning-engine)
- [API Reference](#api-reference)
- [Visual Walkthrough](#visual-walkthrough)
- [Installation & Getting Started](#installation--getting-started)
- [Environment Configuration](#environment-configuration)
- [Testing & Verification](#testing--verification)
- [Application Limitations & Constraints](#application-limitations--constraints)
- [Responsible Disclosure & Security Guarantees](#responsible-disclosure--security-guarantees)
- [License](#license)

---

## Problem Statement

Phishing campaigns, credential theft portals, and malicious redirects represent the primary attack vectors against end-users. Attackers continuously disguise malicious destinations using:

- **Authority spoofing and basic auth obfuscation** (e.g. `https://trusted-bank.com@192.0.2.1/login`)
- **Punycode internationalized domain names (IDN)** to visually mimic legitimate brands (`xn--...`)
- **Multi-hop URL shortener chains** designed to bypass static URL filters and conceal landing destinations
- **Direct IP addresses and non-standard network ports** to bypass domain-based reputation lists
- **Newly registered domains (NRDs)** spun up minutes before phishing emails are dispatched

Standard endpoint defenses often classify links as binary "good or bad" without providing investigative context. Conversely, naive online URL inspectors frequently expose their own host infrastructure to **Server-Side Request Forgery (SSRF)**, **DNS rebinding attacks**, and **denial of service** by fetching untrusted target websites directly.

**Fraud Link Detector** addresses this by providing layered, defense-in-depth telemetry without ever opening, rendering, or executing untrusted user-supplied web pages on the user's client machine.

---

## Architecture Overview

Fraud Link Detector is designed as a hybrid client-server application:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER (React 19)                         │
│  - Instant, offline deterministic heuristic evaluation (0–100 score)   │
│  - Scam Awareness Warning Engine (Categories A–G with plain English)   │
│  - RFC 3986 URL parsing & authority/credential extraction              │
│  - Redacted local scan history & category risk breakdown               │
│  - Safe clipboard detection & Android Web Share Target confirmation    │
└────────────────┬───────────────────┬───────────────────┬───────────────┘
                 │                   │                   │
      POST /api/threat-check    POST /api/recon     POST /api/redirect-chain
                 │                   │                   │
┌────────────────▼───────────────────▼───────────────────▼───────────────┐
│                    BACKEND LAYER (Express 4 on Node.js)                │
│  - In-memory rate limiting (60 req/min for recon/threat, 15 for photo) │
│  - Strict input validation & URL normalization                         │
│  - Strips credentials from target authority prior to upstream dispatch │
├─────────────────────┬─────────────────────┬────────────────────────────┤
│ Google Safe         │ DNS & RDAP          │ Redirect Inspector         │
│ Browsing Client     │ Reconnaissance      │ (SSRF-Hardened)            │
│ - threatMatches:find│ - A, AAAA, MX via   │ - Hop-by-hop (max 5 hops)  │
│ - Safe unconfigured │   node:dns/promises │ - Pre-flight IP validation │
│   fallback mode     │ - ICANN bootstrap   │ - Custom socket pinning    │
│ - API key isolated  │   RDAP query        │ - Immediate socket destroy │
│   on server         │ - Domain age parser │ - Protocol downgrade alert │
├─────────────────────┴─────────────────────┴────────────────────────────┤
│ Isolated Cloud Screenshot Service                                      │
│ - Remote headless sandbox preview via Microlink API                    │
│ - Pre-flight SSRF IP/host filtering, 8s timeout, 2MB buffer limit      │
└────────────────────────────────────────────────────────────────────────┘
```

### Technology Stack
- **Frontend**: React 19, TypeScript, Vite 8, Tailwind CSS, Lucide React icons, Motion
- **Backend**: Node.js, Express 4, `tsx` TypeScript runtime
- **Testing**: Native Node.js test runner (`node:test`), assertions via `node:assert/strict`
- **Networking**: `node:dns/promises`, `node:http`, `node:https`, Node custom agent socket lookups

---

## Feature Breakdown & Implementation Status

To ensure complete technical transparency, features are categorized into implemented, partially implemented, and planned capabilities:

### 1. Implemented Features

- [x] **Local Deterministic Heuristic Engine**: Evaluates URLs in real-time in the browser across 10 distinct security rules without external dependencies.
- [x] **Risk Scoring & Categorization**: Clamped 0–100 score mapped to explicit risk bands: Low (0–29), Medium (30–59), High (60–100).
- [x] **Scam Awareness Warning Engine**: Produces evidence-based, plain-English findings across 7 security categories (Categories A–G), including threat confidence, severity, potential scam scenarios, and actionable advice.
- [x] **Contextual Path-Keyword Classification**: Accurately distinguishes routine path terms (e.g., `/login`, `/verify`, `/banking`, `/wallet`) from genuine phishing indicators. Path keywords alone produce low-severity informational reminders rather than high-risk phishing claims, while strong evidence (embedded `@` authority credentials, confirmed Safe Browsing threats) is independently preserved.
- [x] **Safe Browsing Threat Intelligence**: Optional Google Safe Browsing v4 API integration via server-side `POST /api/threat-check`. Operates in graceful unconfigured mode when `GOOGLE_SAFE_BROWSING_API_KEY` is not present.
- [x] **DNS Reconnaissance**: Concurrent lookups of `A`, `AAAA`, and `MX` records with individual 3-second timeouts via `node:dns/promises`.
- [x] **Domain Age & RDAP Analysis**: Automated query to ICANN bootstrap RDAP services to resolve domain registration age, registrar name, and creation timestamps. Flags domains registered $\le 30$ days ago.
- [x] **SSRF-Protected Redirect Chain Inspector**: Hop-by-hop redirect analysis (maximum 5 hops) using `HEAD` requests (with zero-body `GET` fallback).
- [x] **DNS Rebinding & Connection Pinning**: Sockets explicitly pinned to pre-validated IP addresses via a custom HTTP/HTTPS agent lookup handler to eliminate Time-of-Check to Time-of-Use (TOCTOU) exploits.
- [x] **Protocol Downgrade Detection**: Flags redirects transitioning from `https://` to insecure `http://`.
- [x] **Sensitive Parameter Redaction**: Strips passwords, auth tokens, session IDs, and JWTs from local history storage and inspected hop locations.
- [x] **In-Memory Rate Limiting**: Sliding-window protection (60 requests per minute for recon/redirects, 15 requests per minute for screenshots).
- [x] **Clipboard URL Detection with User Confirmation**: Safe, on-demand clipboard inspection via "Check Clipboard" button and paste event interception. Prompts user confirmation before executing scans.
- [x] **PWA Web Share Target (Android & Desktop)**: Receives shared suspicious links or message text from chat apps (WhatsApp, Telegram, SMS) with explicit candidate confirmation before analysis.
- [x] **Isolated Cloud Website Screenshot**: Ephemeral cloud-rendered visual preview via external isolated sandbox (Microlink API) with local SSRF pre-flight blocking, 8-second global timeout, 2MB incremental stream ceiling, raster magic-bytes validation, and CDN privacy disclosure.
- [x] **Privacy Labels & Layered Disclosures**: Header accurately presents `"Local URL Analysis"` and `"Privacy-Focused Processing"` badges, complemented by a dedicated Privacy Architecture card detailing all 5 processing layers.
- [x] **Automated Test Suite**: 126 automated unit and integration tests covering parser logic, risk engine rules, warning engine classifications, SSRF bypasses, API contracts, clipboard parsing, share targets, and screenshot rendering.

### 2. Partially Implemented Features

- [ ] **RDAP Registry Coverage**: RDAP parsing supports standard ICANN gTLDs and major ccTLDs; unsupported ccTLDs that lack public RDAP endpoints report as registry-unavailable without failing the scan.
- [ ] **Google Safe Browsing Offline Cache**: Safe Browsing queries are executed on-demand per request; persistent local hash prefix caching is not currently implemented.

### 3. Planned Features

- [ ] **Visual Threat Card Export**: Exporting downloadable or shareable incident summary cards (PNG/PDF) for security operations and end-user education.
- [ ] **Heuristic Phishing Logo Matching**: Perceptual hash comparison of rendered website favicons against high-profile login portals.

---

## Defensive Engineering & Security Posture

A primary design requirement of Fraud Link Detector is that **the inspector must never become a vulnerability**. When backend servers accept arbitrary URLs from untrusted clients, they are susceptible to critical vulnerabilities. The following mitigations are strictly enforced:

### SSRF Mitigation & Private IP Blocking

Prior to dispatching any network request in `redirectInspector.ts` or evaluating DNS targets:
1. Target hostnames are resolved to IP addresses.
2. Every IP address is evaluated against standard bogon and private subnets before connection initiation:
   - **RFC 1918 Private IPv4**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - **Loopback Addresses**: `127.0.0.0/8`, `::1`
   - **Link-Local & Cloud Metadata**: `169.254.0.0/16`, `fe80::/10` (specifically guarding AWS/GCP/Azure `169.254.169.254`)
   - **IPv4-Mapped IPv6**: `::ffff:127.0.0.1` and mapped private blocks
   - **RFC 5737 Documentation Ranges**: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
   - **Multicast & Reserved**: `224.0.0.0/4`, `240.0.0.0/4`, `fc00::/7`
3. If an IP falls into any restricted block, the connection is aborted immediately with `SSRF_BLOCKED`.

### DNS Rebinding Protection & Connection Pinning

Standard HTTP client libraries re-resolve DNS hostnames during connection establishment, creating a TOCTOU vulnerability where an attacker's DNS server returns a benign IP on initial check and a loopback/metadata IP during the actual socket dial.

Fraud Link Detector mitigates this by passing a custom `lookup` interceptor to Node's `http.Agent` and `https.Agent`:

```typescript
// Architectural Pattern: Connection Pinning (src/server/redirectInspector.ts)
const customLookup: CustomLookupFunction = (hostname, options, callback) => {
  // Overrides standard resolver: forces socket to connect strictly
  // to the specific IP validated during pre-flight SSRF inspection.
  callback(null, validatedIp, isIpv6 ? 6 : 4);
};
```

The underlying TCP socket connects directly to the pre-screened IP address while preserving the original `Host` header for virtual hosting compliance.

### Stream Disposal & Resource Limiting

To prevent memory exhaustion, slowloris attacks, or downloading malicious payloads:
- Requests default to `HEAD`.
- When fallback to `GET` is required, the response stream is resumed and immediately aborted (`req.destroy()`, `res.resume()`).
- No response bodies are buffered into memory during redirect inspection.
- Per-hop timeout is hard-capped at 2 seconds; cumulative chain timeout is capped at 6 seconds.
- Chain depth is limited to a strict maximum of 5 hops.

### Sensitive Data Sanitization & Redaction

URLs analyzed in security contexts often contain sensitive credentials or authorization tokens. Fraud Link Detector implements automated sanitization:
- Authority credentials (`https://user:password@domain.com`) are stripped before external queries and masked in UI displays.
- Sensitive query parameters (`token`, `auth`, `key`, `api_key`, `access_token`, `secret`, `password`, `session`, `jwt`) and high-entropy hash values are redacted (`[REDACTED]`) before saving to browser history or transmitting in inspection results.

---

## Local Heuristic Engine & Scoring Matrix

The client-side scanner evaluates URLs against 10 deterministic structural heuristics. Each rule contributes additive weight to the aggregate risk score (clamped between 0 and 100):

| Heuristic Indicator | Weight | Description & Security Rationale |
|:---|:---:|:---|
| **Insecure Transport (HTTP)** | +15 | Plaintext HTTP lacking TLS encryption; prone to interception. |
| **Direct IP Hostname** | +25 | Hostname specified as an IPv4 or IPv6 address rather than a domain name; common in drive-by malware. |
| **Authority Credentials (`@`)** | +25 | Embedded credentials before `@` (e.g. `google.com@evil.com`), used to mislead users regarding destination. |
| **Excessive URL Length** | +15 | Total character length exceeding 100 characters; often used to push malicious domains outside mobile address bars. |
| **Deep Subdomain Nesting** | +15 | Subdomain count &ge; 3; frequently observed in phishing kits imitating legitimate hierarchy. |
| **Known URL Shortener** | +20 | Domains such as `bit.ly`, `tinyurl.com`, `t.co` used to obfuscate final destinations. |
| **Suspicious Path / Host Keywords** | +20 | Presence of high-risk keywords (`login`, `verify`, `banking`, `security`, `update`, `wallet`, `2fa`, etc.). Path keywords alone are classified as contextual indicators. |
| **Suspicious Query Parameters** | +15 | Query strings containing credential harvesting flags (`redirect`, `return`, `token`, `password`). |
| **Punycode / IDN Homograph** | +25 | Host labels starting with `xn--`, indicating internationalized character sets commonly exploited in homograph attacks. |
| **Non-Standard Port** | +15 | Specified ports other than standard default web ports (Port 80 for HTTP, Port 443 for HTTPS). Port 8080 is explained as an alternative HTTP port without assuming malice. |

### Risk Categorization & Baseline Rules
- **Low Risk (0–29)**: Minimal suspicious indicators. Displayed with explicit clarification: *"No obvious suspicious patterns detected. This does not guarantee the URL is safe."*
- **Medium Risk (30–59)**: Multiple cautionary signals detected; warrants investigative caution.
- **High Risk (60–100)**: Critical threat indicators detected (e.g. Punycode + Direct IP + Embedded Auth).

---

## Scam Awareness Warning Engine

Fraud Link Detector includes an evidence-based **Scam Awareness Warning Engine** (`src/utils/warningEngine.ts`) that transforms structural observations and backend telemetry into actionable, plain-English advice.

### Security Warning Categories
1. **Known Threat (`known_threat`)**: Triggered when Google Safe Browsing confirms active malware or social engineering (Severity: `critical`, Confidence: `confirmed`).
2. **Phishing & Credential Theft (`phishing_credential_theft`)**:
   - *Strong Evidence*: Authority credentials before `@`, brand spoofing in subdomains, or confirmed threat matches produce high/critical severity warnings.
   - *Contextual Path Keywords*: Common authentication terms in paths (e.g., `/login`, `/verify`, `/banking`, `/wallet`) without host spoofing or authority credentials produce low-severity, informational findings (`warn-contextual-keywords`). These remind users to confirm the destination domain rather than asserting proof of phishing.
3. **Suspicious Redirect Behaviour (`suspicious_redirect`)**: Flags redirect loops, protocol downgrades, and excessive hops.
4. **New Domain Registration (`new_domain`)**: Flags domains registered $\le 30$ days ago based on RDAP registration records.
5. **Suspicious URL Structure (`suspicious_url_structure`)**: Flags direct numeric IPs, Punycode hostnames, and non-standard web ports.
6. **Inconclusive / Unavailable External Checks (`inconclusive_check`)**: Surfaces when threat feeds or RDAP registries are offline or unconfigured, explicitly noting that unavailable checks must never be interpreted as clean results.
7. **No Obvious Threats Detected (`no_obvious_threat`)**: Rendered when no heuristic rules are triggered, accompanied by a prominent non-guarantee disclaimer.

---

## API Reference

The backend Express service exposes the following endpoints:

### 1. Health Check
```http
GET /api/health
```
**Response (200 OK):**
```json
{
  "status": "ok",
  "service": "fraud-link-detector-api"
}
```

---

### 2. Google Safe Browsing Threat Check
```http
POST /api/threat-check
Content-Type: application/json
```
**Request Body:**
```json
{
  "url": "https://suspicious-domain.example/login"
}
```
**Response (Threat Detected - 200 OK):**
```json
{
  "configured": true,
  "isThreat": true,
  "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
  "evaluatedAt": "2026-10-26T20:50:00.000Z"
}
```
**Response (Unconfigured Environment - 200 OK):**
```json
{
  "configured": false,
  "status": "unconfigured",
  "message": "Threat intelligence service is not configured on this server."
}
```

---

### 3. DNS & Domain Reconnaissance
```http
POST /api/recon
Content-Type: application/json
```
**Request Body:**
```json
{
  "url": "https://example.com"
}
```
**Response (200 OK):**
```json
{
  "hostname": "example.com",
  "isIpAddress": false,
  "isSpecialUse": false,
  "dns": {
    "status": "resolved",
    "aRecords": ["93.184.215.14"],
    "aaaaRecords": ["2606:2800:21f:cb07:6820:80da:9e6b:47c"],
    "mxRecords": [],
    "aCount": 1,
    "aaaaCount": 1,
    "mxCount": 0,
    "hasMailExchange": false
  },
  "rdap": {
    "status": "available",
    "registrationDate": "1995-08-14T04:00:00Z",
    "domainAgeDays": 11396,
    "registrar": "RESERVED-Internet Assigned Numbers Authority"
  },
  "findings": [
    {
      "id": "recon-established-domain",
      "category": "domain_age",
      "severity": "neutral",
      "title": "Established Domain Age",
      "explanation": "Domain was registered 11396 days ago (~31.2 years ago). Well-established domains are historically less likely to be ephemeral phishing lures, but domain longevity does not guarantee safety."
    }
  ],
  "evaluatedAt": "2026-10-26T20:50:00.000Z"
}
```

---

### 4. Redirect Chain Inspection
```http
POST /api/redirect-chain
Content-Type: application/json
```
**Request Body:**
```json
{
  "url": "https://bit.ly/example-target"
}
```
**Response (200 OK):**
```json
{
  "initialUrl": "https://bit.ly/example-target",
  "finalDestination": "https://example.com/landing",
  "totalRedirects": 1,
  "status": "COMPLETED",
  "statusMessage": "Chain completed across 1 redirect(s).",
  "hops": [
    {
      "hopIndex": 1,
      "url": "https://bit.ly/example-target",
      "statusCode": 301,
      "statusText": "Moved Permanently",
      "locationHeader": "https://example.com/landing",
      "resolvedIp": "67.199.248.10",
      "isHttps": true,
      "serverHeader": "nginx",
      "durationMs": 142
    },
    {
      "hopIndex": 2,
      "url": "https://example.com/landing",
      "statusCode": 200,
      "statusText": "OK",
      "locationHeader": null,
      "resolvedIp": "93.184.215.14",
      "isHttps": true,
      "serverHeader": "ECS",
      "durationMs": 88
    }
  ],
  "findings": [
    {
      "id": "shortener-0",
      "severity": "info",
      "title": "URL Shortener Detected",
      "description": "Hop 1 uses known link shortener service (bit.ly)."
    }
  ],
  "inspectedAt": "2026-10-26T20:50:00.000Z"
}
```

---

### 5. Isolated Cloud Website Screenshot Preview
```http
POST /api/screenshot
Content-Type: application/json
```
**Request Body:**
```json
{
  "url": "https://example.com"
}
```
**Response (Success - 200 OK):**
```json
{
  "status": "success",
  "imageDataUri": "data:image/jpeg;base64,...",
  "capturedAt": "2026-10-26T20:50:00.000Z",
  "viewport": {
    "width": 1280,
    "height": 800
  }
}
```

---

## Visual Walkthrough

### 1. Main Dashboard (Pre-Scan State)
The primary landing interface prior to analysis, highlighting the URL input form, platform safety tips, and privacy badges (`"Local URL Analysis"` and `"Privacy-Focused Processing"`).

![Main Application Interface](docs/screenshots/dashboard-overview.png)

### 2. Heuristic Scan Results & Risk Breakdown
Transparent risk evaluation displaying the 0–100 heuristic score gauge, risk category, rule-by-rule indicator breakdown, and threat intelligence state.

![Heuristic Scan Results](docs/screenshots/scan-results.png)

### 3. SSRF-Hardened Redirect Chain Inspector
Hop-by-hop HTTP redirect inspection timeline displaying status codes, connection-pinned IP addresses, response latency, and security findings.

![Redirect Chain Inspection](docs/screenshots/redirect-inspector.png)

### 4. DNS & RDAP Domain Telemetry
Real-time infrastructure reconnaissance displaying domain registration age from ICANN RDAP, DNS record endpoints (A, AAAA, MX), and configuration observations.

![DNS and RDAP Telemetry](docs/screenshots/dns-rdap-recon.png)

---

## Installation & Getting Started

### Prerequisites
- **Node.js**: v20.x or higher (Node 22 LTS recommended)
- **npm**: v10.x or higher

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/fraud-link-detector.git
cd fraud-link-detector
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables (Optional)
Copy the example environment configuration:
```bash
cp .env.example .env
```
*(All features function out-of-the-box in local heuristic mode if no API key is provided).*

### 4. Start Development Server
```bash
npm run dev
```
Starts `tsx server.ts` with the Express API and Vite development middleware running on `http://localhost:3000`.

### 5. Production Build & Execution
```bash
# Build the production Vite bundle to dist/
npm run build

# Launch the production Express server
npm run start
```

### Available NPM Scripts
- `npm run dev`: Starts the local development server with Vite middleware (`tsx server.ts`).
- `npm run build`: Compiles production frontend bundle to `dist/` (`vite build`).
- `npm run start`: Runs production server with pre-built static assets (`NODE_ENV=production tsx server.ts`).
- `npm run lint`: Performs TypeScript type checking (`tsc --noEmit`).
- `npm test`: Runs all 126 automated unit and integration tests (`tsx --test ...`).
- `npm run clean`: Cleans build output directories (`rm -rf dist server.js`).

---

## Environment Configuration

Configuration variables defined in `.env.example`:

| Variable | Required | Default | Feature Dependency & Behavioral Effect |
|:---|:---:|:---:|:---|
| `PORT` | Optional | `3000` | HTTP port on which the Express server listens. |
| `NODE_ENV` | Optional | `development` | Set to `production` when running the pre-compiled bundle from `dist/`. |
| `TRUST_PROXY` | Optional | `1` | Controls Express reverse-proxy trust (`app.set('trust proxy', ...)`). Essential for accurate client IP identification under Cloud Run, Nginx, or load balancers to enforce per-IP rate limits. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Optional | None | API key for Google Safe Browsing Lookup API v4 (`threatMatches:find`). If omitted, `/api/threat-check` returns `configured: false`, and the application runs in offline structural heuristic mode. |
| `SCREENSHOT_API_KEY` | Optional | None | API key for external screenshot rendering via Microlink API. If omitted, the server uses Microlink's public free-tier. |

> **Security Note**: Never commit actual API keys or `.env` files containing secrets to version control.

---

## Testing & Verification

The project includes an automated test suite leveraging Node.js's native test runner (`node:test`) executed via `tsx`:

```bash
# Run all automated tests
npm test

# Run TypeScript type verification
npm run lint

# Execute production build verification
npm run build
```

### Verified Test Suite Summary
All **126 automated tests pass** across **11 dedicated test specifications**:
- `src/utils/urlParser.test.ts` (6 tests): RFC 3986 normalization, default ports, authority credential handling, Punycode parsing.
- `src/utils/riskEngine.test.ts` (8 tests): Deterministic scoring rules, threshold clamping, edge-case heuristic triggers.
- `src/utils/historyStorage.test.ts` (4 tests): Local storage persistence, LRU bounds, token and credential redaction.
- `src/server.test.ts` (20 tests): Express rate limiter, CORS policies, health check, and threat check route handling.
- `src/utils/threatStates.test.ts` (5 tests): Exact messaging contracts for Clean, Threat, Unconfigured, and Unavailable states.
- `src/server/dnsRecon.test.ts` (16 tests): Asynchronous DNS lookups, RDAP bootstrap queries, timeouts, and private IP isolation.
- `src/server/redirectInspector.test.ts` (15 tests): Multi-hop redirect limits, protocol downgrade alerts, SSRF defenses, loopback blocks, and connection pinning.
- `src/utils/clipboardUrl.test.ts` (12 tests): Safe user-triggered clipboard reading, permissions rejection handling, and embedded link extraction.
- `src/utils/shareTarget.test.ts` (9 tests): Android Web Share Target parameter parsing, candidate extraction, and query string cleanup.
- `src/server/screenshotService.test.ts` (11 tests): Remote visual preview, local pre-flight SSRF blocks, secondary URL validation, incremental streaming limits, and binary magic bytes validation.
- `src/utils/warningEngine.test.ts` (20 tests): Scam Awareness Warning Engine categories, contextual path-keyword classification, port 8080 wording, and regression verification for IP hosts with path keywords.

---

## Application Limitations & Constraints

To maintain realistic security expectations, the application enforces and discloses the following constraints:

1. **Heuristics Are Indicators, Not Guarantees**: A risk score of 0 or Low risk does not prove that a destination is safe. Novel phishing campaigns and compromised legitimate domains frequently exhibit standard technical structures.
2. **External Threat Checks Require Configuration**: Google Safe Browsing lookups require a valid server-side API key. In unconfigured environments, the app operates strictly in local structural heuristic mode.
3. **Unavailable Checks Must Not Be Treated as Clean**: If an external database, threat feed, or RDAP registry is temporarily unreachable, the application surfaces an "Inconclusive / Unavailable External Checks" finding.
4. **Headers-Only Redirect Analysis**: HTTP redirect inspection analyses server-side HTTP `Location` headers (max 5 hops). It does **not** download or execute client-side JavaScript, DOM redirections (`window.location`), or `<meta http-equiv="refresh">` tags.
5. **Screenshot Preview Privacy**: Remote screenshots are triggered strictly on-demand. When requested, the target URL is transmitted to Microlink API, which may temporarily cache public captures on its CDN.
6. **No Automatic Link Opening**: The application deliberately does not open or navigate to analyzed links in the user's browser, preventing accidental execution of drive-by exploits. Users must independently verify destinations.
7. **PWA Web Share Target Constraints**: Web Share Target support requires compatible operating systems and browsers (e.g., Chrome on Android). On unsupported platforms, users can use the on-demand clipboard inspector or manual paste.

---

## Responsible Disclosure & Security Guarantees

### Disclaimer
> **Important**: Fraud Link Detector is a heuristic analysis and investigative assistance tool. A clean scan or low risk score **does not guarantee that a URL is safe or free from malicious intent**. Always exercise sound judgment before entering credentials or executing downloads. This project has not been independently audited or certified by a third-party security firm.

### Reporting Vulnerabilities
If you identify a security flaw or vulnerability within this application (particularly regarding SSRF bypasses or parsing logic), please disclose it responsibly. Do not open public issues for zero-day vulnerabilities. Please submit a private security advisory through GitHub or contact the repository maintainers directly.

---

## License

This project is licensed under the [MIT License](LICENSE).
