# Fraud Link Detector

[![CI](https://github.com/aditya77288-web/fraud-link-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/aditya77288-web/fraud-link-detector/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-7.x-blue.svg)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19.0-61dafb.svg)](https://react.dev/)
[![Express](https://img.shields.io/badge/Express-4.21-lightgrey.svg)](https://expressjs.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A full-stack cybersecurity portfolio project for investigating suspicious links, deceptive URLs, and potential phishing lures. **Fraud Link Detector** combines client-side deterministic URL heuristics with server-side reconnaissance—including optional Google Safe Browsing intelligence, DNS and RDAP telemetry, an SSRF-conscious HTTP redirect inspector, an evidence-based Scam Awareness Warning Engine, and an on-demand cloud screenshot preview. The project emphasizes transparent findings, privacy disclosures, defensive network controls, and testable security behavior.

---

## Table of Contents

- [Project at a Glance](#project-at-a-glance)
- [Problem Statement](#problem-statement)
- [Architecture Overview](#architecture-overview)
- [Data Flow & Privacy](#data-flow--privacy)
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
- [Quick Demo Guide](#quick-demo-guide)
- [Installation & Getting Started](#installation--getting-started)
- [Vercel Serverless Deployment](#vercel-serverless-deployment)
- [Environment Configuration](#environment-configuration)
- [Testing & Verification](#testing--verification)
- [Application Limitations & Constraints](#application-limitations--constraints)
- [Contributing](#contributing)
- [Security Reporting](#security-reporting)
- [License](#license)

## Project at a Glance

| Area | Details |
|:---|:---|
| Application type | React + TypeScript frontend with an Express API |
| Primary purpose | Investigate suspicious URLs without opening them in the user's browser |
| Local analysis | Deterministic URL parsing, heuristic scoring, and plain-English warnings |
| Server-side analysis | Optional Safe Browsing lookup, DNS/RDAP reconnaissance, redirect inspection, and screenshot preview |
| Defensive focus | URL validation, SSRF controls, DNS pinning for redirect requests, timeouts, rate limits, and sensitive-value redaction |
| Verification | Automated Node.js tests, TypeScript type-checking, and production build in GitHub Actions |
| License | MIT |

**Project status:** Active development. This is an investigative aid, not a replacement for endpoint protection, a browser security product, or a professional security assessment. The project has not received an independent third-party security audit.

**Documentation:** [Architecture](docs/ARCHITECTURE.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

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
│  - In-memory rate limiting (60 req/min for API checks, 15 for photo) │
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

For a maintained data-flow diagram and component boundaries, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The screenshot feature uses an external rendering provider; local pre-flight checks reduce risk but cannot pin the provider's eventual connection to the submitted destination.

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
- [x] **Safe Browsing Threat Intelligence**: Optional Google Safe Browsing v5 API integration via server-side `GET /api/threat-check`. Operates in graceful unconfigured mode when `GOOGLE_SAFE_BROWSING_API_KEY` is not present.
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
- [x] **Automated Test Suite**: 147 automated unit and integration tests across 12 test suites covering parser logic, risk engine rules, warning engine classifications, SSRF bypasses, API contracts, clipboard parsing, share targets, screenshot rendering, and Vercel serverless API routing.

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

## Data Flow & Privacy

The application uses different processing paths depending on which analysis features are requested:

| Feature | Where processing occurs | External data flow |
|:---|:---|:---|
| URL parsing and heuristic score | User's browser | No reputation request is required for this local step |
| Scan history | User's browser storage | Sensitive URL values are redacted before persistence |
| Google Safe Browsing | Express server | When configured, the submitted URL is sent to Google Safe Browsing |
| DNS and RDAP reconnaissance | Express server | DNS queries and RDAP requests are made to resolve domain infrastructure and registration data |
| Redirect inspection | Express server | The server makes bounded HTTP requests to the submitted host and redirect destinations |
| Screenshot preview | External rendering provider | Only on explicit request; the target URL is sent to Microlink for rendering |

Important privacy and safety details:

- Clipboard access is user-triggered; the application does not continuously monitor the clipboard.
- Shared links and clipboard candidates require user confirmation before scanning.
- The application does not automatically open the submitted URL in the user's browser.
- API responses use `Cache-Control: no-store`.
- Optional API keys must remain server-side and must never be committed.
- A screenshot request is not local-only: the target URL is sent to the configured external screenshot provider. Review that provider's terms and privacy policy before enabling this feature in a deployment.

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
    "width": 1290,
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

## Quick Demo Guide

For a safe end-to-end walkthrough—from local setup and a first scan to API health checks and verification—see [docs/DEMO.md](docs/DEMO.md).

---

## Installation & Getting Started

### Prerequisites
- **Node.js**: Node 22 LTS (the CI workflow uses Node 22; use a Vite 8-supported Node release)
- **npm**: v10 or later

### 1. Clone the Repository
```bash
git clone https://github.com/aditya77288-web/fraud-link-detector.git
cd fraud-link-detector
```

### 2. Install Dependencies
```bash
npm ci
```

### 3. Configure Environment Variables (Optional)
Copy the example environment configuration.

**macOS / Linux:**
```bash
cp .env.example .env
```

**Windows PowerShell:**
```powershell
Copy-Item .env.example .env
```
Local heuristic analysis works without external API keys. Safe Browsing and screenshot previews require their respective optional server-side keys for configured provider access. The server loads `.env` at startup.

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
- `npm run start`: Runs the production server with pre-built static assets. `cross-env` makes the `NODE_ENV=production` setting work consistently on Windows, macOS, and Linux.
- `npm run lint`: Performs TypeScript type checking (`tsc --noEmit`).
- `npm test`: Runs all 147 automated unit and integration test cases across 12 test specifications (`tsx --test ...`).
- `npm run clean`: Removes generated `dist/` and `server.js` outputs using a cross-platform Node.js script.

---

## Vercel Serverless Deployment

Fraud Link Detector is fully compatible with Vercel's Node.js Serverless architecture while preserving standalone Express execution for local development and traditional container environments.

### Deployment Architecture on Vercel
1. **Frontend Static Assets**: Vercel compiles the React SPA via `npm run build` (`vite build`) and deploys the optimized output directory (`dist/`) directly to Vercel's global Edge Network.
2. **Serverless API Functions**: The Express application is exported from `api/[...route].ts` (catch-all serverless function capturing all `/api/*` endpoints with natural pathname preservation) and `api/index.ts` (handling the `/api` root and discovery endpoint), powered by the modular factory in `src/server/app.ts`. Express does not invoke `app.listen()` when executed in a serverless environment.
3. **Unified Routing (`vercel.json`)**:
   - Catch-all serverless routing naturally matches `/api/*` without destructive path rewrites.
   - Non-API routes match `/((?!api(?:/|$)).*)` and fall back to `/index.html` for client-side SPA handling.
   - Express mounts routes strictly once at `/api` and receives the true endpoint pathname.

### Configuring Environment Variables in Vercel
In your Vercel project dashboard, navigate to **Settings > Environment Variables** to configure optional keys:

| Variable | Description | Recommended Scope |
|:---|:---|:---|
| `GOOGLE_SAFE_BROWSING_API_KEY` | *(Optional)* Google Safe Browsing Lookup API v5 key for malware/phishing queries. | Production, Preview, Development |
| `SCREENSHOT_API_KEY` | *(Optional)* Microlink API key for website screenshots. | Production, Preview, Development |
| `TRUST_PROXY` | Set to `1` or `true` so Express recognizes Vercel's reverse proxy and extracts real client IPs for rate limiting. | Production, Preview, Development |

> **Security Note**: Environment variables in Vercel are kept strictly server-side in the Node.js Serverless runtime. They are never prefixed with `VITE_` and are never bundled into client-side JavaScript.

---

## Environment Configuration

Runtime configuration variables (the `.env.example` file contains the supported application settings):

| Variable | Required | Default | Feature Dependency & Behavioral Effect |
|:---|:---:|:---:|:---|
| `PORT` | Optional | `3000` | HTTP port on which the Express server listens. |
| `NODE_ENV` | Optional | `development` | Set to `production` when running the pre-compiled bundle from `dist/`. |
| `TRUST_PROXY` | Optional | `1` in code; `.env.example` sets `false` for local use | Controls Express reverse-proxy trust. Set to `1` only behind exactly one trusted proxy hop; use `false` when directly exposed. Incorrect settings can undermine IP-based rate limiting. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Optional | None | API key for Google Safe Browsing Lookup API v5 (`GET /v5/urls:search`). If omitted, `/api/threat-check` returns `configured: false`, and the application runs in offline structural heuristic mode. |
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
The repository currently defines **147 test cases** across **12 dedicated test specifications**. The CI workflow runs the complete suite on each push and pull request; use the CI status badge above as the current pass/fail source:
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
- `src/utils/warningEngine.test.ts` (23 tests): Scam Awareness Warning Engine categories, contextual path-keyword classification, port 8080 wording, and regression verification for IP hosts with path keywords.
- `src/server/vercelApi.test.ts` (18 tests): Vercel Serverless Function entrypoint exports without `listen()`, `vercel.json` routing configuration, `/api` root discovery, natural path routing across all 5 endpoints (`/api/health`, `/api/threat-check`, `/api/recon`, `/api/redirect-chain`, `/api/screenshot`), path normalization, defensive subpath recovery, security headers, rate limiting, and 400 error responses for malformed inputs.

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

## Contributing

Contributions are welcome. Before opening a pull request:

1. Open or review an issue describing the bug or proposed change.
2. Keep changes focused and avoid adding external services or collecting user data without documenting the privacy impact.
3. Add or update tests for behavior changes, especially URL parsing, network boundaries, timeouts, and error states.
4. Run the local verification commands (`npm test`, `npm run lint`, and `npm run build`).
5. Describe the threat model, test evidence, and any known limitations in the pull request.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.

---

## Security Reporting

Please do not publish exploit details for an unpatched vulnerability in a public issue. Follow the private reporting guidance in [SECURITY.md](SECURITY.md).

### Disclaimer
> **Important**: Fraud Link Detector is a heuristic analysis and investigative assistance tool. A clean scan or low risk score **does not guarantee that a URL is safe or free from malicious intent**. Always exercise sound judgment before entering credentials or executing downloads. This project has not been independently audited or certified by a third-party security firm.

### Reporting Vulnerabilities
If you identify a security flaw or vulnerability within this application (particularly regarding SSRF, DNS handling, redirect inspection, or URL parsing), please follow the private disclosure process in [SECURITY.md](SECURITY.md).

---

## License

This project is licensed under the [MIT License](LICENSE).
