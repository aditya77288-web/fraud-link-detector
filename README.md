# Fraud Link Detector

[![Tests](https://img.shields.io/badge/tests-70%20passing-brightgreen.svg)](#testing--verification)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19.0-61dafb.svg)](https://react.dev/)
[![Express](https://img.shields.io/badge/Express-4.21-lightgrey.svg)](https://expressjs.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An open-source, full-stack cybersecurity investigation workbench for analyzing suspicious links, deceptive URLs, and phishing lures. **Fraud Link Detector** combines client-side deterministic URL heuristics with hardened server-side reconnaissance—including Google Safe Browsing intelligence, asynchronous DNS and RDAP registry telemetry, and an SSRF-hardened, hop-by-hop HTTP redirect chain inspector.

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
- [API Reference](#api-reference)
- [Visual Walkthrough](#visual-walkthrough)
- [Installation & Getting Started](#installation--getting-started)
- [Environment Configuration](#environment-configuration)
- [Testing & Verification](#testing--verification)
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

**Fraud Link Detector** addresses this by providing layered, defense-in-depth telemetry without ever opening, rendering, or executing untrusted user-supplied web pages.

---

## Architecture Overview

Fraud Link Detector is designed as a hybrid client-server application:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER (React 19)                         │
│  - Instant, offline deterministic heuristic evaluation (0–100 score)   │
│  - RFC 3986 URL parsing & authority/credential extraction              │
│  - Redacted local scan history & category risk breakdown               │
└────────────────┬───────────────────┬───────────────────┬───────────────┘
                 │                   │                   │
      POST /api/threat-check    POST /api/recon     POST /api/redirect-chain
                 │                   │                   │
┌────────────────▼───────────────────▼───────────────────▼───────────────┐
│                    BACKEND LAYER (Express 4 on Node.js)                │
│  - In-memory rate limiting (60 req/min per IP)                         │
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
└─────────────────────┴─────────────────────┴────────────────────────────┘
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
- [x] **Safe Browsing Threat Intelligence**: Optional Google Safe Browsing v4 API integration via server-side `POST /api/threat-check`. Operates in graceful unconfigured mode when `GOOGLE_SAFE_BROWSING_API_KEY` is not present.
- [x] **DNS Reconnaissance**: Concurrent lookups of `A`, `AAAA`, and `MX` records with individual 3-second timeouts via `node:dns/promises`.
- [x] **Domain Age & RDAP Analysis**: Automated query to ICANN bootstrap RDAP services to resolve domain registration age, registrar name, and creation timestamps.
- [x] **SSRF-Protected Redirect Chain Inspector**: Hop-by-hop redirect analysis (maximum 5 hops) using `HEAD` requests (with zero-body `GET` fallback).
- [x] **DNS Rebinding & Connection Pinning**: Sockets explicitly pinned to pre-validated IP addresses via a custom HTTP/HTTPS agent lookup handler to eliminate Time-of-Check to Time-of-Use (TOCTOU) exploits.
- [x] **Protocol Downgrade Detection**: Flags redirects transitioning from `https://` to insecure `http://`.
- [x] **Sensitive Parameter Redaction**: Strips passwords, auth tokens, session IDs, and JWTs from local history storage and inspected hop locations.
- [x] **In-Memory Rate Limiting**: Global sliding window protection (60 requests per minute per IP address).
- [x] **Automated Test Suite**: 70 automated unit and integration tests covering parser logic, risk engine rules, SSRF bypasses, and API contracts.

### 2. Partially Implemented Features

- [ ] **RDAP Registry Coverage**: RDAP parsing supports standard ICANN gTLDs and major ccTLDs; unsupported ccTLDs that lack public RDAP endpoints report as registry-unavailable without failing the scan.
- [ ] **Google Safe Browsing Offline Cache**: Safe Browsing queries are executed on-demand per request; persistent local hash prefix caching is not currently implemented.

### 3. Planned Features

- [ ] **Clipboard Auto-Detection**: One-click URL inspection triggered automatically from system clipboard paste events.
- [ ] **Native Mobile Web Share Target**: PWA share target integration allowing links from messaging applications to be routed directly to the detector.
- [ ] **Visual Threat Card Export**: Exporting downloadable or shareable incident summary cards (PNG/PDF) for security operations and end-user education.
- [ ] **Sandboxed DOM / Visual Comparison**: Headless, isolated browser screenshotting to compare brand logos against declared domains (deliberately omitted from current backend to maintain zero attack surface).

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
- No response bodies are buffered into memory.
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
| **Suspicious Path / Host Keywords** | +20 | Presence of high-risk keywords (`login`, `verify`, `banking`, `security`, `update`, `wallet`, `2fa`, etc.). |
| **Suspicious Query Parameters** | +15 | Query strings containing credential harvesting flags (`redirect`, `return`, `token`, `password`). |
| **Punycode / IDN Homograph** | +25 | Host labels starting with `xn--`, indicating internationalized character sets commonly exploited in homograph attacks. |
| **Non-Standard Port** | +15 | Specified ports other than standard default web ports (Port 80 for HTTP, Port 443 for HTTPS). |

### Risk Categorization & Baseline Rules
- **Low Risk (0–29)**: Minimal suspicious indicators. Displayed with explicit clarification: *"No obvious suspicious patterns detected. This does not guarantee the URL is safe."*
- **Medium Risk (30–59)**: Multiple cautionary signals detected; warrants investigative caution.
- **High Risk (60–100)**: Critical threat indicators detected (e.g. Punycode + Direct IP + Embedded Auth).

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
    },
    {
      "id": "recon-dns-resolved",
      "category": "dns",
      "severity": "info",
      "title": "Active DNS Resolution",
      "explanation": "Domain resolves to 1 IPv4 endpoint(s) and 1 IPv6 endpoint(s)."
    },
    {
      "id": "recon-mx-missing",
      "category": "dns",
      "severity": "neutral",
      "title": "No Mail Exchange (MX) Records",
      "explanation": "No MX records were found for this domain. Many legitimate web-only services do not configure email routing; missing MX records do not indicate malicious intent."
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
    },
    {
      "id": "domain-change-1",
      "severity": "info",
      "title": "Domain Transition",
      "description": "Redirect transferred from bit.ly to example.com."
    }
  ],
  "inspectedAt": "2026-10-26T20:50:00.000Z"
}
```

---

## Visual Walkthrough

### 1. Main Dashboard (Pre-Scan State)
The primary landing interface prior to analysis, highlighting the URL input form, platform safety tips, and client-side zero-telemetry privacy guarantee.

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
*(Google Safe Browsing is optional. The application functions out-of-the-box in local heuristic mode if no API key is provided).*

### 4. Start Development Server
```bash
npm run dev
```
The application will start on `http://localhost:3000` with the Express API and Vite middleware running concurrently.

### 5. Production Build & Execution
```bash
# Build the production Vite bundle
npm run build

# Launch the production Express server
npm run start
```

---

## Environment Configuration

Configuration variables defined in `.env.example`:

| Variable | Required | Description |
|:---|:---:|:---|
| `PORT` | Optional | Backend HTTP listener port (defaults to `3000`). |
| `NODE_ENV` | Optional | Runtime environment (`development` or `production`). |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Optional | API key for Google Safe Browsing Lookup API v4. If omitted, the app marks Safe Browsing as unconfigured and continues running local heuristics and reconnaissance. |

> **Security Note**: Never commit real API keys or `.env` files containing secrets to version control.

---

## Testing & Verification

The project includes a comprehensive automated test suite leveraging Node.js's native test runner (`node:test`) executed via `tsx`:

```bash
# Run all automated tests
npm test

# Run TypeScript type verification
npm run lint

# Execute production build verification
npm run build
```

### Verified Test Suite Summary
All 70 automated tests pass across 7 dedicated test specifications:
- `src/utils/urlParser.test.ts`: RFC 3986 normalization, authority credential handling, Punycode parsing, port differentiation.
- `src/utils/riskEngine.test.ts`: Deterministic scoring rules, threshold clamping, edge-case heuristic triggers.
- `src/utils/historyStorage.test.ts`: Local storage persistence, LRU bounds, token and credential redaction.
- `src/utils/threatStates.test.ts`: Exact messaging contracts for Clean, Threat, Unconfigured, and Unavailable states.
- `src/server.test.ts`: Express rate limiter, CORS policies, health check, and threat check route handling.
- `src/server/dnsRecon.test.ts`: Asynchronous DNS lookups, RDAP bootstrap queries, timeouts, and private IP isolation.
- `src/server/redirectInspector.test.ts`: Multi-hop redirect limits, protocol downgrade alerts, SSRF defenses, loopback blocks, and connection pinning.

---

## Responsible Disclosure & Security Guarantees

### Disclaimer
> **Important**: Fraud Link Detector is a heuristic analysis and investigative assistance tool. A clean scan or low risk score **does not guarantee that a URL is safe or free from malicious intent**. Phishing actors frequently employ zero-day landing pages, polymorphic redirect cloaking, and compromised infrastructure that have not yet been flagged by threat intelligence feeds. Always exercise sound judgment before entering credentials or executing downloads.

### Reporting Vulnerabilities
If you identify a security flaw or vulnerability within this application (particularly regarding SSRF bypasses or parsing logic), please disclose it responsibly. Do not open public issues for zero-day vulnerabilities. Please submit a private security advisory through GitHub or contact the repository maintainers directly.

---

## License

This project is licensed under the [MIT License](LICENSE).
