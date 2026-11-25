# Safe Demo Guide

This walkthrough demonstrates the main investigation workflow without using live phishing links or opening suspicious destinations.

## 1. Start the application

Use Node.js 22 LTS and npm 10 or later.

```bash
git clone https://github.com/aditya77288-web/fraud-link-detector.git
cd fraud-link-detector
npm install
```

Copy the environment template:

- macOS / Linux: `cp .env.example .env`
- Windows PowerShell: `Copy-Item .env.example .env`

No API key is required for local URL parsing, heuristic scoring, or the basic dashboard. Optional provider keys are documented in the root README.

Start the development server:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## 2. Run a benign first scan

1. Enter `https://example.com` in the URL field.
2. Start the scan.
3. Review the local heuristic score, risk band, rule explanations, and any external-check status.
4. Keep in mind that a low score is not proof that a destination is safe.

The application is designed to analyze the submitted URL; it should not automatically navigate your browser to that destination.

## 3. Understand the analysis layers

- **Local URL analysis:** parsing, normalization, deterministic heuristics, and plain-English warnings run in the browser.
- **Safe Browsing:** requires `GOOGLE_SAFE_BROWSING_API_KEY`; without it, the UI should show an unconfigured state rather than a clean verdict.
- **DNS and RDAP:** requests domain infrastructure and registration information from external services.
- **Redirect inspection:** makes bounded HTTP requests to inspect server-side redirect headers.
- **Screenshot preview:** sends the URL to the configured external screenshot provider only when the preview is explicitly requested.

Only use domains you own or are authorized to test when exercising network-dependent features. Do not submit live malicious links, private URLs, credentials, or personal tokens to third-party services.

## 4. Check API health

With the development server running, open [http://localhost:3000/api/health](http://localhost:3000/api/health) or run:

```bash
curl http://localhost:3000/api/health
```

Windows PowerShell:

```powershell
Invoke-RestMethod http://localhost:3000/api/health
```

A healthy local API responds with a JSON status of `ok`.

## 5. Run project verification

```bash
npm test
npm run lint
npm run build
```

For a production-mode local run:

```bash
npm run build
npm run start
```

The start and clean scripts are designed to work across Windows, macOS, and Linux.

## 6. Portfolio screenshots

The root README includes the committed screenshots for the dashboard, scan results, redirect inspector, and DNS/RDAP reconnaissance. Use screenshots from your own current build if the interface changes; never present synthetic results as live threat-intelligence findings.

## Important limitations

Fraud Link Detector is an investigative aid, not a guarantee of safety or a replacement for browser, endpoint, or network security controls. External services can be unconfigured, unavailable, incomplete, or subject to their own privacy and retention policies. Screenshot-provider pre-flight checks cannot guarantee how the provider itself resolves and connects to a target.
