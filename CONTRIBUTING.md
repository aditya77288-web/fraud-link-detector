# Contributing

Thank you for considering a contribution to Fraud Link Detector.

## Before you start

- Search existing issues and pull requests before proposing a duplicate change.
- For significant changes, open an issue first to discuss scope and security impact.
- Never include real credentials, API keys, personal data, or live malicious URLs containing active tokens in tests or screenshots.

## Local setup

1. Install Node.js 22 LTS and npm.
2. Clone the repository and install dependencies:

   ```bash
   git clone https://github.com/aditya77288-web/fraud-link-detector.git
   cd fraud-link-detector
   npm ci
   ```

3. Copy `.env.example` to `.env` (`cp .env.example .env` on macOS/Linux or `Copy-Item .env.example .env` in Windows PowerShell) and configure only the optional services you intend to test.
4. Start the development server:

   ```bash
   npm run dev
   ```

## Change expectations

- Keep pull requests focused and explain the user-visible or security benefit.
- Add regression tests for bug fixes.
- For network-related changes, cover private/special-use addresses, DNS errors, redirects, timeout behavior, and resource limits where relevant.
- Preserve the distinction between `clean`, `threat detected`, `unconfigured`, and `unavailable` external-service states.
- Document new outbound data flows, third-party services, environment variables, and privacy implications.
- Do not claim a security guarantee that the implementation cannot enforce.

## Before opening a pull request

Run all checks:

```bash
npm test
npm run lint
npm run build
```

In the pull request description include:

- Summary and motivation
- Files or components changed
- Tests added or updated
- Results of the three verification commands
- Security and privacy impact
- Known limitations or follow-up work

The GitHub Actions CI workflow runs the same automated tests, TypeScript check, and production build for pushes to `main` and pull requests targeting `main`.
