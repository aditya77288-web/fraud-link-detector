# Security Policy

## Supported versions

Security fixes are developed against the current default branch (`main`). Older commits and untagged snapshots may not receive fixes.

## Reporting a vulnerability

Please do not disclose an exploitable, unpatched vulnerability in a public issue or pull request.

Use GitHub's private vulnerability reporting feature for this repository if it is enabled. If private reporting is unavailable, contact the repository maintainer through their GitHub profile and request a private channel before sharing technical details.

Include, where safe:

- A concise description of the affected component and potential impact
- Reproduction steps or a minimal proof of concept
- The affected commit or branch
- Any suggested mitigation

Do not include real credentials, personal data, or third-party systems' private information.

## Scope

Areas of particular interest include:

- URL parsing, normalization, and credential handling
- SSRF protections and special-use IP classification
- DNS resolution, rebinding, and redirect connection pinning
- Redirect limits, request timeouts, and resource consumption
- Screenshot-provider URL validation and image retrieval
- API rate limiting, proxy trust configuration, and secret handling

## Response expectations

This is a portfolio project maintained on a best-effort basis. No formal response-time SLA or bug-bounty program is offered. Please allow reasonable time for acknowledgement and triage.

## Security limitations

Fraud Link Detector is an investigative aid, not a guarantee of safety. It has not been independently audited. Screenshot rendering is performed by an external provider; local pre-flight checks cannot guarantee how that provider resolves and connects to the target.
