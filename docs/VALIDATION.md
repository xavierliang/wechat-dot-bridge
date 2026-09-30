# Original package validation — v0.2, 2026-09-30

## Passed

- Node.js v24.19.0
- 94 automated tests passed, 0 failed
- All source modules passed Node syntax checking
- Clean new directory: `npm ci --ignore-scripts --no-audit --no-fund`, syntax checks and all 94 tests passed
- Real jose verification of a fixed synthetic EC JWT, plus rejection of tampered, expired, wrong-owner/issuer/audience fixtures
- Synthetic full application flow: QR request → scanned candidate → exact authenticated owner confirmation → iLink poll → MCP event → read/reply → revocation
- Restart persistence, same-bot relinking without duplicate sends, in-flight QR revocation race, and hard-killed child process lock recovery
- DNS rebinding/private addresses, TLS/SNI options via injected request implementation, redirects, cancellation, streaming-body bounds, signing and error redaction
- `node test/demo.mjs`: zero real network requests and zero real WeChat messages sent
- Plugin manifest validation passed
- npm audit reported zero known dependency vulnerabilities at this check; this is not a guarantee of security

An independent read-only review found four v0.2 issues (poison-message cursor blocking, argument-order idempotency mismatch, relink loss of send tombstones, and revocation during pending QR creation). All were corrected with regression coverage. Reviewer independently reran the final 94 tests, all-source syntax checks and offline demo, finding no unresolved concrete P0/P1/P2 within the reviewed scope.

## Not performed / not established

- Docker/Compose build or fresh container execution: Docker is not installed in this authoring environment
- Real TLS socket/certificate deployment: request internals and handler behavior were tested with mocks, not a public listener
- Real Tencent QR login, account binding, credentials, polling or messages
- Real external IdP/client provisioning or token issuance; all cryptographic test identities/keys are synthetic and unsuitable for use
- Real ChatGPT/dot OAuth connection, plugin installation, MCP discovery/subscription callback or message round-trip
- Public/private repository publication, server deployment, ongoing account access or user data transmission
- Static TypeScript checks: source is JavaScript
- Production load, distributed deployment, media/group support or unbounded retention

The original source archive retains the recorded local test and demo results. Generated result files are excluded from the public source tree because they can contain authoring-environment paths. Reproduce the checks with the commands in the README. The package is ready for server configuration and controlled integration testing, not a claim that production acceptance is complete.

## Publication checks — 2026-09-30

The publication tree contains source, synthetic tests, configuration templates,
and documentation only. Generated test/demo output was removed; ignore rules
exclude it, logs and archives. No production configuration or credentials are
included. The runtime source and synthetic tests are unchanged from the archive.

Supplemental checks on a separate Mac used its existing Node.js v22.19.0:
source syntax passed; the first test run passed 93/94, with the crash-recovery
test failing only because Node's experimental SQLite warning appeared on child
stderr. With `NODE_NO_WARNINGS=1`, all 94 tests passed and the offline demo
reported zero real network requests and zero real WeChat messages. Node 22 is
below this project's supported runtime and these checks do not replace Node 24
validation. A fresh Node 24 download timed out and the local Docker daemon was
unavailable; fresh Node 24 and container validation remain deployment gates.
