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

## Owner web admin and bootstrap — v0.3, 2026-10-01

- Verified official Node.js v24.19.0 archive against the distribution SHA-256 manifest; no runtime installed on the production server.
- All 131 automated tests passed with Node 24.19.0, including all original 94 tests and 37 additional tests. No warning suppression was needed on the supported runtime.
- New tests exercise the actual pinned openid-client library against an injected synthetic IdP with ephemeral RS256 keys: discovery, confidential Basic code exchange, S256, ID-token/JWKS validation, API-token verification, wrong nonce/state/owner/audience/issuer/scope, expiry and replay rejection.
- UI tests cover secure session rotation, CSRF/Origin checks, local QR rendering, exact scanner confirmation, wrong-account/reused-request refusal, revoke, logout/token-exchange/QR/confirmation races, session revocation, HTML escaping and bounded anonymous-session pressure.
- Bootstrap tests cover empty/missing callback hosts, malformed host rejection, authenticated discovery/status, refusal of subscribe/send/poll/delivery and a persisted subscription whose host was removed. Existing SSRF/TLS/DNS checks remain enabled.
- Source syntax checks and offline demo passed; demo reports zero real network requests and zero real WeChat messages sent.
- A fresh isolated directory reproduced `npm ci --offline --ignore-scripts`, source checks, all 131 tests and the offline demo under Node 24.19.0.
- The exact 45-file publication tree was scanned for credential literals, private account/host paths, real tenant identifiers, runtime state, generated output and archives; none were present.
- npm audit reported zero known vulnerabilities for the pinned dependency tree at this check. This does not establish absence of vulnerabilities.

Independent read-only review found and verified corrections for anonymous-session capacity lockout, initiating-login-page CSP and logout racing with a delayed binding confirmation. Final code review found no remaining concrete P0/P1/P2 in scope. The reviewer independently ran 64 targeted tests and the full suite successfully; separate queued-confirmation and cancellation-during-onBind probes left binding empty and the service usable. Documentation review also corrected callback-query leakage through Nginx error logs and inherited proxy caching in the future deployment template.

No actual Auth0 client, grant, login, token, QR, gateway listener, proxy switch or server change was performed for v0.3. Browser execution, real Auth0 tenant compatibility, CDN/proxy behavior, Docker execution and the actual ChatGPT/WeChat round-trip remain unverified. Sustained anonymous traffic can expire/evict pending login transactions; authenticated sessions are not evicted to admit anonymous entries. All fixture identities, codes, QR content, keys and tokens are synthetic; no fixture bearer token is printed or written to disk.

## Admin login diagnostics review — 2026-10-02

- Reproduced the pending diagnostic patch's 155 passing tests under Node.js v24.19.0. Added five rejection tests for expired callback sessions, provider denial with incorrect state, ID-token issuer/audience and API-token issuer; all 160 tests passed.
- Reviewed the authentication diff against the previous implementation: signature, issuer, audience, token type, owner subject, timestamps, scope and revocation checks remain required. No account or authorization policy was changed.
- Failure pages show a random diagnostic ID. Server diagnostics contain only time, a fixed event name, allowlisted stage/reason and that ID. Exceptions, response bodies, identity values, tokens, cookies, codes and callback URLs are not serialized. Synthetic rejection tests check classification and redaction together; state failures do not reach the token endpoint.
- Source syntax checks and the offline demo passed. The syntax-check runner now decodes file URLs correctly for checkout paths containing spaces.
- These are code-review and offline-validation results. They do not establish a successful production owner login, QR binding, MCP subscription or WeChat reply loop. The diagnostic deployment still requires a real owner login to identify the current failure.

## Owner login acceptance and QR form policy — 2026-10-02

- A production diagnostic identified a database-versus-Google owner mismatch. After explicit owner approval, the operator backed up configuration and encrypted state, migrated only the owner in the configuration and otherwise-empty state, and restarted only the bridge. Revocation data and other services were preserved; authentication checks were not weakened.
- A real Safari login through Auth0 and the approved Google identity reached the authenticated management status page. The page reported `unlinked` and `awaiting_callback_configuration`. This establishes administrative login, including resource-token validation, but not WeChat binding or MCP connectivity.
- The QR form regression reproduced `no-referrer` on successful action pages. All query-free management form documents now use `same-origin`, including the pending-operation view; callbacks, redirects, errors and JSON APIs retain `no-referrer`.
- All 162 automated tests and source syntax checks passed under Node.js v24.19.0. The added tests cover a complete synthetic native-form-origin chain through QR creation, challenge, poll, confirmation, revoke and logout, plus continued rejection of missing/null/cross-site Origin, invalid CSRF and query-bearing form URLs.
- The tests used synthetic QR and identity fixtures. No real QR creation, scan, binding, WeChat message or dot event was performed for these validation results. Public QR/MCP routes remain closed pending the separate binding and integration approvals.
