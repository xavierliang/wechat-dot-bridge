# Protocol and reliability contract — v0.3

This implementation is single-owner, single-bot, text-only. Production codepaths exist, but only synthetic/local tests have executed. A real account, TLS deployment, external OAuth client, host subscription and dot round-trip remain acceptance gates.

## MCP and authorization

Protocol version is `2026-07-28`. `/mcp` supports stateless JSON responses to POST requests. Required per-request `_meta` protocol version and client capabilities are checked; `MCP-Protocol-Version` and `Mcp-Method` must mirror the body, and `Mcp-Name` must match tools/call. Responses carry `resultType: complete`. Discovery/tool lists are private and noncacheable (`ttlMs:0`). GET/DELETE return 405. Invalid Origin is rejected. MCP1 initialize/streaming-session compatibility is not implemented or claimed.

OAuth bearer authentication applies to discovery, tools and events. RFC9728 public metadata identifies the external authorization server. The real issuer, audience and owner subject are exact matches; jose verifies asymmetric JWT signatures using an operator-provided public JWKS. Admin and ordinary MCP scopes are separate. Local revocation state is checked per request; failed/missing/Promise-truthiness authorization cannot grant access. No OAuth authorization server or live host/client registration is invented.

QR request and scanner identity are tied to that verified owner. The scanner is not trusted until a second authenticated owner confirmation specifies its exact ID. Sensitive QR data is available only on a no-store admin route; bot credentials never enter MCP results. Tokens/keys are not included in logs or error text.

## Bootstrap and owner UI

An empty callback hostname allowlist is a supported preparation state. Verified MCP discovery, tool/event listings, status and optional web admin login remain available. Subscribe, reply, callback delivery and message polling refuse to run. A later allowlist change requires restart and can resume an existing valid binding. Persisted subscriptions are rechecked against the current exact allowlist before sending. DNS pinning, public-address checks, HTTPS validation and redirect rejection remain unchanged.

The optional `/admin` UI uses a confidential Authorization Code + PKCE client with fixed `/admin/oauth/callback`, state/nonce, issuer and owner validation, one-use CSRF forms and server-only bearer tokens. QR creation, status polling, exact scanner confirmation, revoke and local logout require authenticated POST forms. Logout cancels waiting work and acknowledges only after dispatched mutations drain; a previously committed binding remains until explicit revoke. See AUTH.md for lifetimes, limitations and client settings.

## Events and sending

Event name: `wechat.message.received`. Filter: exact bound sender ID. Data: message ID, deterministic bot/sender thread ID, sender ID, untrusted text. Context tokens stay server-side. MCP replay is unsupported (`cursor:null`); this is separate from the durable iLink upstream cursor. Active-subscription events enter the outbox atomically with the inbox/cursor snapshot. New subscriptions do not replay the old inbox.

The event ID is stable across retries. A 2xx webhook response acknowledges receipt only. Attempts are persisted before send; crashes can consume attempts. Retry at most five times with bounded exponential backoff; 410 cancels the subscription, 413 and nontransient client errors are terminal. Unsubscribe/expired recreation cannot revive old jobs. Callback challenges are unique/short-lived; successful owner/URL/key verification is cached for five minutes. Rotation double-signs with old/new keys for five minutes, including idempotent refreshes.

Replies use existing inbound message IDs, never arbitrary destinations. Stable owner-scoped idempotency keys are fingerprinted canonically. The unknown state is persisted before each first send; a lost acknowledgement or pre-send crash is never blindly retried. Sent/unknown ledgers and hashed seen-message IDs survive unlink/relink. Returning an old idempotency result does not send again, even when the original context has been removed. Exactly-once Tencent semantics are not assumed from `client_id`.

## Storage, crash and resource bounds

AES-256-GCM encrypts all state using an externally supplied key. Snapshot writes are serialized, fsynced, renamed atomically and directory-fsynced. A save error poisons the instance. A separate SQLite exclusive transaction owns the directory for process lifetime; OS crash cleanup releases it. Tests verify hard-killed child recovery. This is not a distributed lock; one bot must map to one directory/process on a reliable local filesystem.

Authorization filtering precedes content validation. Invalid/oversized allowed-owner content is recorded in bounded metadata-only quarantine, with valid peers and upstream cursor committed normally. Structurally broken adapter batches fail closed and halt runtime instead of infinite replay. Resource caps are explicit in DEPLOYMENT.md. No silent tombstone pruning is used to extend capacity.

## Network protections and scope

Callback and iLink destinations use separate exact-host allowlists. Outbound HTTPS validates all DNS answers before each connection and pins a public IPv4 address while preserving original hostname/SNI and certificate verification. Redirects, literal-IP URLs, credentials in URLs, private/reserved addresses, non-443 ports and all IPv6 are rejected. IPv6 and conservative reserved-range rejection can limit connectivity. Transport deadlines include DNS; iLink longpoll has its own bounded timeout and cancellation.

The actual HTTP server enforces TLS socket state, exact Host, body/header/concurrency bounds, deadlines and no query-token routes; it does not trust forwarding headers. Transport tests inject a fake request implementation and verify options, rebinding rejection and cancellation; real network TLS sockets have not been exercised.

The current iLink adapter deliberately accepts only completed user text with safe integer message IDs, valid context and matching bot receiver. This conservative profile requires validation against actual Tencent behavior. It does not implement media, groups, silent credential refresh or automatic trust of redirected hosts.

Sources: [MCP HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [OpenAI Events](https://developers.openai.com/plugins/build/mcp-events), [OpenAI Auth](https://developers.openai.com/plugins/build/auth), [Tencent protocol](https://github.com/Tencent/openclaw-weixin/blob/main/docs/protocol.md).
