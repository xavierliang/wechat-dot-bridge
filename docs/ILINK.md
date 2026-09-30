# iLink adapter and owner binding

Implemented against Tencent's public [protocol](https://github.com/Tencent/openclaw-weixin/blob/main/docs/protocol.md), [API source](https://github.com/Tencent/openclaw-weixin/blob/main/src/api/api.ts), and [QR source](https://github.com/Tencent/openclaw-weixin/blob/main/src/auth/login-qr.ts), inspected 2026-09-30. These describe a changing client implementation, not a guaranteed server contract. No live connection, login, QR scan, credential, message send or deployment was used to implement or test this component.

## Network contract

`ILinkClient` in `src/ilink.mjs` accepts:

```js
new ILinkClient({
  transport,                     // optional injected restricted transport
  channelVersion: '0.1.0',
  allowedHosts: ['ilinkai.weixin.qq.com'],
  baseUrl: 'https://ilinkai.weixin.qq.com',
  token, botId,                  // omit for QR-only client
});
```

`transport(url, {method, headers, body, signal})` returns `{status, body}`; the body is a string. The default is `createRestrictedHttpsTransport` with a 40-second deadline and 1 MiB response limit. It must validate public DNS answers at connection time, pin the selected address, verify the certificate, reject redirects, and honor cancellation. Injectable transports are trusted infrastructure, not caller-supplied tool arguments.

The adapter supports `getUpdates({cursor,signal})`, `sendText({to,contextToken,text,clientId,signal})`, `requestQr({signal})`, and `pollQr({qrcode,baseUrl,verifyCode,signal})`. `poll(cursor,{signal})` and `reply(args)` are Bridge-compatible aliases.

Authenticated POSTs carry the bot token, protocol headers, packed client version and base metadata. QR creation omits bot authorization and prior tokens. QR status GETs carry only application headers. Polling retains the prior cursor when the response cursor is empty or omitted. Either business error field equal to `-14` produces `ilink_session_expired`. Caller cancellation produces `ilink_aborted`.

The adapter never retries a send. Only explicit `ret: 0` with no business error is accepted. Missing acknowledgement is `unknown`; transport failure is an `ILinkError` with `delivery: 'unknown'`. Persist reply-attempt state before calling it, and never blindly replay an unknown outcome. The caller owns cursor persistence, message deduplication, backoff, and session-expiry handling.

Only exact configured hosts under `weixin.qq.com` are eligible. The default has one host. Neither an upstream redirect host nor a returned base URL expands the allowlist. Non-HTTPS URLs, userinfo, nonstandard ports, paths, query strings and fragments are rejected as base URLs. QR creation always starts at the fixed official origin. Extra regional hosts require independently verified operator configuration. No media/CDN handling is implemented.

## Secure linking integration

```js
new LinkingService({
  client: qrClient,
  ownerPrincipal: configuredAuthenticatedSubject,
  loadSecret: async () => encryptedStore.state.link ?? null,
  saveSecret: async (nextState, transition) => {
    // Apply binding/revocation effects AND nextState in one durable encrypted
    // transaction; stop old runtime work before invalidating an old binding.
  },
  onBind, onRevoke,              // optional trusted precommit runtime hooks
  now: () => Date.now(),
  ttlMs: 300000,                 // at most five minutes
});
```

`principal` must be supplied by verified authentication middleware. A matching string from a request body is not authentication. The configured principal is required even before the first link; first-caller ownership is not supported.

Owner methods:

- `begin({principal,signal})`: creates one short-lived, random owner-bound request; refuses a second outstanding challenge or an existing binding
- `status({principal,requestId?})`: returns sanitized state, identity candidates, and `linked`; it does not claim the messaging connection works
- `secureChallenge({principal,requestId})`: the sole owner-facing QR-bearing result, `{requestId,expiresAt,qrContent}`
- `poll({principal,requestId,verifyCode?,signal})`: one upstream status request; stops at `awaiting_owner_confirmation`
- `confirm({principal,requestId,scannerId})`: requires the authenticated owner to explicitly confirm the exact displayed scanner; repeats are idempotent
- `revoke({principal,requestId})`: aborts active QR polling, removes secrets and binding, and commits a revocation transition
- `getActiveBinding({principal})`: credential-bearing INTERNAL daemon accessor; never expose through HTTP, MCP, logging or metrics

A scanner is untrusted until exact owner confirmation. Receiving Tencent's `confirmed` status stores a provisional candidate only; it never adds the scanner to allowed senders. `binded_redirect` cannot establish local ownership. Confirmation freezes the candidate, clears the QR data, and creates the binding. Local expiry is checked again after long polls and before confirmation; expired requests cannot be refreshed silently. Begin a new request explicitly.

The entire state is encrypted through the injected persistence callbacks:

```text
{ version: 1,
  request: null | { id, ownerPrincipal, createdAt, expiresAt, status,
                    qrcode?, qrContent?, baseUrl?, candidate? },
  binding: null | { ownerPrincipal, requestId, scannerId, botId,
                    baseUrl, token, boundAt } }
```

`candidate` contains `scannerId`, `botId`, `baseUrl`, and `token`. Terminal request records retain only safe metadata. `saveSecret` receives `{type}` for begin/poll/expire, `{type:'bind',binding}` for confirmation, or `{type:'revoke',previousBinding}` for revocation. These callback arguments are secret-bearing internal data, never diagnostics. Use the transition to atomically invalidate old contexts, inbox/outbox jobs, subscriptions and credentials alongside the linking state. Starting a new runtime must happen after the commit resolves. Optional precommit hooks must not separately persist or start authorized work; callback/storage failure poisons the service and fails closed.

Serve the challenge only through an explicitly requested authenticated secure-owner route with TLS, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and restrictive content security policy. Prefer rendering `qrContent` as opaque QR data: never interpret it as HTML or fetch an arbitrary supplied URL. Protect browser mutations against CSRF. Do not add a QR/token-returning MCP tool, put secrets in normal JSON-RPC errors, or log HTTP query strings, bodies or authorization headers. Avoid access-log capture of verification codes. Local revocation removes this bridge's ability to use credentials; no unverified upstream token-revocation endpoint is claimed.

## Verification

`node --test test/ilink.test.mjs` runs synthetic transport/storage fixtures. Coverage includes protocol headers, cursor retention, cancellation, session expiry, unknown send outcomes, exact host validation, sanitized outputs/errors, owner isolation, confirmation identity, TTL/restart, atomic transition callbacks, and concurrent confirmation/revocation. Passing these tests does not verify account eligibility, Tencent availability or a production messaging connection.
