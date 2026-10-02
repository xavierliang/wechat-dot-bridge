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

The adapter never retries a send. A successful HTTP/JSON response is acknowledged by explicit `ret: 0`, or by a valid positive uint64 `message_id` when `ret` is omitted and no nonempty `errmsg` is present. A present `ret`/`errcode` must be an int32 and must not signal an error; present IDs and `errmsg` must have valid shapes even alongside `ret: 0`. Numeric IDs are parsed losslessly. Omission alone, `{}`, and `errcode: 0` alone are not acknowledgements. Missing/ambiguous acknowledgement is `unknown`; transport failure is an `ILinkError` with `delivery: 'unknown'`. Persist reply-attempt state before calling it, and never blindly replay an unknown outcome. Existing durable unknown records are not upgraded or retried. The caller owns cursor persistence, message deduplication, backoff, and session-expiry handling.

Each adapter attempt emits `wechat_send_result`, containing only a fixed outcome (`acknowledged`, `rejected`, `unknown`), stage/reason/code, acknowledgement basis, HTTP status, bounded error codes/elapsed time, field types and boolean ID-validity/error-text-presence flags. No body, error text, stack, URL, headers, message/client ID, sender, credential or context token is logged. Diagnostic sink failure cannot change the result or cause a retry. `acknowledged` describes upstream acknowledgement, not user receipt or the later durable state save. Bridge retains its conservative durable `unknown` for non-accepted outcomes, including explicit rejections; diagnostics distinguish the rejection. Historical attempts have no recoverable response diagnostics.

Tencent's [send implementation](https://github.com/Tencent/openclaw-weixin/blob/main/src/api/api.ts#L544) and [response type](https://github.com/Tencent/openclaw-weixin/blob/main/src/api/types.ts#L224) allow omitted `ret`. This adapter requires additional acknowledgement evidence instead of treating every omitted `ret` as success.

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

Serve the challenge only through an explicitly requested authenticated secure-owner route with TLS, `Cache-Control: no-store`, and restrictive content security policy. The JSON challenge API uses `Referrer-Policy: no-referrer`; query-free HTML pages containing QR forms use `same-origin` so native form POSTs retain their exact Origin. Neither policy sends a referrer to external origins, and QR content is never put in the document URL. Prefer rendering `qrContent` as opaque QR data: never interpret it as HTML or fetch an arbitrary supplied URL. Protect browser mutations against CSRF. Do not add a QR/token-returning MCP tool, put secrets in normal JSON-RPC errors, or log HTTP query strings, bodies or authorization headers. Avoid access-log capture of verification codes. Local revocation removes this bridge's ability to use credentials; no unverified upstream token-revocation endpoint is claimed.

## Verification

`node --test test/ilink.test.mjs` runs synthetic transport/storage fixtures. Coverage includes protocol headers, cursor retention, cancellation, session expiry, unknown send outcomes, exact host validation, sanitized outputs/errors, owner isolation, confirmation identity, TTL/restart, atomic transition callbacks, and concurrent confirmation/revocation. Passing these tests does not verify account eligibility, Tencent availability or a production messaging connection.

## Poll compatibility and diagnostics

Successful getUpdates responses may omit `ret` and `msgs`. An omitted list is
empty; an omitted or empty cursor preserves the durable cursor. Explicit nonzero
application codes, nulls and malformed field types remain failures. Send
acknowledgements still require explicit `ret: 0`.

A failed runtime poll emits `wechat_poll_failed` followed by the existing phase
event. Diagnostics use allowlisted stage, reason and error codes, elapsed
milliseconds, HTTP status, bounded numeric `ret`/`errcode`, and field-type labels
for `ret`, `errcode`, `msgs` and the cursor. Transport classifications survive the
iLink wrapper, distinguishing DNS, TCP, TLS, deadline, destination, redirect,
response-size, HTTP, JSON, application and normalization failures. Unknown errors
stay `unclassified` or `transport_failed`; no raw error, cause, stack, URL, header,
body, cursor, identity, token or message is logged. No new diagnostic endpoint is
exposed. Cancellation during shutdown emits no failure diagnostic; a failed log
sink does not alter retry or stop behavior.

The existing 40-second transport deadline and exponential backoff are unchanged.
A deadline remains a classified failure pending observed production evidence;
this change does not claim every timeout is a successful empty poll.

## Lossless inbound IDs and filtering

Tencent defines inbound `message_id` as uint64. The adapter uses Node 24's native
JSON reviver `context.source` to retain the original numeric token, then validates
decimal string IDs against the uint64 range with BigInt. It never reconstructs a
large ID from a rounded JavaScript Number. Numeric and quoted representations
normalize to the same decimal identity for durable deduplication; adjacent large
IDs remain distinct. Existing safe-integer identities remain unchanged.

The bound scanner is filtered before content/ID validation, and Bridge still
checks sender authorization before ingest. A supported inbound text message with
an invalid ID rejects the whole batch before cursor persistence. Unsupported
content, non-user/group/wrong-recipient messages and unapproved senders are
filtered with fixed reason counts. Each nonempty batch emits `wechat_poll_batch`
with `mapped` or `rejected` and bounded counts only; it contains no ID, identity,
text, context token or cursor. A mapped batch has not yet been persisted or
delivered. Missing context/timestamp and malformed structures remain rejected or
filtered rather than weakening the schema.

These diagnostics cannot recover messages already skipped by an earlier version.
The bridge does not reset or rewind a durable upstream cursor automatically.
