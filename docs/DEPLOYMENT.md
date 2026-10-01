# Deployment and acceptance runbook

These are future operator instructions, not a record of an actual deployment. Do not run live flows until server use, persistent account access, and WeChat linking are explicitly approved.

## 1. Host and identity prerequisites

Use a supported Linux host with Docker/Compose or Node 24. One process/one persistent directory owns one bot. Do not run Hermes, OpenClaw and this bridge against the same bot simultaneously. Never place the state directory on NFS or another filesystem with uncertain SQLite locking/atomic rename semantics.

Choose an existing standards-compliant OAuth authorization server. Provision the bridge resource URL (`https://YOUR_HOST/mcp`), exact issuer/owner subject, `bridge:mcp` and a separate administrative client allowed `bridge:admin`. The ordinary ChatGPT plugin client must not receive admin scope. Tokens must satisfy the deliberately strict profile in AUTH.md (RFC9068 at+jwt, scope, jti, bounded lifetime). Do not repurpose an ID token.

Register the actual ChatGPT client through the route supported by both your IdP and the real host UI: CIMD, DCR, or predefined client. Require authorization-code PKCE S256. Copy the redirect URI from the real management page; this package intentionally does not invent one. External IdP grants or client registration are not created by these files. Metadata examples are not proof that this dot supports the completed connection.

Export only the IdP's public signing JWKS to the configured file. The bridge never fetches a caller-chosen JWKS URL. Replace the public JWKS snapshot and restart when rotating keys, retaining the old public key until its tokens expire. External IdP grant revocation is not automatically pushed here: local access revocation works immediately; upstream tokens otherwise remain usable until expiration. Add an approved IdP revocation integration before promising stronger revocation semantics.

## 2. Secret and filesystem provisioning

Prepare files outside the repo via an approved secret manager:

- `storage-key.raw`: exactly 32 raw random bytes, not hex/base64 text; never use test fixtures
- `tls.key`: private key for your valid public TLS certificate
- `tls.crt`: certificate chain for the public hostname
- `idp-public-jwks.json`: public key set, never private JWKs
- `admin-client-secret`: confidential admin client secret, only when web admin is enabled

The container runs UID/GID 1000. Secret mount directory must be readable by that UID; private-key files must be owner-only (`0400` or `0600`) and owned appropriately. No script in this package creates production credentials. Do not transmit secrets in chat, shell history, URLs, logs, Git or this archive.

Copy `.env.example` to a private `.env`, replace every placeholder, and retain `BRIDGE_ENABLE_LIVE=false` until deployment is approved. Initially leave `BRIDGE_CALLBACK_HOSTS=` empty if the host has not supplied its callback domain. Bootstrap allows authenticated MCP discovery/status and admin login, while subscriptions, WeChat message polling and sends fail closed. QR creation remains an explicit owner action. Once a callback host is actually observed and approved, set its exact hostname and restart; an existing valid binding can then resume polling. Set only hostname(s) observed in the legitimate host's configuration/subscription request; do not use wildcards or disable DNS checks to make an unknown callback work. Future callbacks outside the allowlist fail closed.

The Docker volume `/data` contains encrypted content plus an SQLite process-lock database. Back up the encrypted state together with a separately protected copy of its storage key. Losing the key loses recoverability. A backup rollback can restore older dedup state; do not blindly resume polling after rollback without reconciling deliveries. Keep secret backups and state access minimal.

## 3. Build and local preflight

```
npm ci --ignore-scripts
npm run check
npm test
docker build --target test -t wechat-dot-bridge-test .
docker build --target runtime -t wechat-dot-bridge .
```

Docker was unavailable in the authoring environment; these Docker builds have not been run here. Pin the official Node base image to an approved digest before production rollout. The committed npm lockfile pins jose, openid-client, qrcode, their transitive dependencies and integrity metadata; dependency install scripts are disabled.

After approved configuration/secret provisioning and setting the live gate, `npm run preflight` parses local configuration, JWKS and TLS key/certificate without network calls. It does not verify the certificate hostname/chain against a real client or validate host registration.

Compose defaults to publishing `127.0.0.1:8443`, so it is not reachable from ChatGPT by default. For an approved public deployment, set `BRIDGE_PUBLISH_BIND=0.0.0.0` and `BRIDGE_PUBLISH_PORT=443`, with firewall rules and DNS appropriate to the deployment. The app terminates TLS itself on container port 8443; forward TCP directly. An existing reverse proxy can connect to the app over HTTPS with certificate verification and the exact public Host/SNI, or TCP can be forwarded directly. A plaintext upstream does not work: the app ignores X-Forwarded-Proto and requires an actual TLS socket and exact public Host header. Preserve existing vhosts and services. Do not change public bindings/firewalls without the corresponding deployment approval.

```
docker compose up -d --build
docker compose logs --tail=30 bridge
```

The healthcheck connects locally with the configured TLS hostname and validates its public certificate. `/healthz` is generic liveness, not proof that WeChat or dot is connected. Signed-in `wechat_status` reports runtime state. An unlinked service can be healthy.

## 4. Owner-only QR binding

Enable the optional owner web UI only after the separate confidential IdP client and secure secret provisioning are approved. See [exact Auth0 settings](AUTH.md#owner-web-admin-client-v03). Open `/admin`, click login, complete the external owner authentication, then explicitly create a QR. The UI displays the actual scanned account and requires its exact ID before confirmation; use revoke to cancel a wrong-account scan. Login itself creates no QR and enables no binding. The UI's cookie is accepted only by its own form routes; JSON admin APIs remain bearer-only.

The fixed callback is `/admin/oauth/callback`. Disable caching and all request-query, cookie, Authorization-header and body logging for admin routes at every proxy/CDN/APM layer. OAuth code/state in the standard callback query must not be recorded. Do not enable debug HTTP logging. A future isolated Nginx admin location can use this template after reviewing the actual upstream certificate and changing the example hostname:

```nginx
location /admin {
    access_log off;
    error_log /dev/null;
    proxy_cache off;
    proxy_pass https://127.0.0.1:8443;
    proxy_set_header Host bridge.example.invalid;
    proxy_ssl_server_name on;
    proxy_ssl_name bridge.example.invalid;
    proxy_ssl_verify on;
    proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
}
```

Nginx error logs can include the callback query on upstream failures, so this admin-only location suppresses those entries too. Keep generic application/health diagnostics separately; do not enable request debug traces to diagnose login. `proxy_cache off` overrides inherited proxy caching. Review the CDN/APM logging and cache policy independently.

The `/mcp`, health and resource-metadata routes also need the verified HTTPS upstream. This snippet does not change any server, replace an existing vhost or establish CDN logging policy. Always run `nginx -t` before an approved graceful reload. A readiness-only host remains inactive until explicitly switched to the reviewed gateway.

For approved server-side automation, the original JSON admin API accepts actual IdP-issued admin bearer tokens over TLS; never put those tokens into a browser, URL or chat. Do not give admin scope to the ordinary MCP host client.

All requests below are POST JSON on the public bridge origin:

1. `/admin/link/begin`, body `{}` → short-lived owner-bound requestId
2. `/admin/link/challenge`, body `{ "requestId": "..." }` → secure QR content
3. `/admin/link/poll`, body `{ "requestId": "..." }` → wait/scanned/verification/owner-confirmation status
4. If requested, same poll route with `verifyCode`; never log the code
5. `/admin/link/confirm`, body `{ "requestId": "...", "scannerId": "EXACT_RETURNED_ID" }`

Show qrContent only in a trusted owner interface; treat it as opaque data, not HTML or an arbitrary URL to fetch. QR content and bot tokens must not be relayed through MCP tool output. The QR owner must inspect and confirm the exact scanner identity. An arbitrary person scanning a leaked QR does not become trusted automatically. The QR-link attempt expires after five minutes; encrypted restart state preserves that deadline. OAuth login transactions and browser sessions are in memory and are lost on restart.

The handler begins polling only after the owner-confirmed binding is atomically persisted **and** a nonempty approved callback allowlist is configured. No route accepts an arbitrary user-supplied principal or sender allowlist.

## 5. Connect and prove the exact dot path

Connect the remote MCP server at the configured `/mcp` through the actual plugin management flow; authenticate with the owner identity. The protected-resource metadata is at `/.well-known/oauth-protected-resource/mcp`. Rescan tools/events after changes.

Verify all of the following against the real host:

- MCP 2.0 protocol/version metadata and mirrored HTTP headers are accepted
- `wechat.message.received` appears in the event catalog
- A subscription in this dot's intended conversation is created with the expected sender
- Callback challenge verification and HMAC authentication succeed
- One actual owner message arrives, one event reaches this dot, and its instruction executes
- An explicitly approved reply arrives once in the original WeChat thread
- Duplicate/reordered events, disallowed sender, expiration, refresh, restart, disconnect and unsubscribe behave correctly

A webhook 2xx only means receipt, not completion of the dot task. Do not report success before verifying the returned WeChat message. Current code tests do not establish that a plugin connection is available in this particular dot account.

## 6. Revocation and operations

`POST /admin/link/revoke` with requestId aborts pending QR work, stops polling, clears bot credentials, context-bearing inbox and subscriptions. Hashed seen-message tombstones and reply idempotency records remain to prevent duplicate sends after relinking. Old unknown sends are never automatically retried. An old QR or token cannot be used to re-enable the binding through this bridge.

`POST /admin/access/revoke` with `{}` disables the owner locally, cancels in-flight QR work even before a request ID is committed, clears the binding, and blocks new MCP/admin requests. This survives restart. Also revoke grants in your external IdP and revoke/unbind the bot through the relevant official service UI; clearing a local token does not revoke Tencent's remote token. Re-enabling locally requires deliberate offline operator recovery; this package has no self-service bypass. Preserve dedup ledgers when recovering.

SIGTERM cancels outstanding requests and drains queues before closing encrypted storage. The watchdog exits if shutdown exceeds 65 seconds. SQLite releases the same-directory process lock when the process dies, so supervised restart does not need to delete a stale lock file. A different directory does not enforce the same-bot constraint: enforce unique bot ownership operationally.

Capacity bounds: 10,000 active inbox records, 100,000 hashed seen-message tombstones, 32 subscriptions, 32 MiB encrypted-state plaintext budget, 1,024 metadata-only quarantine entries. Oversized/invalid owner text is quarantined while other messages/cursor advance; disallowed sender content cannot stall the poller. State capacity/storage faults stop the runtime for operator action, never silently remove dedup data. This is a bounded single-user service, not an unlimited archive.
