# Authentication and host-registration contract

## Current boundary

This repository implements a **single-owner OAuth resource server** and, when explicitly enabled, a confidential owner web client. It does not implement an identity provider, user signup, consent screen, token endpoint, client registration service, refresh-token service, or IdP revocation endpoint. An operator must choose and configure a standards-compliant external authorization server before the bridge can authenticate real requests.

No login, authorization grant, credential creation, key generation, real token issuance, public deployment, or ChatGPT registration was performed in this work. Passing offline tests does not establish that a particular account, plugin surface, IdP, or callback host will interoperate.

## Owner web admin client (v0.3)

The owner UI is an OAuth/OIDC **client**, not an authorization server. It uses pinned `openid-client` 6.8.8, Authorization Code + PKCE S256, state and nonce. Only the configured HTTPS origin plus `/admin/oauth/callback` is accepted. Issuer discovery, authorization, token and JWKS endpoints must stay on the exact configured issuer origin. Discovery advertises `code`, `S256` and `client_secret_basic`; ID tokens are signature-verified with RS256 and checked for issuer, client audience, nonce, expiry and exact owner subject. The independent resource-server verifier also checks the access token's signature, resource audience, owner, scope, lifetime and revocation state before any session is established.

For the planned `wechat.resopod.ai` origin, configure a **separate** Auth0 administrative application as follows. These are implementation settings, not evidence that an application has been created or deployed:

| Auth0 field | Exact setting |
| --- | --- |
| Application Type | Regular Web Application (confidential server client) |
| Credentials → Authentication Method | Client Secret (Basic), `client_secret_basic` |
| Allowed Callback URLs | `https://wechat.resopod.ai/admin/oauth/callback` only |
| Application Login URI | Leave empty; the login flow must start from the local form |
| Allowed Logout URLs | Leave empty; this implementation does not call Auth0 logout |
| Allowed Web Origins / CORS | Leave empty; no cross-origin browser token requests |
| Grant Types | Authorization Code; no implicit, password, client-credentials or refresh-token flow needed for this admin client |
| ID-token signing algorithm | RS256; OIDC conformant |
| API Identifier / request audience + resource | `https://wechat.resopod.ai/mcp` |
| Requested login scopes | `openid bridge:admin` |
| API access-token profile | RFC 9068; RS256; maximum lifetime 3600 seconds; unencrypted signed JWT |
| API permissions | Define `bridge:admin` and `bridge:mcp`; only the separate admin client/owner may receive administrative scope |

Auth0 documents [application settings](https://auth0.com/docs/get-started/applications/application-settings), [Client Secret (Basic)](https://auth0.com/docs/get-started/applications/credentials), [API settings](https://auth0.com/docs/get-started/apis/api-settings), and the [RFC 9068 profile](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles). The installed [openid-client](https://github.com/panva/openid-client) implements the protocol checks and confidential token exchange. If RBAC is enabled, assign the owner the admin permission and verify that the issued **scope** contains `bridge:admin`; a permissions array alone is insufficient. A reported Resource Parameter Compatibility setting still needs real acceptance testing: requests send the same exact API identifier as both `audience` and `resource`.

The public start/return page is `https://wechat.resopod.ai/admin`. Login requires a CSRF-protected POST from that page; unsolicited IdP-initiated login is unsupported. The OAuth callback is the only GET that changes authentication state. No GET creates a QR or confirms/revokes a binding. Do not register wildcard callbacks or substitute `/mcp`, `/callback`, `/admin/login`, or a provider logout callback.

Provision the exact issuer (including trailing slash), verified owner `sub`, admin client ID and an owner-readable `0400`/`0600` client-secret file outside Git. Set `BRIDGE_ADMIN_UI_ENABLED=true`, `BRIDGE_ADMIN_CLIENT_ID` and `BRIDGE_ADMIN_CLIENT_SECRET_FILE`; `.env.example` contains only templates. Never send the client secret or an admin bearer token through chat. A client ID or email cannot replace the verified owner subject. No real tenant, owner identity, client ID or secret is committed in this repository.

Sessions hold API tokens only in server memory and rotate the opaque cookie after login. Cookies use `__Host-bridge_admin`, Secure, HttpOnly, SameSite=Lax, Path=/ and no Domain. Prelogin state/nonce/PKCE transactions expire in five minutes and are consumed before token exchange, including failures. Authenticated sessions expire after at most one hour, earlier token expiry, or 15 minutes idle; restart logs everyone out. Forms enforce exact Origin, same-origin fetch metadata when supplied and one-use CSRF tokens. Responses are no-store/no-referrer with a restrictive CSP. QR images are generated locally from authenticated, bounded opaque content without fetching image URLs.

**Local logout only:** `POST /admin/logout` destroys the browser's bridge session, aborts pending work and drains dispatched operations before acknowledging. A mutation already in its atomic storage write can finish before logout returns; logout does not undo a binding that has committed. Use the explicit revoke form to stop WeChat access. Logout does not terminate other browser sessions, revoke provider grants or log out the Auth0 SSO session. A later login still requests `prompt=login`. No refresh tokens or `offline_access` are requested or stored. Per-request local access revocation is checked; provider-side account disablement still requires the external revocation integration described below.

The session pool is bounded at 128 entries. Anonymous pressure evicts prelogin sessions before authenticated owners; sustained traffic can force a pending login to restart. Apply independently approved availability controls at the proxy if needed; no blanket security/proxy changes are implied by enabling this UI.

## Official requirements and registration route

OpenAI's [authentication guide](https://developers.openai.com/plugins/build/auth) describes resource metadata, authorization-server discovery, PKCE S256, and resource-bound access tokens. Registration may use CIMD, DCR, or a predefined OAuth client. The IdP owns that choice. Copy the exact callback and client metadata document URLs from the actual connection-management interface; callback mode varies. Declare `bridge:mcp` on the plugin's OAuth security schemes. The ordinary plugin client should not receive administrative permission.

The [connection guide](https://developers.openai.com/plugins/deploy/connect-chatgpt) provides the host-side sequence:

1. Prepare a reachable HTTPS `/mcp` endpoint or a supported development tunnel
2. Enable Developer mode under Settings → Security and login, if account/workspace policy permits
3. In ChatGPT Plugins, use the plus button, enter the connection details, and create the connection
4. Complete the actual IdP linking flow and inspect discovered tools
5. Refresh the connection when metadata changes, then test in a fresh conversation

The [MCP Events guide](https://developers.openai.com/plugins/build/mcp-events) requires protocol `2026-07-28`. Confirm that event discovery appears in the real plugin interface, then test subscription, callback verification, matching delivery, and unsubscribe. A successful webhook HTTP response alone does not prove that the host ran the intended task.

## Resource-server API

`src/auth.mjs` uses the pinned `jose` dependency's `jwtVerify` and `createLocalJWKSet`. The host reads a provisioned **public-only** JWKS file and passes the parsed object. This module performs no network requests and follows no token-supplied key URL. It rejects symmetric/private JWK material and remote-key references.

```js
import {
  createResourceServerAuth,
  evaluateRevocation,
} from '../src/auth.mjs';

// Illustrative inputs only. The host supplies its own validated configuration,
// provisioned public JWKS, and durable revocation store.
const auth = await createResourceServerAuth({
  issuer: configuration.issuer,
  resource: configuration.resource,
  ownerSubject: configuration.ownerSubject,
  jwks: provisionedPublicJwks,
  revocationCheck: async claims =>
    evaluateRevocation(claims, await readDurableOwnerAuthState()),
});

const bridgeOwner = auth.ownerPrincipal;
const identity = await auth.authenticate(requestHeaders);
// Pass identity.principal, not caller-supplied data, to the bridge.

// Separate operator endpoint:
const operator = await auth.authenticate(requestHeaders, {
  requiredScopes: ['bridge:admin'],
});
```

The factory returns `authenticate`, `ownerPrincipal`, `protectedResourceMetadata`, `metadataPath`, `metadataUrl`, `challenge`, and `errorResponse`. `authenticate()` resolves to `{principal, issuer, scopes, tokenId, issuedAt, expiresAt}`. It returns no raw bearer token. Errors must be rendered through `auth.errorResponse(error, requiredScopes)` or an equivalent host adapter that preserves its status and challenge headers.

`principalFor(issuer, subject)` binds ownership to both exact strings, producing `oidc_` followed by a SHA-256 digest of their JSON pair. A different issuer or subject creates a different principal. The configured bridge owner must be `auth.ownerPrincipal`; do not compare it with a display name, email, WeChat sender ID, or an unverified JWT claim.

### Token profile enforced here

This implementation deliberately supports signed JWT **access tokens**, not arbitrary bearer strings or OIDC ID tokens:

- `typ` must identify `at+jwt` (the equivalent `application/at+jwt` spelling is accepted)
- Signature verification uses only the configured public key set
- Default algorithms are RS256 and ES256; configuration may select the explicit asymmetric allowlist
- `iss` and `sub` must exactly match the configured issuer and owner subject
- `aud` must include the configured resource identifier, preserving path/trailing-slash semantics
- `iat`, `exp`, and `jti` are required; `nbf` is checked when present
- Timestamps are integer Unix seconds; future-issued and expired tokens are rejected
- Maximum token lifetime defaults to 3600 seconds; configuration supports 1–86400 seconds
- Clock tolerance defaults to zero; configuration permits up to 60 seconds
- Permissions come only from a space-separated `scope` claim; MCP requires `bridge:mcp`, operator routes require `bridge:admin`
- The revocation callback must approve each request

An IdP that emits `typ: JWT`, opaque tokens, only an `scp` array, or no `jti` is **not compatible with this profile as implemented**. Configure a supported JWT access-token profile or design and review an explicit provider adapter. Do not work around incompatibility by decoding without verification, accepting ID tokens, disabling audience validation, or passing the WeChat bot credential as MCP authentication.

### Discovery ownership

Serve `auth.protectedResourceMetadata` without authentication at `auth.metadataPath`. For resource `https://bridge.example.invalid/mcp`, the generated URL is `https://bridge.example.invalid/.well-known/oauth-protected-resource/mcp`. The document points at the exact configured external issuer. The challenge advertises this URL. Default metadata advertises only `bridge:mcp`; an administrative route challenges for its own permission.

The external issuer, **not this bridge**, must publish its real RFC 8414 or OIDC discovery document. `validateAuthorizationServerMetadata(snapshot, options)` can check a separately obtained discovery snapshot for issuer consistency, code-flow support, S256, declared token-endpoint methods, and the selected registration mechanism. It performs no retrieval and does not establish that advertised endpoints actually work. Do not serve fabricated authorization-server metadata from the bridge.

The [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) defines protected-resource discovery and status semantics: invalid tokens produce 401, while insufficient permissions produce 403 with a scope challenge. Discovery data is public configuration; tokens belong in request headers, never URLs.

### Public-key rotation

The JWKS snapshot is copied when the factory is created. A modified disk file does not change a running verifier. Operators must obtain updated public keys through a trusted provisioning path, validate that path independently, and restart/reconstruct the verifier. Plan overlap for active IdP signing keys. Unknown signing keys fail closed until provisioned. The resource-server verifier performs no automatic remote JWKS refresh. Separately, the optional admin OIDC client retrieves issuer discovery and ID-token signing keys using a restricted HTTPS transport; those keys do not replace the provisioned API verification snapshot.

## Revocation semantics

Every successful cryptographic validation calls `revocationCheck` with frozen `{issuer, subject, principal, jti, issuedAt, expiresAt, scopes}`. Only literal `true` permits access. Exceptions, missing state, and any other return value deny access. The callback must read a durable authoritative source, not a process-local success cache.

`evaluateRevocation(claims, state)` expects:

```json
{
  "enabled": true,
  "revokedBefore": 0,
  "revokedTokenIds": []
}
```

`revokedBefore` is an integer Unix-second cutoff. Tokens with `iat <= revokedBefore` are rejected, including those issued in the cutoff second. `revokedTokenIds` blocks exact `jti` values. `enabled: false` blocks the owner entirely. This authorization state is separate from the WeChat link state so an authorized operator can manage an unlinked bridge.

Persist a revocation change before acknowledging it. Serialize sensitive operations with revocation changes where required, and recheck the durable owner's permission before webhook delivery or queued work. An expired HTTP bearer token and a revoked long-lived subscription are different cases: subscription access must be re-evaluated for its lifetime. The host must cancel/purge queued sends when the relevant link or subscription loses permission.

Local cutoffs do not revoke refresh tokens at the IdP, remove a ChatGPT plugin connection, or consume provider back-channel logout events. Those are external integration responsibilities. A deployment must define how operator revocation, IdP account disablement, and host disconnect reach the durable store. Until that route is implemented and tested, automatic propagation of those external revocations remains unverified.

## Protocol implementation references

The current [MCP base protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic) requires `resultType` on every result and per-request protocol version/capabilities in `params._meta`. Optional client/server identity metadata is descriptive, not authorization evidence. The [HTTP binding](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) specifies mirrored request headers, origin checks, stateless POST requests, and transport error statuses. The [canonical schema](https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts) also requires cache hints on discovery and tool-list responses. The project implements a narrow synchronous profile and should not claim general SDK conformance from its own tests.

## Evidence and remaining integration checks

`node --test test/auth.test.mjs` exercises policy checks with a deliberately synthetic injected verifier; that marker is not a token and is rejected by production `jose`. Additional tests derive a publicly known, deliberately trivial EC test key in memory and locally sign synthetic JWTs for `.invalid` destinations and a fixed clock. They verify production `jose` success and rejection of tampering, expiry, wrong issuer, wrong audience, and wrong owner. No tokens or private keys are logged or saved. These fixtures must never be used for deployment.

Other tests cover scope separation, ID-token/algorithm rejection, revocation, discovery, malformed headers, public-JWKS restrictions, and fail-closed verifier errors. They do not establish a real IdP login or permission grant. No production credential fixture is included.

Before describing the bridge as connected, verify all of these in the target environment:

- Exact IdP issuer, resource audience, owner subject, scope policy, and public signing keys
- The actual host's supported registration mode and exact callback URI
- OAuth linking and successful authorized `/mcp` calls, including expiry/refresh
- Failure for a different owner, audience, missing scope, revoked token, and disabled owner
- A separate operator client whose administrative scope is not granted to the plugin
- Authenticated event discovery, real callback host verification, delivery, and host task execution
- Durable delivery revocation after disconnect/account disablement and process restart
- TLS termination, Origin policy, duplicate-header handling, access logging redaction, and key rotation

An unknown host callback domain, missing plugin event registration support, unavailable IdP discovery, or absent secure credential provisioning is a deployment blocker to report, not a value to invent.
