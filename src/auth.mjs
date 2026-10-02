import {createHash} from 'node:crypto';
import {markLoginFailure,apiJwtFailureReason,ownerFailureReason} from './login-diagnostics.mjs';

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (value, max = 1024) => typeof value === 'string' && value.length > 0 && value.length <= max;
const scopePattern = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
const supportedAlgorithms = new Set(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']);

function httpsIdentifier(value, name) {
  if (!text(value, 2048) || /[\s\\]/.test(value)) throw new TypeError(`invalid_${name}`);
  let url;
  try { url = new URL(value); } catch { throw new TypeError(`invalid_${name}`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new TypeError(`invalid_${name}`);
  return url;
}

function scopes(value, name, allowEmpty = false) {
  if (!Array.isArray(value) || (!allowEmpty && !value.length) || value.length > 32 || value.some(s => !text(s, 128) || !scopePattern.test(s)) || new Set(value).size !== value.length) throw new TypeError(`invalid_${name}`);
  return Object.freeze([...value]);
}

function publicJwks(jwks) {
  if (!object(jwks) || !Array.isArray(jwks.keys) || !jwks.keys.length || jwks.keys.length > 32) throw new TypeError('invalid_public_jwks');
  const ids = new Set();
  for (const key of jwks.keys) {
    if (!object(key) || !['RSA', 'EC', 'OKP'].includes(key.kty) || !text(key.kid, 256) || ids.has(key.kid)) throw new TypeError('invalid_public_jwks');
    if (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'x5u', 'jku'].some(k => Object.hasOwn(key, k))) throw new TypeError('private_or_remote_jwk_rejected');
    if (key.use !== undefined && key.use !== 'sig') throw new TypeError('invalid_jwk_use');
    if (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== 'verify')) throw new TypeError('invalid_jwk_operations');
    if (key.alg !== undefined && !supportedAlgorithms.has(key.alg)) throw new TypeError('invalid_jwk_algorithm');
    ids.add(key.kid);
  }
  // The host owns rotation. The snapshot cannot change under an in-flight call.
  return structuredClone(jwks);
}

export function principalFor(issuer, subject) {
  httpsIdentifier(issuer, 'issuer');
  if (!text(subject, 1024)) throw new TypeError('invalid_owner_subject');
  return 'oidc_' + createHash('sha256').update(JSON.stringify([issuer, subject])).digest('hex');
}

export class AuthError extends Error {
  constructor(code = 'invalid_token', status = 401, requiredScopes = []) {
    super(code);
    this.name = 'AuthError';
    this.code = code;
    this.status = status;
    this.requiredScopes = [...requiredScopes];
  }
}

/** No token, connection state, or claims are persisted by this module. */
export function evaluateRevocation(claims, state) {
  if (!object(claims) || !object(state) || state.enabled !== true) return false;
  if (!Number.isSafeInteger(state.revokedBefore) || state.revokedBefore < 0 || !Number.isSafeInteger(claims.issuedAt) || claims.issuedAt <= state.revokedBefore) return false;
  if (!text(claims.jti, 256) || !Array.isArray(state.revokedTokenIds) || state.revokedTokenIds.some(id => !text(id, 256))) return false;
  return !state.revokedTokenIds.includes(claims.jti);
}

/** Validate a separately obtained IdP discovery snapshot; never fetch or host it. */
export function validateAuthorizationServerMetadata(metadata, {issuer, clientRegistration, predefinedClientId} = {}) {
  httpsIdentifier(issuer, 'issuer');
  if (!object(metadata) || metadata.issuer !== issuer) throw new TypeError('authorization_server_issuer_mismatch');
  httpsIdentifier(metadata.authorization_endpoint, 'authorization_endpoint');
  httpsIdentifier(metadata.token_endpoint, 'token_endpoint');
  if (!Array.isArray(metadata.code_challenge_methods_supported) || !metadata.code_challenge_methods_supported.includes('S256')) throw new TypeError('pkce_s256_required');
  if (!Array.isArray(metadata.response_types_supported) || !metadata.response_types_supported.includes('code')) throw new TypeError('authorization_code_required');
  if (!Array.isArray(metadata.token_endpoint_auth_methods_supported) || !metadata.token_endpoint_auth_methods_supported.length) throw new TypeError('token_endpoint_auth_methods_required');
  if (metadata.jwks_uri !== undefined) httpsIdentifier(metadata.jwks_uri, 'jwks_uri');
  if (clientRegistration === 'cimd') {
    if (metadata.client_id_metadata_document_supported !== true || !metadata.token_endpoint_auth_methods_supported.some(m => ['none', 'private_key_jwt'].includes(m))) throw new TypeError('cimd_not_supported');
  } else if (clientRegistration === 'dcr') {
    httpsIdentifier(metadata.registration_endpoint, 'registration_endpoint');
  } else if (clientRegistration === 'predefined') {
    if (!text(predefinedClientId, 2048)) throw new TypeError('predefined_client_id_required');
  } else throw new TypeError('client_registration_required');
  return Object.freeze({issuer, clientRegistration, issuerIdentification: metadata.authorization_response_iss_parameter_supported === true});
}

function bearerToken(headers) {
  let value;
  if (headers instanceof Headers) value = headers.get('authorization');
  else if (object(headers)) {
    const values = Object.entries(headers).filter(([name]) => name.toLowerCase() === 'authorization');
    if (values.length > 1) throw new AuthError('invalid_request', 400);
    value = values[0]?.[1];
  }
  if (value === undefined || value === null) throw new AuthError('authentication_required');
  if (typeof value !== 'string' || value.length > 16384) throw new AuthError('invalid_request', 400);
  const match = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(value);
  if (!match) throw new AuthError('invalid_token');
  return match[1];
}

/**
 * An OAuth resource server, not an authorization server. Production uses jose
 * with a host-provisioned public JWKS snapshot. No network I/O is performed.
 * verifyJwt is a trusted dependency injection point for offline unit tests only.
 */
export async function createResourceServerAuth(config, {verifyJwt, now = () => Date.now()} = {}) {
  if (!object(config)) throw new TypeError('auth_configuration_required');
  const {issuer, resource, ownerSubject, revocationCheck} = config;
  httpsIdentifier(issuer, 'issuer');
  const resourceUrl = httpsIdentifier(resource, 'resource');
  const ownerPrincipal = principalFor(issuer, ownerSubject);
  if (typeof revocationCheck !== 'function') throw new TypeError('revocation_check_required');
  if (typeof now !== 'function') throw new TypeError('clock_required');
  const scopesSupported = scopes(config.scopesSupported ?? ['bridge:mcp', 'bridge:admin'], 'scopes_supported');
  const defaultScopes = scopes(config.defaultScopes ?? ['bridge:mcp'], 'default_scopes');
  if (defaultScopes.some(s => !scopesSupported.includes(s))) throw new TypeError('unknown_default_scope');
  const algorithms = config.algorithms ?? ['RS256', 'ES256'];
  if (!Array.isArray(algorithms) || !algorithms.length || algorithms.some(alg => !supportedAlgorithms.has(alg)) || new Set(algorithms).size !== algorithms.length) throw new TypeError('invalid_algorithms');
  const allowedAlgorithms = Object.freeze([...algorithms]);
  const tolerance = config.clockToleranceSeconds ?? 0;
  const maxLifetime = config.maxTokenLifetimeSeconds ?? 3600;
  if (!Number.isSafeInteger(tolerance) || tolerance < 0 || tolerance > 60) throw new TypeError('invalid_clock_tolerance');
  if (!Number.isSafeInteger(maxLifetime) || maxLifetime < 1 || maxLifetime > 86400) throw new TypeError('invalid_token_lifetime');
  if (verifyJwt !== undefined && typeof verifyJwt !== 'function') throw new TypeError('invalid_verifier');
  if (!verifyJwt) {
    const snapshot = publicJwks(config.jwks);
    const {createLocalJWKSet, jwtVerify} = await import('jose');
    const keySet = createLocalJWKSet(snapshot);
    verifyJwt = (token, options) => jwtVerify(token, keySet, options);
  }
  const metadataPath = '/.well-known/oauth-protected-resource' + (resourceUrl.pathname === '/' ? '' : resourceUrl.pathname);
  const metadataUrl = resourceUrl.origin + metadataPath;
  const protectedResourceMetadata = Object.freeze({
    // Advertise only basic plugin permissions. Administrative scope is
    // challenged separately and should not be granted to the plugin client.
    resource, authorization_servers: Object.freeze([issuer]), scopes_supported: defaultScopes,
    bearer_methods_supported: Object.freeze(['header']),
  });

  function challenge(error, requiredScopes = defaultScopes) {
    const required = scopes(requiredScopes, 'required_scopes', true);
    const parts = [`resource_metadata="${metadataUrl}"`];
    if (required.length) parts.push(`scope="${required.join(' ')}"`);
    const code = error instanceof AuthError ? error.code : 'invalid_token';
    if (code !== 'authentication_required') {
      const known = ['invalid_token', 'invalid_request', 'insufficient_scope'].includes(code) ? code : 'invalid_token';
      parts.push(`error="${known}"`, `error_description="${known === 'insufficient_scope' ? 'Additional permission required' : 'Valid authorization required'}"`);
    }
    return 'Bearer ' + parts.join(', ');
  }

  function errorResponse(error, requiredScopes = error?.requiredScopes?.length ? error.requiredScopes : defaultScopes) {
    const code = error instanceof AuthError ? error.code : 'invalid_token';
    return {
      status: error instanceof AuthError ? error.status : 401,
      headers: {'content-type': 'application/json', 'cache-control': 'no-store', 'www-authenticate': challenge(error, requiredScopes)},
      body: JSON.stringify({error: code}),
    };
  }

  async function authenticate(headers, {requiredScopes = defaultScopes} = {}) {
    const denied=reason=>markLoginFailure(new AuthError(),reason);
    const required = scopes(requiredScopes, 'required_scopes', true);
    if (required.some(s => !scopesSupported.includes(s))) throw new TypeError('unknown_required_scope');
    const token = bearerToken(headers);
    const seconds = Math.floor(now() / 1000);
    if (!Number.isSafeInteger(seconds) || seconds < 0) throw new AuthError();
    let checked;
    try {
      checked = await verifyJwt(token, {
        issuer, audience: resource, algorithms: [...allowedAlgorithms], typ: 'at+jwt',
        requiredClaims: ['iss', 'aud', 'sub', 'exp', 'iat', 'jti'],
        clockTolerance: tolerance, currentDate: new Date(seconds * 1000),
      });
    } catch(error) { throw denied(apiJwtFailureReason(error)); }
    const payload = checked?.payload, header = checked?.protectedHeader;
    // Defense in depth: also makes the trust contract of an injected verifier explicit.
    if (!object(payload) || !object(header) || !allowedAlgorithms.includes(header.alg) || header.jku !== undefined || header.jwk !== undefined || header.x5u !== undefined) throw denied('api_token_invalid');
    if (typeof header.typ !== 'string' || !['at+jwt', 'application/at+jwt'].includes(header.typ.toLowerCase())) throw denied('api_type_invalid');
    if (payload.iss !== issuer) throw denied('api_issuer_invalid');
    if (payload.sub !== ownerSubject) throw denied(ownerFailureReason(payload.sub,ownerSubject,'api'));
    if (!(payload.aud === resource || Array.isArray(payload.aud) && payload.aud.every(a => typeof a === 'string') && payload.aud.includes(resource))) throw denied('api_audience_invalid');
    if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) || payload.exp <= payload.iat) throw denied('api_lifetime_invalid');
    if (payload.iat > seconds + tolerance) throw denied('api_not_yet_valid');
    if (payload.exp <= seconds - tolerance) throw denied('api_expired');
    if (payload.exp - payload.iat > maxLifetime) throw denied('api_lifetime_excessive');
    if (!text(payload.jti, 256)) throw denied('api_jti_missing');
    if (payload.nbf !== undefined && (!Number.isSafeInteger(payload.nbf) || payload.nbf > seconds + tolerance)) throw denied('api_not_yet_valid');
    if (typeof payload.scope !== 'string' || payload.scope.length > 4096) throw denied('api_scope_invalid');
    let granted;
    try { granted = scopes(payload.scope === '' ? [] : payload.scope.split(' '), 'token_scopes', true); } catch { throw denied('api_scope_invalid'); }
    const claims = Object.freeze({issuer, subject: ownerSubject, principal: ownerPrincipal, jti: payload.jti, issuedAt: payload.iat, expiresAt: payload.exp, scopes: granted});
    // A persistent source must decide on EVERY request. No success cache and no
    // reliance on upstream login cookies, a previous tool call, or WeChat state.
    let active = false;
    try { active = await revocationCheck(claims); } catch { throw denied('api_revocation_rejected'); }
    if (active !== true) throw denied('api_revocation_rejected');
    if (required.some(scope => !granted.includes(scope))) throw markLoginFailure(new AuthError('insufficient_scope', 403, required),'api_scope_missing');
    return Object.freeze({principal: ownerPrincipal, issuer, scopes: granted, tokenId: payload.jti, issuedAt: payload.iat, expiresAt: payload.exp});
  }
  return Object.freeze({authenticate, ownerPrincipal, protectedResourceMetadata, metadataUrl, metadataPath, challenge, errorResponse});
}
