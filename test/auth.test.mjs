import test from 'node:test';
import assert from 'node:assert/strict';
import {createECDH} from 'node:crypto';
import {importJWK, SignJWT} from 'jose';
import {AuthError, createResourceServerAuth, evaluateRevocation, principalFor, validateAuthorizationServerMetadata} from '../src/auth.mjs';

// Not a signed token or usable credential. The injected verifier deliberately
// treats these marker bytes as a test input; production jose rejects them.
const headers = {authorization: 'Bearer synthetic.offline.fixture'};
const current = 1800000000;
const issuer = 'https://identity.example.invalid/tenant';
const resource = 'https://bridge.example.invalid/mcp';
const ownerSubject = 'offline-owner';
const config = {issuer, resource, ownerSubject, revocationCheck: () => true};
const goodPayload = {iss: issuer, aud: resource, sub: ownerSubject, iat: current - 10, exp: current + 300, jti: 'offline-fixture-id', scope: 'bridge:mcp'};
const goodHeader = {alg: 'RS256', typ: 'at+jwt'};
const deps = (payload = goodPayload, protectedHeader = goodHeader) => ({now: () => current * 1000, verifyJwt: async () => ({payload: {...payload}, protectedHeader: {...protectedHeader}})});
const authError = (code = 'invalid_token', status = 401) => error => error instanceof AuthError && error.code === code && error.status === status;

test('auth identity is bound to exact issuer and owner subject', async () => {
  const auth = await createResourceServerAuth(config, deps());
  const result = await auth.authenticate(headers);
  assert.equal(result.principal, auth.ownerPrincipal);
  assert.equal(result.principal, principalFor(issuer, ownerSubject));
  assert.notEqual(principalFor(issuer + '/', ownerSubject), result.principal);
  assert.notEqual(principalFor(issuer, 'different-owner'), result.principal);
  assert.deepEqual(result.scopes, ['bridge:mcp']);
  assert.equal(result.tokenId, goodPayload.jti);
  assert.equal(Object.hasOwn(result, 'token'), false);
});

test('production verifier receives restrictive jose verification options', async () => {
  let options;
  const auth = await createResourceServerAuth(config, {...deps(), verifyJwt: async (token, opts) => {
    assert.equal(token, 'synthetic.offline.fixture'); options = opts;
    return {payload: goodPayload, protectedHeader: goodHeader};
  }});
  await auth.authenticate(headers);
  assert.deepEqual(options.algorithms, ['RS256', 'ES256']);
  assert.equal(options.typ, 'at+jwt');
  assert.equal(options.issuer, issuer);
  assert.equal(options.audience, resource);
  assert.deepEqual(options.requiredClaims, ['iss', 'aud', 'sub', 'exp', 'iat', 'jti']);
  assert.equal(options.currentDate.getTime(), current * 1000);
});

test('admin permission is independent and cannot be inferred from MCP access', async () => {
  const auth = await createResourceServerAuth(config, deps());
  await assert.rejects(auth.authenticate(headers, {requiredScopes: ['bridge:admin']}), authError('insufficient_scope', 403));
  const admin = await createResourceServerAuth(config, deps({...goodPayload, scope: 'bridge:admin'}));
  await admin.authenticate(headers, {requiredScopes: ['bridge:admin']});
  await assert.rejects(admin.authenticate(headers), authError('insufficient_scope', 403));
});

test('owner, issuer and audience mismatch are rejected after verification', async () => {
  for (const patch of [{sub: 'someone-else'}, {iss: issuer + '/'}, {aud: 'https://other.example.invalid'}, {aud: [resource, 123]}]) {
    const auth = await createResourceServerAuth(config, deps({...goodPayload, ...patch}));
    await assert.rejects(auth.authenticate(headers), authError());
  }
  const auth = await createResourceServerAuth(config, deps({...goodPayload, aud: ['https://other.example.invalid', resource]}));
  await auth.authenticate(headers);
});

test('time claims and lifetime bounds reject expired, future and malformed tokens', async () => {
  for (const patch of [{exp: current}, {exp: 'tomorrow'}, {iat: undefined}, {iat: current + 1}, {iat: current - 4000}, {nbf: current + 1}, {nbf: 'later'}, {exp: goodPayload.iat}, {jti: ''}, {jti: undefined}]) {
    const auth = await createResourceServerAuth(config, deps({...goodPayload, ...patch}));
    await assert.rejects(auth.authenticate(headers), authError());
  }
});

test('missing scopes, malformed scopes, unsigned algorithms and ID tokens fail closed', async () => {
  for (const scope of [undefined, ['bridge:mcp'], 'bridge:mcp  bridge:admin', 'bridge:mcp\nbridge:admin', 'bridge:mcp bridge:mcp']) {
    const auth = await createResourceServerAuth(config, deps({...goodPayload, scope}));
    await assert.rejects(auth.authenticate(headers), authError());
  }
  for (const patch of [{alg: 'none'}, {alg: 'HS256'}, {typ: 'JWT'}, {typ: {}}, {typ: undefined}, {jku: 'https://attacker.invalid/jwks'}, {jwk: {}}, {x5u: 'https://attacker.invalid/cert'}]) {
    const auth = await createResourceServerAuth(config, deps(goodPayload, {...goodHeader, ...patch}));
    await assert.rejects(auth.authenticate(headers), authError());
  }
});

test('bearer parsing rejects duplicate, oversized, joined and malformed headers', async () => {
  const auth = await createResourceServerAuth(config, deps());
  await assert.rejects(auth.authenticate({}), authError('authentication_required'));
  for (const authorization of ['Basic synthetic.offline.fixture', 'Bearer synthetic.offline.fixture, Bearer a.b.c', 'Bearer a.b.', ' Bearer a.b.c', 'Bearer a.b.c\r\nX: y']) {
    await assert.rejects(auth.authenticate({authorization}), authError());
  }
  await assert.rejects(auth.authenticate({Authorization: headers.authorization, authorization: headers.authorization}), authError('invalid_request', 400));
  await assert.rejects(auth.authenticate({authorization: [headers.authorization]}), authError('invalid_request', 400));
  await assert.rejects(auth.authenticate({authorization: 'x'.repeat(16385)}), authError('invalid_request', 400));
  await auth.authenticate(new Headers({Authorization: headers.authorization}));
});

test('verification and revocation failures never expose implementation errors', async () => {
  const auth = await createResourceServerAuth(config, {...deps(), verifyJwt: async () => { throw Error('internal secret text'); }});
  await assert.rejects(auth.authenticate(headers), authError());
  for (const check of [() => false, () => undefined, () => 'true', () => {throw Error('database details');}]) {
    const revoked = await createResourceServerAuth({...config, revocationCheck: check}, deps());
    await assert.rejects(revoked.authenticate(headers), authError());
  }
});

test('revocation is checked every time against externally persisted state', async () => {
  const state = {enabled: true, revokedBefore: 0, revokedTokenIds: []};
  let calls = 0;
  const auth = await createResourceServerAuth({...config, revocationCheck: claims => {
    calls++; assert.equal(claims.subject, ownerSubject); return evaluateRevocation(claims, state);
  }}, deps());
  await auth.authenticate(headers);
  state.revokedTokenIds.push(goodPayload.jti);
  await assert.rejects(auth.authenticate(headers), authError());
  assert.equal(calls, 2);
  state.revokedTokenIds = [];
  state.revokedBefore = goodPayload.iat;
  await assert.rejects(auth.authenticate(headers), authError());
  state.revokedBefore = goodPayload.iat - 1;
  await auth.authenticate(headers);
  state.enabled = false;
  await assert.rejects(auth.authenticate(headers), authError());
});

test('malformed or absent persisted revocation state denies access', () => {
  const claims = {issuedAt: goodPayload.iat, jti: goodPayload.jti};
  for (const state of [undefined, {}, {enabled: true}, {enabled: true, revokedBefore: -1, revokedTokenIds: []}, {enabled: true, revokedBefore: 0, revokedTokenIds: [1]}, {enabled: true, revokedBefore: '0', revokedTokenIds: []}]) assert.equal(evaluateRevocation(claims, state), false);
});

test('protected resource metadata and challenges are resource-specific', async () => {
  const auth = await createResourceServerAuth(config, deps());
  assert.equal(auth.metadataPath, '/.well-known/oauth-protected-resource/mcp');
  assert.equal(auth.metadataUrl, 'https://bridge.example.invalid/.well-known/oauth-protected-resource/mcp');
  assert.equal(auth.protectedResourceMetadata.resource, resource);
  assert.deepEqual(auth.protectedResourceMetadata.authorization_servers, [issuer]);
  assert.deepEqual(auth.protectedResourceMetadata.scopes_supported, ['bridge:mcp']);
  assert.deepEqual(auth.protectedResourceMetadata.bearer_methods_supported, ['header']);
  const absent = auth.errorResponse(new AuthError('authentication_required'));
  assert.equal(absent.status, 401);
  assert.match(absent.headers['www-authenticate'], /resource_metadata="https:\/\/bridge.example.invalid\/\.well-known\/oauth-protected-resource\/mcp"/);
  assert.match(absent.headers['www-authenticate'], /scope="bridge:mcp"/);
  assert.doesNotMatch(absent.headers['www-authenticate'], /error=/);
  const admin = auth.errorResponse(new AuthError('insufficient_scope', 403, ['bridge:admin']));
  assert.equal(admin.status, 403);
  assert.match(admin.headers['www-authenticate'], /scope="bridge:admin"/);
  assert.match(admin.headers['www-authenticate'], /error="insufficient_scope"/);
  assert.equal(admin.headers['cache-control'], 'no-store');
});

test('constructor rejects insecure or incomplete configuration', async () => {
  for (const patch of [{issuer: 'http://identity.invalid'}, {issuer: 'https://user:password@identity.invalid'}, {resource: 'https://bridge.invalid/mcp?q=x'}, {resource: 'https://bridge.invalid/mcp#x'}, {ownerSubject: ''}, {revocationCheck: undefined}, {algorithms: ['HS256']}, {clockToleranceSeconds: 61}, {maxTokenLifetimeSeconds: 0}, {scopesSupported: ['bad scope']}, {defaultScopes: ['undefined']}]) {
    await assert.rejects(createResourceServerAuth({...config, ...patch}, deps()), TypeError);
  }
});

test('local JWKS cannot include private/symmetric/remote keys or duplicate IDs', async () => {
  const base = {kty: 'RSA', kid: 'public-offline-fixture', n: 'AQAB', e: 'AQAB'};
  for (const keys of [[], [{...base, d: 'private-material'}], [{...base, k: 'symmetric-material'}], [{...base, jku: 'https://other.invalid'}], [{...base, x5u: 'https://other.invalid'}], [{...base, use: 'enc'}], [{...base, key_ops: ['sign']}], [base, base], [{...base, kty: 'oct'}]]) {
    await assert.rejects(createResourceServerAuth({...config, jwks: {keys}}), TypeError);
  }
});

test('real jose verifier rejects injected-test marker; there is no production bypass', async () => {
  const auth = await createResourceServerAuth({...config, jwks: {keys: [{kty: 'RSA', kid: 'unusable-public-test-key', n: 'AQAB', e: 'AQAB'}]}});
  await assert.rejects(auth.authenticate(headers), authError());
});

// Public, deliberately trivial EC scalar 1, constructed only inside this test.
// This is NOT a production key or a provisioned identity. Never use this key in
// deployment. Its tokens target only .invalid domains and a fixed synthetic clock.
async function syntheticSigningFixture() {
  const scalar = Buffer.alloc(32);
  scalar[31] = 1;
  const ec = createECDH('prime256v1');
  ec.setPrivateKey(scalar);
  const point = ec.getPublicKey(undefined, 'uncompressed');
  const publicKey = {
    kty: 'EC', crv: 'P-256', kid: 'publicly-known-synthetic-test-key',
    alg: 'ES256', use: 'sig', key_ops: ['verify'],
    x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33, 65).toString('base64url'),
  };
  const privateKey = await importJWK({...publicKey, key_ops: ['sign'], d: scalar.toString('base64url')}, 'ES256');
  scalar.fill(0);
  return {
    ownerSubject: 'syntheticowner',
    jwks: {keys: [publicKey]},
    // All signing is local test data. No token or private key is logged/saved.
    sign: patch => new SignJWT({...goodPayload, sub: 'syntheticowner', ...patch})
      .setProtectedHeader({alg: 'ES256', typ: 'at+jwt', kid: publicKey.kid})
      .sign(privateKey),
  };
}

test('real jose verifies a synthetic fixed-key JWT through production auth', async () => {
  const fixture = await syntheticSigningFixture();
  const auth = await createResourceServerAuth({...config, ownerSubject: fixture.ownerSubject, jwks: fixture.jwks}, {now: () => current * 1000});
  const token = await fixture.sign();
  const identity = await auth.authenticate({authorization: 'Bearer ' + token});
  assert.equal(identity.principal, auth.ownerPrincipal);
  assert.deepEqual(identity.scopes, ['bridge:mcp']);
  assert.equal(identity.tokenId, 'offline-fixture-id');
});

test('real jose rejects a tampered synthetic signature before revocation', async () => {
  const fixture = await syntheticSigningFixture();
  let revocationCalls = 0;
  const auth = await createResourceServerAuth({...config, ownerSubject: fixture.ownerSubject, jwks: fixture.jwks, revocationCheck: () => {revocationCalls++; return true;}}, {now: () => current * 1000});
  const parts = (await fixture.sign()).split('.');
  const signature = Buffer.from(parts[2], 'base64url');
  signature[0] ^= 1;
  parts[2] = signature.toString('base64url');
  await assert.rejects(auth.authenticate({authorization: 'Bearer ' + parts.join('.')}), authError());
  assert.equal(revocationCalls, 0);
});

test('real jose rejects signed expired, wrong-issuer and wrong-audience fixtures', async () => {
  const fixture = await syntheticSigningFixture();
  let revocationCalls = 0;
  const auth = await createResourceServerAuth({...config, ownerSubject: fixture.ownerSubject, jwks: fixture.jwks, revocationCheck: () => {revocationCalls++; return true;}}, {now: () => current * 1000});
  for (const patch of [
    {iat: current - 100, exp: current - 1},
    {iss: 'https://wrong-identity.example.invalid/tenant'},
    {aud: 'https://wrong-bridge.example.invalid/mcp'},
    {sub: 'wrong-synthetic-owner'},
  ]) {
    const token = await fixture.sign(patch);
    await assert.rejects(auth.authenticate({authorization: 'Bearer ' + token}), authError());
  }
  assert.equal(revocationCalls, 0);
});

const discovery = {issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token', jwks_uri: issuer + '/jwks', code_challenge_methods_supported: ['S256'], response_types_supported: ['code'], token_endpoint_auth_methods_supported: ['none'], client_id_metadata_document_supported: true};
test('IdP snapshot validation requires PKCE and an explicit actual registration method', () => {
  assert.equal(validateAuthorizationServerMetadata(discovery, {issuer, clientRegistration: 'cimd'}).clientRegistration, 'cimd');
  assert.equal(validateAuthorizationServerMetadata({...discovery, registration_endpoint: issuer + '/register'}, {issuer, clientRegistration: 'dcr'}).clientRegistration, 'dcr');
  assert.equal(validateAuthorizationServerMetadata(discovery, {issuer, clientRegistration: 'predefined', predefinedClientId: 'public-client-id'}).clientRegistration, 'predefined');
  for (const patch of [{issuer: issuer + '/'}, {code_challenge_methods_supported: []}, {authorization_endpoint: 'http://identity.invalid'}, {token_endpoint_auth_methods_supported: []}, {client_id_metadata_document_supported: false}, {response_types_supported: ['token']}]) assert.throws(() => validateAuthorizationServerMetadata({...discovery, ...patch}, {issuer, clientRegistration: 'cimd'}), TypeError);
  assert.throws(() => validateAuthorizationServerMetadata(discovery, {issuer, clientRegistration: 'dcr'}), /registration_endpoint/);
  assert.throws(() => validateAuthorizationServerMetadata(discovery, {issuer, clientRegistration: 'predefined'}), /predefined_client_id/);
});
