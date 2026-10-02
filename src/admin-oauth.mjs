import * as oidc from 'openid-client';
import {createRestrictedHttpsTransport} from './security.mjs';
import {markLoginFailure,oauthFailureReason,ownerFailureReason} from './login-diagnostics.mjs';

export const ADMIN_PATH = '/admin';
export const ADMIN_CALLBACK_PATH = '/admin/oauth/callback';
export const ADMIN_SCOPES = 'openid bridge:admin';

// The only network dependency is operator-selected. Never use callback/query
// parameters to choose an issuer, token endpoint, redirect URI, or JWKS URL.
export function createAdminOAuth(config, clientSecret, {transport} = {}) {
 const issuer = new URL(config.issuer), origin = new URL(config.publicUrl).origin;
 if (issuer.protocol !== 'https:' || issuer.port || issuer.username || issuer.password || issuer.search || issuer.hash || !config.adminClientId || typeof clientSecret !== 'string' || !clientSecret.length) throw Error('admin_oauth_configuration_required');
 const redirectUri = origin + ADMIN_CALLBACK_PATH;
 const restricted = transport ?? createRestrictedHttpsTransport({allowedHosts:[issuer.hostname], timeoutMs:10000, maxResponseBytes:1048576});
 const safeFetch = async (url, options = {}) => {
  const target = new URL(url);
  if (target.origin !== issuer.origin || target.username || target.password || target.hash) throw Error('oauth_destination_rejected');
  const body = options.body == null ? '' : options.body instanceof URLSearchParams ? options.body.toString() : options.body;
  if (typeof body !== 'string') throw Error('oauth_body_rejected');
  const result = await restricted(target.toString(), {method:options.method ?? 'GET', headers:Object.fromEntries(new Headers(options.headers)), body, signal:options.signal});
  return new Response(result.body, {status:result.status, headers:result.headers});
 };
 let pending;
 async function getClient() {
  if (!pending) pending = (async () => {
   const client = await oidc.discovery(issuer, config.adminClientId,
    {id_token_signed_response_alg:'RS256'}, oidc.ClientSecretBasic(clientSecret),
    {[oidc.customFetch]:safeFetch, timeout:10, execute:[oidc.enableNonRepudiationChecks]});
   const metadata = client.serverMetadata();
   if (metadata.issuer !== config.issuer || !metadata.code_challenge_methods_supported?.includes('S256') || !metadata.response_types_supported?.includes('code') || !metadata.token_endpoint_auth_methods_supported?.includes('client_secret_basic')) throw Error('oauth_metadata_rejected');
   for (const name of ['authorization_endpoint','token_endpoint','jwks_uri']) {
    const endpoint = new URL(metadata[name]);
    if (endpoint.origin !== issuer.origin || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw Error('oauth_metadata_rejected');
   }
   return client;
  })().catch(error => {pending = undefined; throw markLoginFailure(Error('oauth_unavailable'),oauthFailureReason(error));});
  return pending;
 }
 return {
  async begin(transaction) {
   const client = await getClient();
   return oidc.buildAuthorizationUrl(client, {
    redirect_uri:redirectUri, response_type:'code', response_mode:'query',
    scope:ADMIN_SCOPES, audience:config.publicUrl, resource:config.publicUrl,
    code_challenge:await oidc.calculatePKCECodeChallenge(transaction.verifier),
    code_challenge_method:'S256', state:transaction.state, nonce:transaction.nonce,
    prompt:'login',
   }).toString();
  },
  async exchange(url, transaction) {
   try {
   const client = await getClient();
   const tokens = await oidc.authorizationCodeGrant(client, url, {
    expectedState:transaction.state, expectedNonce:transaction.nonce,
    pkceCodeVerifier:transaction.verifier, idTokenExpected:true,
   }, {resource:config.publicUrl});
   const claims = tokens.claims();
   if (!claims || claims.iss !== config.issuer || claims.sub !== config.ownerSubject || typeof tokens.access_token !== 'string' || tokens.token_type?.toLowerCase() !== 'bearer' || !Number.isSafeInteger(claims.exp)) throw markLoginFailure(Error('owner_login_rejected'),claims&&claims.sub!==config.ownerSubject?ownerFailureReason(claims.sub,config.ownerSubject):'id_response_invalid');
   // ID tokens and refresh tokens never leave this function. API access tokens
   // still undergo the independent resource-server signature/aud/scope checks.
   return {accessToken:tokens.access_token, idExpiresAt:claims.exp * 1000};
   } catch(error) {throw markLoginFailure(Error('oauth_exchange_failed'),oauthFailureReason(error));}
  },
 };
}
