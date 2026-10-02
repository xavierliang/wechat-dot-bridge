// Diagnostics are classifications, never serialized errors, responses or claims.
const stages=new Set(['request','callback','oauth_begin','oauth_exchange','api_token','admin_action']);
const reasons=new Set([
 'unclassified','request_rejected','callback_cookie_missing','callback_session_unavailable',
 'callback_transaction_missing','callback_transaction_expired','callback_parameters_rejected',
 'callback_state_mismatch','callback_code_missing','callback_provider_error','login_expired','login_already_pending',
 'provider_invalid_request','provider_unauthorized_client','provider_access_denied','provider_invalid_scope',
 'provider_server_error','provider_temporarily_unavailable','provider_login_required','provider_consent_required',
 'provider_interaction_required','provider_invalid_target',
 'oauth_unavailable','oauth_exchange_failed','oauth_destination_rejected','oauth_transport_failed',
 'oauth_timeout','oauth_dns_failed','oauth_response_rejected','oauth_metadata_rejected',
 'oauth_invalid_client','oauth_invalid_grant','oauth_unauthorized_client','oauth_invalid_scope',
 'oauth_access_denied','oauth_invalid_request','oauth_invalid_target','oauth_provider_error',
 'id_issuer_invalid','id_audience_invalid','id_nonce_invalid','id_authorized_party_invalid',
 'id_timestamp_invalid','id_signature_invalid','id_key_unavailable','id_owner_mismatch','id_response_invalid','id_owner_database_google_mismatch',
 'api_token_invalid','api_issuer_invalid','api_audience_invalid','api_owner_mismatch',
 'api_type_invalid','api_signature_invalid','api_key_unavailable','api_expired',
 'api_required_claim_missing','api_jti_missing','api_lifetime_invalid','api_scope_invalid',
 'api_scope_missing','api_revocation_rejected','api_not_yet_valid','api_lifetime_excessive','api_owner_database_google_mismatch',
]);
const marked=new WeakMap();
export function markLoginFailure(error,reason){if(error&&typeof error==='object')marked.set(error,reasons.has(reason)?reason:'unclassified');return error;}
export function loginFailureReason(error,fallback='unclassified'){return marked.get(error)??(reasons.has(fallback)?fallback:'unclassified');}
const provider=new Map(['invalid_request','unauthorized_client','access_denied','invalid_scope','server_error','temporarily_unavailable','login_required','consent_required','interaction_required','invalid_target'].map(value=>[value,'provider_'+value]));
export function providerFailureReason(value){return provider.get(value)??'callback_provider_error';}
export function ownerFailureReason(actual,expected,kind='id'){
 const prefix=kind==='api'?'api':'id';
 return typeof actual==='string'&&typeof expected==='string'&&expected.startsWith('auth0|')&&actual.startsWith('google-oauth2|')?prefix+'_owner_database_google_mismatch':prefix+'_owner_mismatch';
}
const oauthErrors=new Map(['invalid_client','invalid_grant','unauthorized_client','invalid_scope','access_denied','invalid_request','invalid_target'].map(value=>[value,'oauth_'+value]));
const idClaims=new Map([['iss','id_issuer_invalid'],['aud','id_audience_invalid'],['nonce','id_nonce_invalid'],['azp','id_authorized_party_invalid'],['exp','id_timestamp_invalid'],['iat','id_timestamp_invalid'],['auth_time','id_timestamp_invalid']]);
const network=new Map([['callback_url_rejected','oauth_destination_rejected'],['callback_address_rejected','oauth_destination_rejected'],['oauth_destination_rejected','oauth_destination_rejected'],['transport_failed','oauth_transport_failed'],['timeout','oauth_timeout'],['aborted_or_timeout','oauth_timeout'],['response_failed','oauth_response_rejected'],['redirect_rejected','oauth_response_rejected'],['oauth_metadata_rejected','oauth_metadata_rejected']]);
export function oauthFailureReason(error){
 try{
  let fallback='oauth_exchange_failed';
  for(let item=error,depth=0;item&&typeof item==='object'&&depth<5;item=item.cause,depth++){
   if(marked.has(item))return marked.get(item);
   if(item.code==='OAUTH_RESPONSE_BODY_ERROR')return oauthErrors.get(item.error)??'oauth_provider_error';
   if(item.code==='OAUTH_JWT_TIMESTAMP_CHECK_FAILED')return 'id_timestamp_invalid';
   if(item.code==='OAUTH_KEY_SELECTION_FAILED')return 'id_key_unavailable';
   if(item.code==='OAUTH_JWT_CLAIM_COMPARISON_FAILED')fallback='id_response_invalid';
   if(item.code==='OAUTH_INVALID_RESPONSE'||item.code==='OAUTH_PARSE_ERROR')fallback='id_response_invalid';
   if(item.code==='OAUTH_RESPONSE_IS_NOT_JSON'||item.code==='OAUTH_RESPONSE_IS_NOT_CONFORM')fallback='oauth_response_rejected';
   if(item.code==='ENOTFOUND'||item.code==='EAI_AGAIN')return 'oauth_dns_failed';
   if(item.code==='ETIMEDOUT')return 'oauth_timeout';
   if(item.message==='JWT signature verification failed')return 'id_signature_invalid';
   if(idClaims.has(item.claim))return idClaims.get(item.claim);
   if(network.has(item.message))return network.get(item.message);
  }
  return fallback;
 }catch{return 'oauth_exchange_failed';}
}
export function apiJwtFailureReason(error){
 try{
  if(error?.code==='ERR_JWS_SIGNATURE_VERIFICATION_FAILED')return 'api_signature_invalid';
  if(error?.code==='ERR_JWKS_NO_MATCHING_KEY'||error?.code==='ERR_JWKS_MULTIPLE_MATCHING_KEYS')return 'api_key_unavailable';
  if(error?.code==='ERR_JWT_EXPIRED')return 'api_expired';
  if(error?.code==='ERR_JWT_CLAIM_VALIDATION_FAILED'){
   if(error.reason==='missing')return error.claim==='jti'?'api_jti_missing':'api_required_claim_missing';
   return new Map([['typ','api_type_invalid'],['iss','api_issuer_invalid'],['aud','api_audience_invalid'],['exp','api_lifetime_invalid'],['iat','api_lifetime_invalid'],['nbf','api_lifetime_invalid']]).get(error.claim)??'api_token_invalid';
  }
 }catch{}
 return 'api_token_invalid';
}
export function safeLoginDiagnostic({stage,reason,requestId},write=line=>process.stderr.write(line+'\n')){
 if(typeof requestId!=='string'||! /^[a-f0-9]{16}$/.test(requestId))return;
 write(JSON.stringify({time:new Date().toISOString(),event:'admin_login_rejected',stage:stages.has(stage)?stage:'request',reason:reasons.has(reason)?reason:'unclassified',request_id:requestId}));
}
