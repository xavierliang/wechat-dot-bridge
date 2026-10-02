import test from 'node:test';
import assert from 'node:assert/strict';
import {safeLoginDiagnostic,oauthFailureReason,apiJwtFailureReason,markLoginFailure,loginFailureReason} from '../src/login-diagnostics.mjs';
import {adminFixture} from './admin-fixtures.mjs';

const sensitive='synthetic-secret-code-cookie-token-and-email';
function checked(f,response,stage,reason){
 const event=f.diagnostics.at(-1);assert.equal(event.stage,stage);assert.equal(event.reason,reason);
 assert.match(event.requestId,/^[a-f0-9]{16}$/);assert.ok(response.body.includes(event.requestId));
 assert.deepEqual(Object.keys(event).sort(),['reason','requestId','stage']);
 const lines=[];safeLoginDiagnostic(event,line=>lines.push(line));
 const serialized=JSON.stringify([response,lines]);assert.ok(!serialized.includes(sensitive));
 for(const token of f.issuer.accessTokens)assert.ok(!serialized.includes(token));
 assert.equal(response.status,400);assert.equal(response.headers['referrer-policy'],'no-referrer');
 assert.equal(f.upstream.length,0);return event;
}
test('diagnostic logger emits fixed fields and rejects arbitrary values or correlation data',()=>{
 const lines=[];safeLoginDiagnostic({stage:sensitive,reason:sensitive,requestId:'0123456789abcdef',claims:{secret:sensitive},error:sensitive},x=>lines.push(x));
 const event=JSON.parse(lines[0]);assert.equal(event.stage,'request');assert.equal(event.reason,'unclassified');
 assert.deepEqual(Object.keys(event).sort(),['event','reason','request_id','stage','time']);assert.ok(!lines[0].includes(sensitive));
 safeLoginDiagnostic({stage:'callback',reason:'unclassified',requestId:sensitive},x=>lines.push(x));assert.equal(lines.length,1);
 const error=markLoginFailure(Error(sensitive),sensitive);assert.equal(loginFailureReason(error),'unclassified');
});
test('library error classifiers inspect only bounded allowlisted codes and claim names',()=>{
 assert.equal(oauthFailureReason({code:'OAUTH_RESPONSE_BODY_ERROR',error:'invalid_client',error_description:sensitive}),'oauth_invalid_client');
 assert.equal(oauthFailureReason({code:'OAUTH_RESPONSE_BODY_ERROR',error:sensitive}),'oauth_provider_error');
 assert.equal(oauthFailureReason({code:'OAUTH_JWT_CLAIM_COMPARISON_FAILED',cause:{claim:'nonce',claims:{nonce:sensitive}}}),'id_nonce_invalid');
 assert.equal(oauthFailureReason({message:'transport_failed',cause:{secret:sensitive}}),'oauth_transport_failed');
 assert.equal(oauthFailureReason({message:sensitive,code:sensitive}),'oauth_exchange_failed');
 const loop={message:sensitive};loop.cause=loop;assert.equal(oauthFailureReason(loop),'oauth_exchange_failed');
 assert.equal(apiJwtFailureReason({code:'ERR_JWT_CLAIM_VALIDATION_FAILED',claim:'typ',payload:{secret:sensitive}}),'api_type_invalid');
 assert.equal(apiJwtFailureReason({code:'ERR_JWT_CLAIM_VALIDATION_FAILED',claim:'jti',reason:'missing'}),'api_jti_missing');
});
test('callback diagnostics distinguish missing cookie, wrong state and consumed transaction',async t=>{
 const f=await adminFixture(t),b=f.browser(),url=await b.begin();
 checked(f,await f.browser().request(url.pathname+url.search),'callback','callback_cookie_missing');
 const good=url.pathname+url.search;url.searchParams.set('state',sensitive);
 const first=checked(f,await b.request(url.pathname+url.search),'callback','callback_state_mismatch');
 const second=checked(f,await b.request(good),'callback','callback_transaction_missing');
 assert.notEqual(first.requestId,second.requestId);assert.equal(f.issuer.requests.filter(r=>r.url.endsWith('/oauth/token')).length,0);
});
test('provider error diagnostics require matching state and never log its description',async t=>{
 const f=await adminFixture(t),b=f.browser(),url=await b.begin();
 url.searchParams.delete('code');url.searchParams.set('error','access_denied');url.searchParams.set('error_description',sensitive);
 checked(f,await b.request(url.pathname+url.search),'callback','provider_access_denied');
 assert.equal(f.issuer.requests.filter(r=>r.url.endsWith('/oauth/token')).length,0);
});
test('expired callback session is rejected before any token exchange',async t=>{
 const f=await adminFixture(t),b=f.browser(),url=await b.begin();f.advance(300001);
 checked(f,await b.request(url.pathname+url.search),'callback','callback_session_unavailable');
 assert.equal(f.issuer.requests.filter(r=>r.url.endsWith('/oauth/token')).length,0);
});
test('provider denial with wrong state reports state failure without trusting provider data',async t=>{
 const f=await adminFixture(t),b=f.browser(),url=await b.begin();
 url.searchParams.delete('code');url.searchParams.set('state',sensitive);
 url.searchParams.set('error','access_denied');url.searchParams.set('error_description',sensitive);
 checked(f,await b.request(url.pathname+url.search),'callback','callback_state_mismatch');
 assert.equal(f.issuer.requests.filter(r=>r.url.endsWith('/oauth/token')).length,0);
});
for(const error of ['invalid_client','invalid_grant','invalid_target'])test('token endpoint diagnostics classify '+error+' without changing rejection',async t=>{
 const f=await adminFixture(t,{issuer:{tokenError:error,tokenErrorDescription:sensitive}}),b=f.browser(),url=await b.begin();
 checked(f,await b.request(url.pathname+url.search),'oauth_exchange','oauth_'+error);
});
for(const [label,options,stage,reason] of [
 ['ID issuer',{issuer:{idClaims:{iss:'https://other.invalid/'}}},'oauth_exchange','id_issuer_invalid'],
 ['ID audience',{issuer:{idClaims:{aud:'other-client'}}},'oauth_exchange','id_audience_invalid'],
 ['ID nonce',{issuer:{idClaims:{nonce:'wrong'}}},'oauth_exchange','id_nonce_invalid'],
 ['ID signature',{issuer:{badIdSignature:true}},'oauth_exchange','id_signature_invalid'],
 ['ID owner',{issuer:{idClaims:{sub:'different-owner'}}},'oauth_exchange','id_owner_mismatch'],
 ['database versus Google owner',{ownerSubject:'auth0|synthetic-owner',issuer:{idClaims:{sub:'google-oauth2|synthetic-user'}}},'oauth_exchange','id_owner_database_google_mismatch'],
 ['API owner',{issuer:{accessClaims:{sub:'different-owner'}}},'api_token','api_owner_mismatch'],
 ['API issuer',{issuer:{accessClaims:{iss:'https://other.invalid/'}}},'api_token','api_issuer_invalid'],
 ['API audience',{issuer:{accessClaims:{aud:'https://other.invalid/mcp'}}},'api_token','api_audience_invalid'],
 ['API scope',{issuer:{accessClaims:{scope:'openid'}}},'api_token','api_scope_missing'],
 ['API type',{issuer:{accessType:'JWT'}},'api_token','api_type_invalid'],
 ['API jti',{issuer:{accessClaims:{jti:undefined}}},'api_token','api_jti_missing'],
 ['API lifetime',{issuer:{accessClaims:{exp:Math.floor(Date.now()/1000)+7200}}},'api_token','api_lifetime_excessive'],
 ['API expiry',{issuer:{accessClaims:{exp:1}}},'api_token','api_expired'],
])test('validated diagnostics classify '+label+' and preserve authentication checks',async t=>{
 const f=await adminFixture(t,options),b=f.browser(),url=await b.begin();checked(f,await b.request(url.pathname+url.search),stage,reason);
});
test('successful synthetic login produces no failure diagnostic',async t=>{
 const f=await adminFixture(t);await f.browser().login();assert.deepEqual(f.diagnostics,[]);
});
