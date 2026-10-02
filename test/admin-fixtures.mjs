// Entirely synthetic IdP, JWTs, QR data and network transport. No real login,
// token, external request or WeChat account is used by these fixtures.
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {createHash} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../src/store.mjs';
import {createApplication} from '../src/application.mjs';
import {createAdminOAuth} from '../src/admin-oauth.mjs';
import {createResourceServerAuth,evaluateRevocation} from '../src/auth.mjs';
import {ILinkClient} from '../src/ilink.mjs';
import {KEY} from './fixtures.mjs';
import {PROTOCOL} from '../src/mcp.mjs';

const keyPromise=generateKeyPair('RS256');
export const ISSUER='https://identity.example.invalid/';
export const RESOURCE='https://bridge.example.invalid/mcp';
export const ORIGIN='https://bridge.example.invalid';
export const OWNER='synthetic-owner';
export const CLIENT_ID='synthetic-admin-client';
const SECRET='synthetic-client-secret-not-real';
const packet=body=>({status:200,headers:{'content-type':'application/json'},body:JSON.stringify(body)});

export async function fakeIssuer(options={}) {
 const pair=await keyPromise, jwk={...await exportJWK(pair.publicKey),kid:'synthetic-rsa',alg:'RS256',use:'sig',key_ops:['verify']};
 const codes=new Map(),requests=[],accessTokens=[];let serial=0;
 const metadata={issuer:ISSUER,authorization_endpoint:ISSUER+'authorize',token_endpoint:ISSUER+'oauth/token',jwks_uri:ISSUER+'jwks',response_types_supported:['code'],grant_types_supported:['authorization_code'],subject_types_supported:['public'],id_token_signing_alg_values_supported:['RS256'],code_challenge_methods_supported:['S256'],token_endpoint_auth_methods_supported:['client_secret_basic'],...options.metadata};
 async function jwt(payload,typ='at+jwt') {return new SignJWT(payload).setProtectedHeader({alg:'RS256',typ,kid:jwk.kid}).sign(pair.privateKey);}
 async function access(patch={},scope='bridge:admin') {
  const now=Math.floor(Date.now()/1000);
  const token=await jwt({iss:ISSUER,sub:OWNER,aud:RESOURCE,iat:now,exp:now+3600,jti:'synthetic-'+(++serial),scope,...patch},options.accessType??'at+jwt');accessTokens.push(token);return token;
 }
 function authorize(location) {
  const url=new URL(location);assert.equal(url.origin,new URL(ISSUER).origin);
  assert.equal(url.searchParams.get('client_id'),CLIENT_ID);assert.equal(url.searchParams.get('redirect_uri'),ORIGIN+'/admin/oauth/callback');
  assert.equal(url.searchParams.get('code_challenge_method'),'S256');assert.equal(url.searchParams.get('response_type'),'code');
  assert.equal(url.searchParams.get('scope'),'openid bridge:admin');assert.equal(url.searchParams.get('audience'),RESOURCE);assert.equal(url.searchParams.get('resource'),RESOURCE);
  const code='synthetic-code-'+(++serial);codes.set(code,Object.fromEntries(url.searchParams));
  const callback=new URL(ORIGIN+'/admin/oauth/callback');callback.searchParams.set('code',code);callback.searchParams.set('state',url.searchParams.get('state'));return callback;
 }
 const transport=async(url,request)=>{
  requests.push({url,method:request.method});
  if(url===ISSUER+'.well-known/openid-configuration')return packet(metadata);
  if(url===ISSUER+'jwks')return packet({keys:[jwk]});
  if(url!==ISSUER+'oauth/token')throw Error('synthetic_unexpected_destination');
  const body=new URLSearchParams(request.body),entry=codes.get(body.get('code'));codes.delete(body.get('code'));
  assert.ok(entry,'authorization code must be one-use');
  assert.equal(request.method,'POST');
  const basic=new Headers(request.headers).get('authorization');assert.ok(basic?.startsWith('Basic '));
  const credentials=Buffer.from(basic.slice(6),'base64').toString().split(':').map(x=>decodeURIComponent(x.replace(/\+/g,' ')));
  assert.deepEqual(credentials,[CLIENT_ID,SECRET]);
  assert.equal(body.get('grant_type'),'authorization_code');assert.equal(body.get('redirect_uri'),ORIGIN+'/admin/oauth/callback');
  assert.equal(createHash('sha256').update(body.get('code_verifier')).digest('base64url'),entry.code_challenge);
  assert.equal(body.get('resource'),RESOURCE);
  if(options.tokenError)return {status:401,headers:{'content-type':'application/json'},body:JSON.stringify({error:options.tokenError,error_description:options.tokenErrorDescription??'synthetic provider detail'})};
  if(options.tokenGate)await options.tokenGate();
  const now=Math.floor(Date.now()/1000);
  let id=await jwt({iss:ISSUER,sub:OWNER,aud:CLIENT_ID,iat:now,exp:now+3600,nonce:entry.nonce,...options.idClaims},'JWT');
  if(options.badIdSignature){const parts=id.split('.');parts[2]=(parts[2][0]==='A'?'B':'A')+parts[2].slice(1);id=parts.join('.');}
  return packet({access_token:await access(options.accessClaims),id_token:id,token_type:'Bearer',expires_in:3600,scope:'openid bridge:admin',...options.tokenResponse});
 };
 return {jwks:{keys:[jwk]},transport,authorize,access,accessTokens,requests,metadata};
}

export async function adminFixture(t,options={}) {
 const issuer=await fakeIssuer(options.issuer),dir=await mkdtemp(join(tmpdir(),'wechat-admin-test-'));
 const store=await Store.open(dir,KEY);let time=Date.now();
 const config={publicUrl:RESOURCE,issuer:ISSUER,ownerSubject:options.ownerSubject??OWNER,adminEnabled:true,adminClientId:CLIENT_ID,callbackHosts:options.callbackHosts??[],channelVersion:'0.1.0'};
 const verifier=await createResourceServerAuth({...config,resource:RESOURCE,jwks:issuer.jwks,revocationCheck:claims=>evaluateRevocation(claims,store.state.auth)});
 let authGate;const auth={...verifier,async authenticate(...args){await authGate?.();return verifier.authenticate(...args);}};
 const oauth=createAdminOAuth(config,SECRET,{transport:issuer.transport});
 const upstream=[],runtimes=[],callbacks=[],logs=[],diagnostics=[];let scanner='synthetic-scanner-A',qrSerial=0,qrGate;
 const qrTransport=async(url,request)=>{
  upstream.push({url,method:request.method});
  if(url.includes('get_bot_qrcode')){if(qrGate)await qrGate(request.signal);return packet({qrcode:'synthetic-private-qr-'+(++qrSerial),qrcode_img_content:'synthetic:qr-'+qrSerial});}
  if(url.includes('get_qrcode_status'))return packet({status:'confirmed',bot_token:'synthetic-private-bot-token',ilink_bot_id:'synthetic-bot',ilink_user_id:scanner,baseurl:'https://ilinkai.weixin.qq.com'});
  if(url.includes('getupdates'))return packet({ret:0,msgs:[],get_updates_buf:'synthetic-cursor'});
  throw Error('unexpected_synthetic_wechat_request');
 };
 class Runtime {constructor({bridge}){this.bridge=bridge;this.signal=new AbortController().signal;runtimes.push(this);}start(){this.phase='running';}async stop(){this.phase='stopped';await this.bridge.queue;}}
 const app=await createApplication({config,store,auth,adminOAuth:oauth,adminClock:()=>time,adminDiagnostic:event=>diagnostics.push(event),Runtime,clientFactory:opts=>new ILinkClient({...opts,transport:qrTransport}),callbackTransport:async(...args)=>{callbacks.push(args);throw Error('unexpected_callback');},log:e=>logs.push(e)});
 t.after(async()=>{await app.close();await rm(dir,{recursive:true});});
 function browser() {
  let cookie='',csrf='',last;
  async function request(path,method='GET',values={},extra={}) {
   const headers={cookie,...(method==='POST'?{'content-type':'application/x-www-form-urlencoded',origin:ORIGIN,'sec-fetch-site':'same-origin'}:{}),...extra.headers};
   const input={path,method,secure:true,headers,body:method==='POST'?new URLSearchParams({csrf,...values}).toString():'',...extra};input.headers=headers;
   last=await app.handle(input);
   const set=last.headers?.['set-cookie'];if(set)cookie=set.includes('Max-Age=0')?'':set.split(';')[0];
   const found=last.body?.match(/name="csrf" value="([A-Za-z0-9_-]+)"/);if(found)csrf=found[1];
   return last;
  }
  return {request,get cookie(){return cookie;},get csrf(){return csrf;},get last(){return last;},async begin(){await request('/admin');const r=await request('/admin/login','POST');assert.equal(r.status,303,r.body);return issuer.authorize(r.headers.location);},async login(){const url=await this.begin();const r=await request(url.pathname+url.search);assert.equal(r.status,303,r.body);assert.equal(r.headers.location,'/admin');const page=await request('/admin');assert.equal(page.status,200);return page;}};
 }
 return {app,store,issuer,config,upstream,runtimes,callbacks,logs,diagnostics,browser,advance:n=>{time+=n;},setScanner:n=>{scanner=n;},setQrGate:fn=>{qrGate=fn;},setAuthGate:fn=>{authGate=fn;}};
}

export function mcpInput(token,method,params={}) {
 return {path:'/mcp',method:'POST',secure:true,headers:{authorization:'Bearer '+token,'content-type':'application/json',accept:'application/json, text/event-stream','mcp-method':method,'mcp-protocol-version':PROTOCOL,...(method==='tools/call'?{'mcp-name':params.name}:{})},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params:{...params,_meta:{'io.modelcontextprotocol/protocolVersion':PROTOCOL,'io.modelcontextprotocol/clientCapabilities':{}}}})};
}
