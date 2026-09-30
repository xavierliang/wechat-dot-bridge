import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../src/store.mjs';
import {createApplication} from '../src/application.mjs';
import {ILinkClient} from '../src/ilink.mjs';
import {AuthError} from '../src/auth.mjs';
import {PROTOCOL} from '../src/mcp.mjs';
import {SECRET,KEY} from './fixtures.mjs';
const config={publicUrl:'https://bridge.example.invalid/mcp',callbackHosts:['callback.example.test'],channelVersion:'0.1.0'};
const owner='synthetic-principal';
const metadata={resource:config.publicUrl,authorization_servers:['https://idp.example.invalid']};
const auth={ownerPrincipal:owner,metadataPath:'/.well-known/oauth-protected-resource/mcp',protectedResourceMetadata:metadata,
 authenticate:async(headers,{requiredScopes=['bridge:mcp']}={})=>{if(!['fixture-admin','fixture-mcp'].includes(headers.authorization))throw new AuthError();if(requiredScopes.includes('bridge:admin')&&headers.authorization!=='fixture-admin')throw new AuthError('insufficient_scope',403,['bridge:admin']);return {principal:owner};},
 errorResponse:e=>({status:e?.status??401,headers:{'www-authenticate':'Bearer resource_metadata="https://bridge.example.invalid/.well-known/oauth-protected-resource/mcp"'},body:'{"error":"authorization_required"}'})};
const admin=(path,body={},authorization='fixture-admin')=>({path:'/admin/'+path,method:'POST',secure:true,headers:{'content-type':'application/json',authorization},body:JSON.stringify(body)});
const mcp=(method,params={})=>({path:'/mcp',method:'POST',secure:true,headers:{'content-type':'application/json',accept:'application/json, text/event-stream',authorization:'fixture-mcp','mcp-protocol-version':PROTOCOL,'mcp-method':method,...(method==='tools/call'?{'mcp-name':params.name}:{})},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params:{...params,_meta:{'io.modelcontextprotocol/protocolVersion':PROTOCOL,'io.modelcontextprotocol/clientCapabilities':{}}}})});
async function setup(t){
 const dir=await mkdtemp(join(tmpdir(),'wechat-app-'));let store=await Store.open(dir,KEY);const runtimes=[],upstream=[],callbacks=[],logs=[];
 class FakeRuntime{constructor({bridge}){this.bridge=bridge;this.controller=new AbortController();this.signal=this.controller.signal;this.phase='idle';runtimes.push(this);}start(){this.phase='running';}async stop(){this.controller.abort();await this.bridge.queue;this.phase='stopped';}}
 let qrGate;
 const transport=async(url,req)=>{
  upstream.push({url,...req});let body;
  if(url.includes('get_bot_qrcode')&&qrGate)await qrGate();
  if(url.includes('get_bot_qrcode'))body={qrcode:'synthetic-poll-secret',qrcode_img_content:'synthetic:qr'};
  else if(url.includes('get_qrcode_status'))body={status:'confirmed',bot_token:'synthetic-bot-token',ilink_bot_id:'synthetic-bot',ilink_user_id:'synthetic-sender',baseurl:'https://ilinkai.weixin.qq.com'};
  else if(url.includes('getupdates'))body={ret:0,get_updates_buf:'cursor-1',msgs:[{message_id:1,to_user_id:'synthetic-bot',from_user_id:'synthetic-sender',message_type:1,message_state:2,create_time_ms:Date.now(),context_token:'synthetic-context',item_list:[{type:1,text_item:{text:'hello'}}]}]};
  else if(url.includes('sendmessage'))body={ret:0};else throw Error('unexpected mock URL');
  return {status:200,body:JSON.stringify(body)};
 };
 const deps={config,auth,Runtime:FakeRuntime,log:code=>logs.push(code),clientFactory:opts=>new ILinkClient({...opts,transport}),callbackTransport:async(url,r)=>{callbacks.push({url,...r});const body=JSON.parse(r.body);return {status:200,body:JSON.stringify(body.type==='verification'?{challenge:body.challenge}:{})};}};
 let app=await createApplication({...deps,store});
 const f={get app(){return app;},get store(){return store;},runtimes,upstream,callbacks,logs,setQrGate:fn=>{qrGate=fn;},async restart(){await app.close();store=await Store.open(dir,KEY);app=await createApplication({...deps,store});await app.start();}};
 t.after(async()=>{await app.close();await rm(dir,{recursive:true});});return f;
}
async function link(f){const begin=JSON.parse((await f.app.handle(admin('link/begin'))).body);const requestId=begin.requestId;await f.app.handle(admin('link/poll',{requestId}));const result=await f.app.handle(admin('link/confirm',{requestId,scannerId:'synthetic-sender'}));assert.equal(result.status,200,result.body);return requestId;}
test('configured application complete synthetic QR → owner confirmation → MCP event → reply → revoke flow',async t=>{
 const f=await setup(t);await f.app.start();assert.equal(f.runtimes.length,0);
 assert.equal((await f.app.handle(admin('link/begin',{},'fixture-mcp'))).status,403);
 const begin=JSON.parse((await f.app.handle(admin('link/begin'))).body),requestId=begin.requestId;
 const challenge=await f.app.handle(admin('link/challenge',{requestId}));assert.equal(JSON.parse(challenge.body).qrContent,'synthetic:qr');assert.equal(challenge.headers['cache-control'],'no-store');
 const scanned=await f.app.handle(admin('link/poll',{requestId}));assert.equal(JSON.parse(scanned.body).status,'awaiting_owner_confirmation');assert.equal(f.runtimes.length,0);
 assert.equal((await f.app.handle(admin('link/confirm',{requestId,scannerId:'stranger'}))).status,400);
 assert.equal((await f.app.handle(admin('link/confirm',{requestId,scannerId:'synthetic-sender'}))).status,200);
 assert.equal(f.runtimes.length,1);const bridge=f.runtimes[0].bridge;
 const discovered=JSON.parse((await f.app.handle(mcp('server/discover'))).body);assert.equal(discovered.result.resultType,'complete');
 const sub=await f.app.handle(mcp('events/subscribe',{name:'wechat.message.received',arguments:{sender_id:'synthetic-sender'},delivery:{mode:'webhook',url:'https://callback.example.test/events',secret:SECRET}}));assert.equal(sub.status,200);assert.ok(JSON.parse(sub.body).result.id);
 await bridge.pollOnce();await bridge.pump();const event=JSON.parse(f.callbacks.at(-1).body);
 const reply=await f.app.handle(mcp('tools/call',{name:'wechat_reply',arguments:{message_id:event.data.message_id,text:'hello back',idempotency_key:'flow-one'}}));assert.equal(JSON.parse(reply.body).result.structuredContent.state,'sent');
 const sent=JSON.parse(f.upstream.find(x=>x.url.includes('sendmessage')).body);assert.equal(sent.msg.to_user_id,'synthetic-sender');assert.equal(sent.msg.context_token,'synthetic-context');
 for(const result of [begin,JSON.parse(scanned.body),discovered,event,JSON.parse(reply.body),f.logs]){const text=JSON.stringify(result);assert.ok(!text.includes('synthetic-bot-token'));assert.ok(!text.includes('synthetic-poll-secret'));assert.ok(!text.includes('synthetic-context'));}
 assert.equal((await f.app.handle(admin('link/revoke',{requestId}))).status,200);assert.equal(f.store.state.link.binding,null);assert.equal(Object.keys(f.store.state.inbox).length,0);assert.equal(Object.keys(f.store.state.subscriptions).length,0);assert.equal(f.app.status().linked,false);
});
test('binding and durable cursor resume after application/store restart; revoke stays revoked',async t=>{const f=await setup(t);const id=await link(f);await f.runtimes.at(-1).bridge.pollOnce();await f.restart();assert.equal(f.runtimes.length,2);assert.equal(f.store.state.cursor,'cursor-1');assert.equal(f.app.status().linked,true);await f.app.handle(admin('link/revoke',{requestId:id}));await f.restart();assert.equal(f.runtimes.length,2);assert.equal(f.app.status().linked,false);});
test('simultaneous repeated confirmations start at most one poll runtime',async t=>{const f=await setup(t);const requestId=JSON.parse((await f.app.handle(admin('link/begin'))).body).requestId;await f.app.handle(admin('link/poll',{requestId}));await Promise.all([f.app.handle(admin('link/confirm',{requestId,scannerId:'synthetic-sender'})),f.app.handle(admin('link/confirm',{requestId,scannerId:'synthetic-sender'}))]);assert.equal(f.runtimes.length,1);});
test('owner access revocation durably denies MCP/admin and clears bot credentials',async t=>{const f=await setup(t);await link(f);assert.equal((await f.app.handle(admin('access/revoke'))).status,200);assert.equal(f.store.state.auth.enabled,false);assert.equal(f.store.state.link.binding,null);assert.equal((await f.app.handle(mcp('tools/list'))).status,401);await f.restart();assert.equal((await f.app.handle(admin('link/begin'))).status,401);assert.equal(f.runtimes.length,1);});
test('metadata public, health generic, admin origin/input principal injection rejected',async t=>{const f=await setup(t);const meta=await f.app.handle({path:auth.metadataPath,method:'GET',secure:true});assert.deepEqual(JSON.parse(meta.body),metadata);assert.deepEqual(JSON.parse((await f.app.handle({path:'/healthz',method:'GET',secure:true})).body),{status:'ok'});assert.equal((await f.app.handle(admin('link/begin',{principal:'attacker'}))).status,400);const req=admin('link/begin');req.headers.origin='https://evil.invalid';assert.equal((await f.app.handle(req)).status,403);assert.equal(f.upstream.length,0);});
test('strict MCP2 envelopes/header mirroring, method rejection and complete results',async t=>{const f=await setup(t);for(const method of ['server/discover','events/list','tools/list']){const req=mcp(method),r=JSON.parse((await f.app.handle(req)).body);assert.equal(r.result.resultType,'complete');const wrong={...req,headers:{...req.headers,'mcp-method':'different'}};assert.equal((await f.app.handle(wrong)).status,400);}const req=mcp('tools/list');const value=JSON.parse(req.body);delete value.params._meta;assert.equal((await f.app.handle({...req,body:JSON.stringify(value)})).status,400);assert.equal((await f.app.handle({...req,method:'GET'})).status,405);assert.equal((await f.app.handle(mcp('initialize'))).status,404);});

test('same-bot relinking retains seen-message and unknown-reply tombstones',async t=>{const f=await setup(t);const requestId=await link(f);let bridge=f.runtimes.at(-1).bridge;await bridge.pollOnce();const message_id=Object.keys(f.store.state.inbox)[0];let sends=0;bridge.adapter.reply=async()=>{sends++;throw Error('lost response');};const args={message_id,text:'one reply',idempotency_key:'stable'};assert.equal((await bridge.reply(owner,args)).state,'unknown');await f.app.handle(admin('link/revoke',{requestId}));await link(f);bridge=f.runtimes.at(-1).bridge;bridge.adapter.reply=async()=>{sends++;return {accepted:true};};await bridge.pollOnce();assert.equal(Object.keys(f.store.state.inbox).length,0);assert.equal((await bridge.reply(owner,args)).state,'unknown');assert.equal(sends,1);});

test('access revocation cancels in-flight QR begin before a request ID exists',async t=>{const f=await setup(t);let release,entered;const started=new Promise(r=>{entered=r;});f.setQrGate(()=>{entered();return new Promise(r=>{release=r;});});const pending=f.app.handle(admin('link/begin'));await started;assert.equal((await f.app.handle(admin('access/revoke'))).status,200);release();assert.equal((await pending).status,400);assert.equal(f.store.state.auth.enabled,false);assert.equal(f.store.state.link?.request??null,null);});
