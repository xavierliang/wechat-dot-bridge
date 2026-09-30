import test from 'node:test';
import assert from 'node:assert/strict';
import {ILinkClient,ILinkError,ILINK_BASE_URL,validateIlinkBaseUrl,encodeClientVersion} from '../src/ilink.mjs';
import {LinkingService} from '../src/linking.mjs';
import {Store} from '../src/store.mjs';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

// Fixed, synthetic data only. These tests do not use DNS, real HTTPS, a login,
// a real QR code, credentials, a scanner, a send or an external service.
const TOKEN='synthetic-bot-token-not-real';
const QR='synthetic-qr-polling-value';
const QR_CONTENT='https://synthetic.invalid/qr-not-real';
const CONFIRMED={status:'confirmed',bot_token:TOKEN,ilink_bot_id:'synthetic-bot',ilink_user_id:'synthetic-scanner',baseurl:ILINK_BASE_URL};
const normalizedConfirmed={status:'confirmed',token:TOKEN,botId:'synthetic-bot',scannerId:'synthetic-scanner',baseUrl:ILINK_BASE_URL};
const principal='authenticated-owner';
const packet=x=>({status:200,body:JSON.stringify(x)});
function network(responses,options={}) {
 const calls=[];
 const transport=async(url,request)=>{calls.push({url,...request});const next=responses.shift();return typeof next==='function'?next(url,request):next;};
 return {calls,client:new ILinkClient({transport,token:TOKEN,botId:'synthetic-bot',...options})};
}
function linking(options={}) {
 let persisted=null,now=1801300000000,qrCalls=0,pollCalls=0;
 const transitions=[],bound=[],revoked=[];
 const qrResults=[normalizedConfirmed];
 const client={
  validateBaseUrl:validateIlinkBaseUrl,
  requestQr:async()=>{qrCalls++;return {qrcode:QR,qrContent:QR_CONTENT,baseUrl:ILINK_BASE_URL};},
  pollQr:async()=>{pollCalls++;return qrResults.shift();},
  ...options.client,
 };
 const config={client,ownerPrincipal:principal,now:()=>now,loadSecret:async()=>structuredClone(persisted),saveSecret:async(s,t)=>{persisted=structuredClone(s);transitions.push(structuredClone(t));},onBind:async b=>bound.push(b),onRevoke:async b=>revoked.push(b),...options};
 config.client=client;
 let service=new LinkingService(config);
 return {get service(){return service;},client,config,transitions,bound,revoked,qrResults,get persisted(){return persisted;},get qrCalls(){return qrCalls;},get pollCalls(){return pollCalls;},advance:n=>{now+=n;},restart:()=>{service=new LinkingService(config);return service;}};
}
async function candidate(f){const start=await f.service.begin({principal});const pending=await f.service.poll({principal,requestId:start.requestId});return {start,pending,args:{principal,requestId:start.requestId,scannerId:pending.scannerId}};}

 test('iLink authenticated POST metadata, uint32 UIN and cursor mapping',async()=>{
 const f=network([packet({ret:0,msgs:[{message_id:17,message_type:1,message_state:2,from_user_id:'synthetic-scanner',to_user_id:'synthetic-bot',context_token:'synthetic-context',create_time_ms:1801300000000,item_list:[{type:1,text_item:{text:'你好'}}]}],get_updates_buf:'next'})],{channelVersion:'2.4.8'});
 const result=await f.client.getUpdates({cursor:'previous'}),request=f.calls[0];
 assert.equal(request.url,`${ILINK_BASE_URL}/ilink/bot/getupdates`);assert.equal(request.method,'POST');
 assert.equal(request.headers.Authorization,`Bearer ${TOKEN}`);assert.equal(request.headers.AuthorizationType,'ilink_bot_token');assert.equal(request.headers['iLink-App-Id'],'bot');assert.equal(request.headers['iLink-App-ClientVersion'],'132104');
 const uin=Buffer.from(request.headers['X-WECHAT-UIN'],'base64').toString();assert.match(uin,/^\d+$/);assert.ok(Number(uin)<=4294967295);
 assert.deepEqual(JSON.parse(request.body),{get_updates_buf:'previous',base_info:{channel_version:'2.4.8',bot_agent:'DotBridge/0.1.0'}});
 assert.equal(result.cursor,'next');assert.equal(result.messages[0].text,'你好');assert.equal(result.messages[0].contextToken,'synthetic-context');
 });
 test('empty or missing response cursor preserves durable cursor',async()=>{
 const f=network([packet({ret:0,msgs:[],get_updates_buf:''}),packet({ret:0,msgs:[]})]);
 assert.deepEqual(await f.client.poll('keep-me'),{messages:[],cursor:'keep-me'});assert.deepEqual(await f.client.poll('keep-me'),{messages:[],cursor:'keep-me'});
 });
 test('session expiry -14 recognized on either field without leaking response',async()=>{
 for(const data of [{ret:-14,errmsg:TOKEN},{ret:0,errcode:-14,errmsg:TOKEN}]){
  const f=network([packet(data)]);await assert.rejects(f.client.poll(),e=>e.code==='ilink_session_expired'&&!JSON.stringify(e).includes(TOKEN));
 }
 });
 test('malformed updates rejected, cursor remains owned by durable caller',async()=>{
 for(const data of [{ret:0,msgs:[],get_updates_buf:17},{ret:0,get_updates_buf:'next'},{ret:0,msgs:[null],get_updates_buf:'next'},{msgs:[],get_updates_buf:'next'}]){
  const f=network([packet(data)]);await assert.rejects(f.client.poll('unchanged'),/ilink_response_invalid/);
 }
 });
 test('longpoll cancellation propagates external abort and is not retried',async()=>{
 const controller=new AbortController();let observed;
 const f=network([(_u,r)=>new Promise((_resolve,reject)=>{observed=r.signal;r.signal.addEventListener('abort',()=>reject(Error(TOKEN)),{once:true});})]);
 const poll=f.client.getUpdates({cursor:'previous',signal:controller.signal});controller.abort();
 await assert.rejects(poll,e=>e.code==='ilink_aborted'&&!e.retryable);assert.equal(observed,controller.signal);assert.equal(f.calls.length,1);
 });
 test('reply DTO acknowledgement required and unknown outcome never retried',async()=>{
 const args={to:'synthetic-scanner',contextToken:'synthetic-context',text:'Hi',clientId:'stable-id'};
 const f=network([packet({ret:0}),packet({}),()=>{throw Error(`credential ${TOKEN}`);}]);
 assert.deepEqual(await f.client.reply(args),{accepted:true,state:'sent'});
 assert.equal(JSON.parse(f.calls[0].body).msg.client_id,'stable-id');assert.equal(JSON.parse(f.calls[0].body).msg.context_token,'synthetic-context');
 assert.deepEqual(await f.client.reply(args),{accepted:false,state:'unknown'});
 await assert.rejects(f.client.reply(args),e=>e.code==='ilink_send_unknown'&&e.delivery==='unknown'&&!e.retryable&&!String(e).includes(TOKEN));assert.equal(f.calls.length,3);
 });
 test('reply negative response is rejected, session expiry classified',async()=>{
 const args={to:'a',contextToken:'c',text:'Hi',clientId:'id'};
 const f=network([packet({ret:12,errmsg:TOKEN}),packet({ret:-14})]);
 assert.equal((await f.client.reply(args)).state,'rejected');await assert.rejects(f.client.reply(args),/session_expired/);
 });
 test('HTTP redirects, non-JSON and diagnostic injection are sanitized',async()=>{
 for(const response of [{status:302,body:TOKEN},{status:503,body:TOKEN},{status:200,body:TOKEN},packet([TOKEN])]){
  const f=network([response]);await assert.rejects(f.client.poll(),e=>e instanceof ILinkError&&!String(e).includes(TOKEN)&&!JSON.stringify(e).includes(TOKEN));assert.equal(f.calls.length,1);
 }
 });
 test('QR request omits old tokens/auth and GET status omits POST auth headers',async()=>{
 const f=network([packet({qrcode:QR,qrcode_img_content:QR_CONTENT}),packet(CONFIRMED)]);
 assert.deepEqual(await f.client.requestQr(),{qrcode:QR,qrContent:QR_CONTENT,baseUrl:ILINK_BASE_URL});
 const first=f.calls[0];assert.equal(first.url,`${ILINK_BASE_URL}/ilink/bot/get_bot_qrcode?bot_type=3`);assert.deepEqual(JSON.parse(first.body),{local_token_list:[]});assert.equal(first.headers.Authorization,undefined);assert.equal(first.headers.AuthorizationType,'ilink_bot_token');
 const result=await f.client.pollQr({qrcode:QR,verifyCode:'1234'});const second=f.calls[1];
 assert.equal(second.method,'GET');assert.equal(second.body,'');assert.equal(new URL(second.url).searchParams.get('verify_code'),'1234');assert.equal(result.scannerId,'synthetic-scanner');
 for(const key of ['Authorization','AuthorizationType','X-WECHAT-UIN','Content-Type'])assert.equal(second.headers[key],undefined);
 });
 test('exact Tencent allowlist rejects arbitrary QR redirects/baseurls',async()=>{
 for(const raw of ['http://ilinkai.weixin.qq.com','https://ilinkai.weixin.qq.com.evil.test','https://evil.test','https://127.0.0.1','https://user@ilinkai.weixin.qq.com','https://ilinkai.weixin.qq.com:444','https://ilinkai.weixin.qq.com/path','https://ilinkai.weixin.qq.com?q=secret','https://ilinkai.weixin.qq.com#x'])assert.throws(()=>validateIlinkBaseUrl(raw));
 assert.throws(()=>validateIlinkBaseUrl('https://evil.test',['evil.test']));
 for(const result of [{status:'scaned_but_redirect',redirect_host:'evil.test'},{...CONFIRMED,baseurl:'https://evil.test'},{status:'scaned_but_redirect',redirect_host:'ilinkai.weixin.qq.com/evil'}]){
  const f=network([packet(result)]);await assert.rejects(f.client.pollQr({qrcode:QR}),/rejected/);assert.equal(f.calls.length,1);
 }
 const f=network([packet({status:'scaned_but_redirect',redirect_host:'synthetic.weixin.qq.com'})],{allowedHosts:['ilinkai.weixin.qq.com','synthetic.weixin.qq.com']});
 assert.deepEqual(await f.client.pollQr({qrcode:QR}),{status:'scaned_but_redirect',baseUrl:'https://synthetic.weixin.qq.com'});
 });
 test('version packing and metadata fail closed',()=>{
 assert.equal(encodeClientVersion('1.0.11'),'65547');for(const v of ['unknown','1.2','1.2.3-pre','256.0.0','-1.2.3'])assert.throws(()=>encodeClientVersion(v));
 assert.throws(()=>new ILinkClient({token:'\r\nsecret'}));
 });
 test('every linking route requires configured principal and exact request',async()=>{
 const f=linking();
 for(const method of ['begin','status','secureChallenge','poll','confirm','revoke','getActiveBinding'])await assert.rejects(f.service[method]({principal:'stranger',requestId:'unknown'}),/unauthorized/);
 assert.equal(f.qrCalls,0);
 const start=await f.service.begin({principal});
 for(const method of ['status','secureChallenge','poll','confirm','revoke'])await assert.rejects(f.service[method]({principal,requestId:'unknown'}),/request_not_found/);
 assert.match(start.requestId,/^link_[A-Za-z0-9_-]{32}$/);assert.equal(f.pollCalls,0);
 });
 test('ordinary linking results contain no QR or tokens; owner route only QR content',async()=>{
 const f=linking();const start=await f.service.begin({principal});
 const challenge=await f.service.secureChallenge({principal,requestId:start.requestId});assert.equal(challenge.qrContent,QR_CONTENT);assert.equal(challenge.qrcode,undefined);
 const pending=await f.service.poll({principal,requestId:start.requestId});const status=await f.service.status({principal});
 for(const result of [start,pending,status,JSON.stringify(f.service)])for(const secret of [TOKEN,QR,QR_CONTENT])assert.ok(!JSON.stringify(result).includes(secret));
 assert.equal(pending.status,'awaiting_owner_confirmation');assert.equal(pending.linked,false);assert.equal(pending.scannerId,'synthetic-scanner');assert.equal(f.bound.length,0);assert.equal(await f.service.getActiveBinding({principal}),null);
 await assert.rejects(f.service.secureChallenge({principal,requestId:start.requestId}),/unavailable/);
 });
 test('only one challenge and no implicit trust of scanning identity',async()=>{
 const f=linking(),{start,pending,args}=await candidate(f);
 await assert.rejects(f.service.begin({principal}),/in_progress/);assert.equal(f.qrCalls,1);
 await assert.rejects(f.service.confirm({...args,scannerId:'different-scanner'}),/scanner_mismatch/);
 assert.deepEqual(await f.service.poll({principal,requestId:start.requestId}),pending);assert.equal(f.pollCalls,1);
 const result=await f.service.confirm(args);assert.equal(result.status,'bound');assert.equal(result.linked,true);assert.equal(f.bound.length,1);
 assert.deepEqual(await f.service.confirm(args),result);assert.equal(f.bound.length,1);
 await assert.rejects(f.service.begin({principal}),/already_active/);
 });
 test('encrypted-storage callback holds whole pending state and survives restart',async()=>{
 const f=linking(),{start,args}=await candidate(f);assert.equal(f.persisted.request.candidate.token,TOKEN);
 f.restart();assert.equal((await f.service.status({principal})).status,'awaiting_owner_confirmation');await f.service.confirm(args);
 assert.equal(f.persisted.binding.token,TOKEN);assert.equal(f.persisted.request.qrcode,undefined);assert.equal(f.persisted.request.candidate,undefined);
 f.restart();const binding=await f.service.getActiveBinding({principal});assert.equal(binding.token,TOKEN);assert.equal(binding.requestId,start.requestId);binding.token='modified';assert.equal((await f.service.getActiveBinding({principal})).token,TOKEN);
 assert.equal(f.transitions.filter(t=>t.type==='bind').length,1);
 });
 test('local five-minute expiry erases pending credentials and rejects late confirmation',async()=>{
 const f=linking(),{args}=await candidate(f);f.advance(300000);
 assert.equal((await f.service.status({principal})).status,'expired');assert.equal(f.persisted.request.qrcode,undefined);assert.equal(f.persisted.request.candidate,undefined);
 await assert.rejects(f.service.confirm(args),/unavailable/);assert.equal(f.bound.length,0);
 assert.equal((await f.service.begin({principal})).status,'waiting');
 assert.throws(()=>linking({ttlMs:300001}),/ttl_invalid/);
 });
 test('expiry while network is pending cannot bind late scanner',async()=>{
 const f=linking({client:{pollQr:async()=>{f.advance(300000);return normalizedConfirmed;}}});const start=await f.service.begin({principal});
 assert.equal((await f.service.poll({principal,requestId:start.requestId})).status,'expired');assert.equal(f.persisted.request.candidate,undefined);
 });
 test('server expiry/blocked/already-bound never invent owner trust',async()=>{
 for(const [upstream,expected] of [['expired','expired'],['verify_code_blocked','blocked'],['binded_redirect','already_bound']]){
  const f=linking();f.qrResults[0]={status:upstream};const start=await f.service.begin({principal});
  assert.equal((await f.service.poll({principal,requestId:start.requestId})).status,expected);assert.equal(f.persisted.request.qrcode,undefined);assert.equal(await f.service.getActiveBinding({principal}),null);
 }
 });
 test('verification code accepted only on owner requested verification step',async()=>{
 const f=linking();f.qrResults[0]={status:'need_verifycode'};f.qrResults.push({status:'scaned'});const start=await f.service.begin({principal}),args={principal,requestId:start.requestId};
 await assert.rejects(f.service.poll({...args,verifyCode:'1234'}),/verification_code_invalid/);
 assert.equal((await f.service.poll(args)).status,'needs_verification');await assert.rejects(f.service.poll({...args,verifyCode:'not-a-code'}),/verification_code_invalid/);
 assert.equal((await f.service.poll({...args,verifyCode:'1234'})).status,'scanned');assert.ok(!JSON.stringify(f.persisted).includes('1234'));
 });
 test('revoke invalidates binding, pending secrets and invokes durable transition',async()=>{
 const f=linking(),{args}=await candidate(f);await f.service.confirm(args);const result=await f.service.revoke(args);
 assert.equal(result.status,'revoked');assert.equal(result.linked,false);assert.equal(f.revoked.length,1);assert.equal(f.revoked[0].token,undefined);
 assert.equal(await f.service.getActiveBinding({principal}),null);for(const secret of [TOKEN,QR,QR_CONTENT])assert.ok(!JSON.stringify(f.persisted).includes(secret));
 assert.equal(f.transitions.at(-1).type,'revoke');f.restart();assert.equal((await f.service.status({principal})).status,'revoked');await assert.rejects(f.service.confirm(args),/unavailable/);
 });
 test('owner revoke aborts concurrent longpoll and serializes final state',async()=>{
 let startedResolve;const started=new Promise(r=>{startedResolve=r;});
 const f=linking({client:{pollQr:({signal})=>new Promise((_resolve,reject)=>{startedResolve();signal.addEventListener('abort',()=>reject(new ILinkError('ilink_aborted')),{once:true});})}});
 const start=await f.service.begin({principal}),args={principal,requestId:start.requestId};
 const poll=f.service.poll(args);const failed=assert.rejects(poll,/aborted/);await started;
 const revoke=f.service.revoke(args);await failed;assert.equal((await revoke).status,'revoked');assert.equal(f.persisted.binding,null);
 });
 test('concurrent confirm/revoke ends revoked and cannot reuse credentials',async()=>{
 const f=linking(),{args}=await candidate(f);const confirmation=f.service.confirm(args),revocation=f.service.revoke(args);
 assert.equal((await confirmation).status,'bound');assert.equal((await revocation).status,'revoked');assert.equal(await f.service.getActiveBinding({principal}),null);
 });
 test('storage failure fails closed and sanitizes secret-bearing errors',async()=>{
 const f=linking({saveSecret:async()=>{throw Error(TOKEN);}});await assert.rejects(f.service.begin({principal}),e=>e.code==='link_storage_unavailable'&&!String(e).includes(TOKEN));await assert.rejects(f.service.status({principal}),/storage_unavailable/);
 const bad=linking({loadSecret:async()=>({version:1,request:{ownerPrincipal:'stranger'},binding:null})});await assert.rejects(bad.service.status({principal}),/storage_unavailable/);
 });
 test('restored pending challenge expires before it can be exposed',async()=>{
 const f=linking();const start=await f.service.begin({principal});f.advance(300001);f.restart();await assert.rejects(f.service.secureChallenge({principal,requestId:start.requestId}),/unavailable/);assert.equal(f.persisted.request.qrcode,undefined);
 });

 test('real encrypted Store hides pending QR and candidate token across restart',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'ilink-synthetic-'));const key=Buffer.alloc(32,53);let store=await Store.open(dir,key);
 t.after(async()=>{await store.close();await rm(dir,{recursive:true,force:true});});
 const f=linking({loadSecret:async()=>store.state.link??null,saveSecret:async next=>{store.state.link=next;await store.save();}});
 const {args}=await candidate(f);const raw=await readFile(join(dir,'state.enc'),'utf8');
 for(const secret of [TOKEN,QR,QR_CONTENT])assert.ok(!raw.includes(secret));
 await store.close();store=await Store.open(dir,key);f.restart();assert.equal((await f.service.status({principal})).status,'awaiting_owner_confirmation');
 await f.service.confirm(args);assert.equal((await f.service.getActiveBinding({principal})).token,TOKEN);
 await f.service.revoke(args);await store.close();store=await Store.open(dir,key);assert.equal(store.state.link.binding,null);assert.equal(store.state.link.request.candidate,undefined);
 });
