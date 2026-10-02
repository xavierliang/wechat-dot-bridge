import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {EventEmitter} from 'node:events';
import {Readable} from 'node:stream';
import {ILinkClient} from '../src/ilink.mjs';
import {createRestrictedHttpsTransport} from '../src/security.mjs';
import {sendDiagnostic,safeSendDiagnostic} from '../src/send-diagnostics.mjs';
import {fixture} from './fixtures.mjs';
const secret='SYNTHETIC_PRIVATE_SEND_VALUE_NOT_REAL';
const args={to:secret,contextToken:secret,text:secret,clientId:secret};
const packet=data=>({status:200,body:JSON.stringify(data)});
function setup(response,options={}){
 const events=[];let calls=0;
 const client=new ILinkClient({token:secret,botId:'synthetic-bot',transport:async(...params)=>{calls++;return typeof response==='function'?response(...params):response;},onSendDiagnostic:e=>events.push(e),...options});
 return {client,events,get calls(){return calls;}};
}
function checkSafe(f){
 assert.equal(f.events.length,1);const e=f.events[0];assert.ok(Number.isInteger(e.elapsedMs));
 assert.ok(!JSON.stringify(e).includes(secret));
 const lines=[];safeSendDiagnostic(e,line=>lines.push(line));assert.ok(!lines[0].includes(secret));assert.equal(JSON.parse(lines[0]).event,'wechat_send_result');
 return e;
}
test('send confirms explicit zero or a positive lossless server ID when ret is omitted',async()=>{
 for(const data of [{ret:0},{ret:0,errcode:0},{ret:0,errmsg:''},{message_id:'1'},{message_id:'9007199254740993'},{message_id:'18446744073709551615',errcode:0,errmsg:''},{ret:0,message_id:'123'}]){
  const f=setup(packet(data));assert.deepEqual(await f.client.reply(args),{accepted:true,state:'sent'});
  const e=checkSafe(f);assert.equal(e.outcome,'acknowledged');assert.equal(e.acknowledgement,data.ret===0?'ret_zero':'message_id');assert.equal(e.httpStatus,200);assert.equal(f.calls,1);
 }
 for(const id of ['9007199254740993','18446744073709551615']){
  const f=setup({status:200,body:'{"message_id":'+id+'}'});assert.equal((await f.client.reply(args)).accepted,true);assert.equal(checkSafe(f).messageIdValid,true);
 }
});
test('missing ret alone, zero errcode and ambiguous errmsg do not claim acknowledgement',async()=>{
 for(const data of [{},{errcode:0},{errmsg:''},{errmsg:secret},{message_id:'123',errmsg:secret}]){
  const f=setup(packet(data));assert.deepEqual(await f.client.reply(args),{accepted:false,state:'unknown'});
  const e=checkSafe(f);assert.equal(e.outcome,'unknown');assert.equal(e.acknowledgement,'none');assert.equal(e.reason,data.errmsg?'ambiguous_error':'acknowledgement_missing');assert.equal(f.calls,1);
 }
});
test('nonzero ret or errcode override valid acknowledgement fields',async()=>{
 for(const data of [{ret:1},{errcode:1},{ret:0,errcode:3},{ret:7,message_id:'123'},{message_id:'123',errcode:7},{ret:-2147483648,errmsg:secret},{ret:2147483647}]){
  const f=setup(packet(data));assert.deepEqual(await f.client.reply(args),{accepted:false,state:'rejected',code:'ilink_send_rejected'});
  const e=checkSafe(f);assert.equal(e.outcome,'rejected');assert.equal(e.reason,'upstream_error');assert.equal(f.calls,1);
 }
 for(const data of [{ret:-14},{ret:0,errcode:-14},{message_id:'123',ret:-14}]){
  const f=setup(packet(data));await assert.rejects(f.client.reply(args),e=>e.code==='ilink_session_expired'&&e.delivery==='unknown');assert.equal(checkSafe(f).outcome,'rejected');
 }
});
test('malformed code, ID and errmsg fields never acknowledge even with ret zero',async()=>{
 const invalid=[null,false,true,'0',{},[],0.5,2147483648,-2147483649];
 const packets=[];for(const field of ['ret','errcode'])for(const value of invalid)packets.push({...{ret:0},[field]:value,message_id:'123'});
 for(const message_id of [null,false,{},[],0,'0','0000','',secret,'18446744073709551616','-1','1.0','1e3','+1',' 1'])packets.push({ret:0,message_id});
 for(const errmsg of [null,1,false,{},[]])packets.push({ret:0,errmsg});
 for(const data of packets){const f=setup(packet(data));await assert.rejects(f.client.reply(args),/ilink_response_invalid/);const e=checkSafe(f);assert.equal(e.outcome,'unknown');assert.equal(e.reason,'fields_invalid');assert.equal(f.calls,1);}
 for(const literal of ['-0','-1','1.5','1e3','18446744073709551616']){
  const f=setup({status:200,body:'{"ret":0,"message_id":'+literal+'}'});await assert.rejects(f.client.reply(args),/ilink_response_invalid/);checkSafe(f);
 }
});
test('send HTTP, redirect, response-size and JSON failures have fixed classifications',async()=>{
 for(const [response,reason,status] of [
  [{status:503,body:secret},'http_failed',503],[{status:400,body:secret},'http_failed',400],[{status:302,body:secret},'redirect_rejected',302],
  [{status:200,body:secret},'json_invalid',200],[{status:200,body:''},'json_invalid',200],[packet(null),'response_invalid',200],[packet([]),'response_invalid',200],
  [{status:200,body:'x'.repeat(1048577)},'response_invalid',200],[{status:200,body:{}},'response_invalid',200],[{body:secret},'response_invalid',undefined]
 ]){
  const f=setup(response);await assert.rejects(f.client.reply(args));const e=checkSafe(f);assert.equal(e.reason,reason);assert.equal(e.httpStatus,status);assert.equal(e.outcome,'unknown');assert.equal(f.calls,1);
 }
});
function requester({status=200,body='{}',errorCode}={}){
 return (_url,_options,callback)=>{const req=new EventEmitter();req.end=()=>queueMicrotask(()=>{
  if(errorCode)return req.emit('error',Object.assign(Error(secret),{code:errorCode,cause:secret}));
  const res=new Readable({read(){}});res.statusCode=status;res.headers={'set-cookie':secret};callback(res);res.push(body);res.push(null);
 });return req;};
}
const restricted=options=>createRestrictedHttpsTransport({allowedHosts:['ilinkai.weixin.qq.com'],resolve:async()=>[{address:'8.8.8.8'}],...options});
test('send transport diagnostics preserve DNS TCP TLS deadline destination and size failures',async()=>{
 const transports=[
  [restricted({resolve:async()=>{throw Object.assign(Error(secret),{code:'ENOTFOUND'});}}),'dns_failed'],
  [restricted({requestImpl:requester({errorCode:'ECONNREFUSED'})}),'tcp_failed'],
  [restricted({requestImpl:requester({errorCode:'ERR_TLS_CERT_ALTNAME_INVALID'})}),'tls_failed'],
  [restricted({timeoutMs:10,resolve:async()=>new Promise(()=>{})}),'timeout'],
  [restricted({resolve:async()=>[{address:'127.0.0.1'}]}),'destination_rejected'],
  [restricted({maxResponseBytes:2,requestImpl:requester({body:secret})}),'response_too_large']
 ];
 for(const [transport,reason] of transports){const f=setup(null,{transport});await assert.rejects(f.client.reply(args),e=>e.code==='ilink_send_unknown'&&!e.retryable&&e.delivery==='unknown');assert.equal(checkSafe(f).reason,reason);}
});
test('preflight errors and both cancellation timings emit once without retries',async()=>{
 const bad=setup(packet({ret:0}));await assert.rejects(bad.client.reply({...args,text:''}),/ilink_reply_fields_required/);assert.equal(checkSafe(bad).code,'ilink_reply_fields_required');assert.equal(bad.calls,0);
 const controller=new AbortController();controller.abort();const f=setup(packet({ret:0}));await assert.rejects(f.client.reply({...args,signal:controller.signal}),/ilink_aborted/);assert.equal(checkSafe(f).code,'ilink_aborted');assert.equal(f.calls,0);
 const active=new AbortController(),g=setup((_url,{signal})=>new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(Error(secret)),{once:true})));
 const sending=g.client.reply({...args,signal:active.signal});active.abort();await assert.rejects(sending,/ilink_aborted/);checkSafe(g);assert.equal(g.calls,1);
});
test('send diagnostic allowlist drops sensitive fields, raw errors and injected values',()=>{
 const input={outcome:secret,stage:secret,reason:secret,code:secret,acknowledgement:secret,retType:secret,messageIdType:secret,ret:secret,errcode:Infinity,httpStatus:600,elapsedMs:-1,messageIdPresent:secret,messageIdValid:secret,errmsgNonempty:secret,body:secret,headers:secret,cause:secret,stack:secret,message_id:secret,client_id:secret,url:secret,toJSON:()=>({secret})};
 const e=sendDiagnostic(input);assert.deepEqual(e,{outcome:'unknown',stage:'request',reason:'unclassified',acknowledgement:'none'});
 const lines=[];safeSendDiagnostic(input,line=>lines.push(line));assert.ok(!lines[0].includes(secret));assert.equal(Object.keys(JSON.parse(lines[0])).length,6);
});
test('diagnostic sink failure cannot change send result or cause another attempt',async()=>{
 for(const data of [{ret:0},{message_id:'123'},{},{ret:5}]){const f=setup(packet(data),{onSendDiagnostic:()=>{throw Error(secret);}});const r=await f.client.reply(args);assert.equal(r.accepted,data.ret===0||!!data.message_id);assert.equal(f.calls,1);}
 const f=setup(()=>{throw Error(secret);},{onSendDiagnostic:()=>{throw Error(secret);}});await assert.rejects(f.client.reply(args),/ilink_send_unknown/);assert.equal(f.calls,1);
});
test('existing unknown replies remain byte-for-byte unchanged across adapter upgrade and restart',async t=>{
 const f=await fixture(t);await f.bridge.pollOnce();const id=Object.keys(f.store.state.inbox)[0];let attempts=0;
 f.bridge.adapter={reply:async()=>{attempts++;throw Error(secret);}};
 const reply={message_id:id,text:'synthetic reply',idempotency_key:'stable-unknown'};
 const old=await f.bridge.reply('principal',reply);assert.equal(old.state,'unknown');assert.equal(attempts,1);
 const before=structuredClone(f.store.state.replies),raw=await readFile(f.dir+'/state.enc','utf8');
 const upgraded=setup(packet({message_id:'123'}));f.config.adapter=upgraded.client;f.bridge.adapter=upgraded.client;
 assert.deepEqual(await f.bridge.reply('principal',reply),old);assert.deepEqual(f.store.state.replies,before);assert.equal(await readFile(f.dir+'/state.enc','utf8'),raw);
 await f.restart();assert.deepEqual(await f.bridge.reply('principal',reply),old);assert.deepEqual(f.store.state.replies,before);assert.equal(upgraded.calls,0);assert.deepEqual(upgraded.events,[]);
 await assert.rejects(f.bridge.reply('principal',{...reply,text:'changed'}),/idempotency_conflict/);assert.equal(upgraded.calls,0);
 const fresh={...reply,idempotency_key:'independent-new-request'};assert.equal((await f.bridge.reply('principal',fresh)).state,'sent');assert.equal(upgraded.calls,1);await f.restart();assert.equal((await f.bridge.reply('principal',fresh)).state,'sent');assert.equal(upgraded.calls,1);
});
