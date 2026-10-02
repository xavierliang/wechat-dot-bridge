import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {Readable} from 'node:stream';
import {ILinkClient} from '../src/ilink.mjs';
import {createRestrictedHttpsTransport} from '../src/security.mjs';
import {PollingRuntime} from '../src/runtime.mjs';
import {markPollFailure,pollFailureDiagnostic,safePollDiagnostic} from '../src/poll-diagnostics.mjs';

const secret='SYNTHETIC_PRIVATE_VALUE_NOT_REAL';
const client=transport=>new ILinkClient({token:secret,botId:'synthetic-bot',transport});
const packet=data=>({status:200,body:JSON.stringify(data)});
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function failure(transport) {
 let caught;
 try{await client(transport).poll(secret);}catch(error){caught=error;}
 assert.ok(caught);assert.ok(!JSON.stringify(caught).includes(secret));
 const event=pollFailureDiagnostic(caught,123);
 const lines=[];safePollDiagnostic(event,line=>lines.push(line));
 assert.equal(lines.length,1);assert.ok(!lines[0].includes(secret));
 return JSON.parse(lines[0]);
}
function requester({status=200,body='{}',errorCode}={}) {
 return (_url,_options,callback)=>{
  const req=new EventEmitter();
  req.end=()=>queueMicrotask(()=>{
   if(errorCode)return req.emit('error',Object.assign(Error(secret),{code:errorCode,cause:secret}));
   const res=new Readable({read(){}});res.statusCode=status;res.headers={'set-cookie':secret};
   callback(res);res.push(body);res.push(null);
  });
  return req;
 };
}
const restricted=options=>createRestrictedHttpsTransport({allowedHosts:['ilinkai.weixin.qq.com'],resolve:async()=>[{address:'8.8.8.8'}],...options});

test('poll failure diagnostics retain HTTP, JSON, application and schema distinctions',async()=>{
 for(const [response,expected] of [
  [{status:503,body:secret},{stage:'http',reason:'http_failed',code:'ilink_http_failed',httpStatus:503}],
  [{status:200,body:secret},{stage:'json',reason:'json_invalid',code:'ilink_response_invalid',httpStatus:200}],
  [packet({ret:-14,errmsg:secret}),{stage:'application',reason:'upstream_error',code:'ilink_session_expired',ret:-14,retType:'number',msgsType:'missing'}],
  [packet({errcode:27,errmsg:secret}),{stage:'application',code:'ilink_poll_failed',errcode:27,retType:'missing'}],
  [packet({msgs:secret,get_updates_buf:secret}),{stage:'normalize',reason:'fields_invalid',code:'ilink_response_invalid',retType:'missing',msgsType:'string',cursorType:'string'}],
  [packet({ret:secret,msgs:[]}),{stage:'application',code:'ilink_poll_failed',retType:'string'}],
 ]) {
  const event=await failure(async()=>response);
  for(const [key,value] of Object.entries(expected))assert.equal(event[key],value,key);
  assert.equal(event.event,'wechat_poll_failed');assert.equal(event.elapsedMs,123);
 }
});

test('DNS and request errors remain classified through restricted transport and client wrappers',async()=>{
 const dns=restricted({resolve:async()=>{throw Object.assign(Error(secret),{code:'ENOTFOUND'});},requestImpl:()=>assert.fail('no socket after DNS failure')});
 assert.equal((await failure(dns)).reason,'dns_failed');
 for(const [code,reason] of [['ECONNREFUSED','tcp_failed'],['ERR_TLS_CERT_ALTNAME_INVALID','tls_failed'],[secret,'transport_failed']]){
  const event=await failure(restricted({requestImpl:requester({errorCode:code})}));
  assert.equal(event.stage,'transport');assert.equal(event.reason,reason);assert.equal(event.code,'ilink_transport_failed');
 }
});

test('deadline, destination rejection, redirect and response cap remain failures with safe metadata',async()=>{
 const deadline=await failure(restricted({timeoutMs:10,resolve:async()=>new Promise(()=>{}),requestImpl:()=>assert.fail('no socket')}));
 assert.equal(deadline.reason,'timeout');assert.equal(deadline.code,'ilink_transport_failed');
 const rejected=await failure(restricted({resolve:async()=>[{address:'127.0.0.1'}],requestImpl:()=>assert.fail('no private request')}));
 assert.equal(rejected.reason,'destination_rejected');
 const redirected=await failure(restricted({requestImpl:requester({status:302,body:secret})}));
 assert.equal(redirected.reason,'redirect_rejected');assert.equal(redirected.httpStatus,302);
 const oversized=await failure(restricted({requestImpl:requester({body:secret}),maxResponseBytes:2}));
 assert.equal(oversized.reason,'response_too_large');assert.equal(oversized.httpStatus,200);
});

test('diagnostic allowlists exclude injected strings, sensitive fields and invalid numbers',()=>{
 const lines=[];
 const unsafe={stage:secret,reason:secret,code:secret,retType:secret,msgsType:secret,httpStatus:999,ret:secret,errcode:2**53,elapsedMs:-1,headers:secret,body:secret,cursor:secret,message:secret,url:secret,stack:secret,toJSON:()=>({secret})};
 const error=markPollFailure(Object.assign(Error(secret),{code:secret,cause:secret}),unsafe);
 safePollDiagnostic({...unsafe,...pollFailureDiagnostic(error,NaN)},line=>lines.push(line));
 const event=JSON.parse(lines[0]);
 assert.deepEqual(Object.keys(event).sort(),['time','event','stage','reason','code'].sort());
 assert.equal(event.code,'poll_failed');assert.equal(event.reason,'unclassified');assert.ok(!lines[0].includes(secret));
 for(const unknown of [undefined,null,secret,{},new Error(secret)]){
  const diagnostic=pollFailureDiagnostic(unknown,0);
  assert.equal(diagnostic.code,'poll_failed');assert.ok(!JSON.stringify(diagnostic).includes(secret));
 }
});

test('runtime recovers after a classified failure and omitted empty fields without backoff',async()=>{
 const responses=[{status:503,body:secret},packet({})],adapter=client(async()=>responses.shift());
 const events=[],phases=[],waits=[];let runtime;
 const bridge={queue:Promise.resolve(),pump:async()=>{},pollOnce:async signal=>{assert.deepEqual(await adapter.poll(secret,{signal}),{messages:[],cursor:secret});}};
 runtime=new PollingRuntime({bridge,onState:phase=>phases.push(phase),onDiagnostic:event=>events.push(event),wait:async(ms,signal)=>{
  if(ms>=1000){waits.push(ms);return;}
  if(runtime.phase==='running'){runtime.controller.abort();return;}
  await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));
 }});
 runtime.start();await runtime.done;
 assert.deepEqual(waits,[1000]);assert.equal(events.length,1);
 assert.equal(events[0].code,'ilink_http_failed');assert.equal(events[0].httpStatus,503);
 assert.deepEqual(phases,['starting','retrying','running']);assert.equal(responses.length,0);
 assert.ok(!JSON.stringify(events).includes(secret));assert.ok(Number.isInteger(events[0].elapsedMs));
});

test('runtime external cancellation is quiet and aborts the poll immediately',async()=>{
 const events=[],adapter=client((_url,{signal})=>new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(Error(secret)),{once:true})));
 const bridge={queue:Promise.resolve(),pump:async()=>{},pollOnce:signal=>adapter.poll(secret,{signal})};
 const runtime=new PollingRuntime({bridge,onDiagnostic:event=>events.push(event)}).start();
 await tick();await runtime.stop();assert.equal(runtime.phase,'stopped');assert.deepEqual(events,[]);
});

test('diagnostic sink failure does not prevent bounded backoff or session-expiry stop',async()=>{
 for(const expired of [false,true]){
  let runtime;const waits=[];
  const bridge={queue:Promise.resolve(),pump:async()=>{},pollOnce:async()=>{throw Object.assign(Error(secret),{code:expired?'ilink_session_expired':'ilink_http_failed'});}};
  runtime=new PollingRuntime({bridge,onDiagnostic:()=>{throw Error(secret);},wait:async(ms,signal)=>{
   if(ms>=1000){waits.push(ms);runtime.controller.abort();return;}
   if(!signal.aborted)await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));
  }});
  runtime.start();await runtime.done;
  assert.equal(runtime.phase,expired?'relink_required':'retrying');assert.deepEqual(waits,expired?[]:[1000]);
 }
});
