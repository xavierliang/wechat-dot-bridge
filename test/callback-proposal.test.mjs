import test from 'node:test';
import assert from 'node:assert/strict';
import {observedCallbackHost} from '../src/callback-proposal.mjs';
import {adminFixture,mcpInput} from './admin-fixtures.mjs';
const binding={scannerId:'synthetic-scanner-A',botId:'synthetic-bot'};
const secret='whsec_'+Buffer.alloc(32,17).toString('base64');
const proposal=()=>({name:'wechat.message.received',arguments:{sender_id:binding.scannerId},delivery:{mode:'webhook',url:'https://receiver.example.invalid/private-path?receiver=synthetic-private-value',secret},cursor:null});
async function boundFixture(t){
 const f=await adminFixture(t),b=f.browser();await b.login();const r=await b.request('/admin/ui/begin','POST');
 const requestId=r.body.match(/name="requestId" value="([^"]+)"/)[1];
 await b.request('/admin/ui/poll','POST',{requestId});assert.equal((await b.request('/admin/ui/confirm','POST',{requestId,scannerId:binding.scannerId})).status,200);
 return {...f,b,requestId,token:await f.issuer.access({},'bridge:mcp')};
}
test('callback proposal keeps only a canonical hostname',()=>{
 const p=proposal();p.delivery.url='https://RECEIVER.example.invalid:443/private-path?receiver=synthetic-private-value';
 assert.equal(observedCallbackHost(p,binding),'receiver.example.invalid');
});
test('callback proposal rejects malformed envelopes, identities, URLs and signing keys',()=>{
 const mutations=[p=>p.name='other.event',p=>p.arguments.sender_id='other-sender',p=>p.arguments.extra=true,p=>p.delivery.mode='poll',p=>p.delivery.extra=true,p=>p.delivery.secret='synthetic-invalid-key',p=>p.cursor='replay',p=>p.ttlMs=0,p=>p.ttlMs=Infinity,...['http://receiver.example.invalid/','https://user:pass@receiver.example.invalid/','https://receiver.example.invalid:444/','https://receiver.example.invalid/#fragment','https://127.0.0.1/','https://[::1]/','https://localhost/','not a URL','https://receiver.example.invalid/'+('x'.repeat(8192))].map(url=>p=>p.delivery.url=url)];
 for(const mutate of mutations){const p=proposal();mutate(p);assert.throws(()=>observedCallbackHost(p,binding));}
 assert.throws(()=>observedCallbackHost(proposal(),null));assert.throws(()=>observedCallbackHost(proposal(),{...binding,botId:binding.scannerId}));
 const missingSender=proposal();missingSender.arguments={};assert.throws(()=>observedCallbackHost(missingSender,{botId:binding.botId}));
});
test('actual authenticated bootstrap attempt exposes only an unapproved host and never saves or connects',async t=>{
 const f=await boundFixture(t),before=structuredClone(f.store.state),beforeTraffic=f.upstream.length;
 const result=await f.app.handle(mcpInput(f.token,'events/subscribe',proposal()));assert.equal(JSON.parse(result.body).error.message,'callbacks_not_configured');
 const status=JSON.parse((await f.app.handle(mcpInput(f.token,'tools/call',{name:'wechat_status'}))).body).result.structuredContent;
 assert.equal(status.unapprovedCallbackHost,'receiver.example.invalid');assert.equal(status.callbacksConfigured,false);assert.equal(status.phase,'awaiting_callback_configuration');
 const page=await f.b.request('/admin');assert.ok(page.body.includes('尚未批准或验证'));assert.ok(page.body.includes('receiver.example.invalid'));
 const exposed=JSON.stringify([result,status,page,f.logs,f.diagnostics]);for(const privateValue of [secret,'private-path','synthetic-private-value'])assert.ok(!exposed.includes(privateValue));
 assert.deepEqual(f.store.state,before);assert.deepEqual(f.config.callbackHosts,[]);assert.equal(f.callbacks.length,0);assert.equal(f.runtimes.length,0);assert.equal(f.upstream.length,beforeTraffic);
});
test('unauthenticated, wrong-owner, wrong-sender and unlinked attempts cannot publish a proposal',async t=>{
 const f=await boundFixture(t);
 for(const token of ['not-a-token',await f.issuer.access({sub:'other-owner'},'bridge:mcp')])assert.equal((await f.app.handle(mcpInput(token,'events/subscribe',proposal()))).status,401);
 const invalid=proposal();invalid.arguments.sender_id='other-sender';await f.app.handle(mcpInput(f.token,'events/subscribe',invalid));assert.equal(f.app.status().unapprovedCallbackHost,null);
 await f.b.request('/admin/ui/revoke','POST',{requestId:f.requestId});await f.app.handle(mcpInput(f.token,'events/subscribe',proposal()));assert.equal(f.app.status().unapprovedCallbackHost,null);assert.equal(f.callbacks.length,0);
});
test('revocation clears an observed hostname without enabling subscription or reply',async t=>{
 const f=await boundFixture(t);await f.app.handle(mcpInput(f.token,'events/subscribe',proposal()));assert.equal(f.app.status().unapprovedCallbackHost,'receiver.example.invalid');
 await f.b.request('/admin/ui/revoke','POST',{requestId:f.requestId});assert.equal(f.app.status().unapprovedCallbackHost,null);
 const reply=await f.app.handle(mcpInput(f.token,'tools/call',{name:'wechat_reply',arguments:{message_id:'synthetic',text:'synthetic',idempotency_key:'synthetic'}}));assert.equal(JSON.parse(reply.body).error.message,'callbacks_not_configured');
 assert.deepEqual(f.store.state.subscriptions,{});assert.equal(f.callbacks.length,0);assert.equal(f.runtimes.length,0);
});
