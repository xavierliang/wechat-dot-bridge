import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {ILinkClient} from '../src/ilink.mjs';
import {parseIlinkJson,normalizeMessageId} from '../src/ilink-json.mjs';
import {safePollBatchDiagnostic} from '../src/poll-diagnostics.mjs';
import {fixture,subscription} from './fixtures.mjs';
const SECRET_TEXT='SYNTHETIC_MESSAGE_CONTENT_NOT_REAL';
const rawMessage=(overrides={})=>({message_id:'WIRE_ID',from_user_id:'synthetic-owner',to_user_id:'synthetic-bot',message_type:1,message_state:2,context_token:'synthetic-context',create_time_ms:1801300000000,item_list:[{type:1,text_item:{text:SECRET_TEXT}}],...overrides});
function wire(idLiteral,{overrides={},cursor='next',ret}={}) {
 return JSON.stringify({...(ret===undefined?{}:{ret}),msgs:[rawMessage(overrides)],get_updates_buf:cursor}).replace('"message_id":"WIRE_ID"','"message_id":'+idLiteral);
}
function clientFor(raw,events=[],options={}) {
 return new ILinkClient({token:'synthetic-token',botId:'synthetic-bot',allowedSenders:['synthetic-owner'],transport:async()=>({status:200,body:typeof raw==='function'?raw():raw}),onPollDiagnostic:event=>events.push(event),...options});
}
test('native JSON source preserves exact uint64 tokens, quoted IDs and escaped property names',()=>{
 for(const id of ['0','123','9007199254740992','9007199254740993','18446744073709551615']){
  assert.equal(parseIlinkJson(wire(id)).msgs[0].message_id,id);
  assert.equal(parseIlinkJson(wire(JSON.stringify(id))).msgs[0].message_id,id);
 }
 const raw=wire('18446744073709551615').replace('"message_id"','"message_\\u0069d"');
 assert.equal(parseIlinkJson(raw).msgs[0].message_id,'18446744073709551615');
 const text='{"message_id":18446744073709551615} quote \\" \\\\ unicode 好';
 const parsed=parseIlinkJson(wire('19',{overrides:{item_list:[{type:1,text_item:{text}}]}}));
 assert.equal(parsed.msgs[0].item_list[0].text_item.text,text);
 assert.equal(parsed.msgs[0].create_time_ms,1801300000000);
 assert.throws(()=>parseIlinkJson('{"message_id":01}'));
});
test('ID validator accepts bounded decimal strings and safe numeric callers without repairing rounded IDs',()=>{
 for(const id of ['0','123','9007199254740993','18446744073709551615'])assert.equal(normalizeMessageId(id),id);
 assert.equal(normalizeMessageId('000123'),'123');assert.equal(normalizeMessageId(123),'123');
 for(const invalid of ['18446744073709551616','9'.repeat(100),'-1','1.0','1e3',' 1','+1','',null,{},true,-1,1.5,Number.MAX_SAFE_INTEGER+1,NaN,Infinity])assert.equal(normalizeMessageId(invalid),null);
});
test('actual client retains exact numeric and string IDs while keeping empty polls valid',async()=>{
 for(const id of ['9007199254740993','18446744073709551615']){
  for(const literal of [id,JSON.stringify(id)]){
   const result=await clientFor(wire(literal)).poll('previous');
   assert.equal(result.messages[0].id,id);assert.equal(result.messages[0].text,SECRET_TEXT);assert.equal(result.cursor,'next');
  }
 }
 const events=[];
 assert.deepEqual(await clientFor('{}',events).poll('previous'),{messages:[],cursor:'previous'});
 assert.deepEqual(events,[]);
});
test('adjacent uint64 IDs stay distinct and numeric/string duplicates deduplicate through encrypted state and event delivery',async t=>{
 const f=await fixture(t);await f.bridge.subscribe('principal',subscription());
 const events=[];
 let raw='{"msgs":['+JSON.stringify(rawMessage()).replace('"WIRE_ID"','9007199254740992')+','+JSON.stringify(rawMessage()).replace('"WIRE_ID"','9007199254740993')+'],"get_updates_buf":"one"}';
 const adapter=clientFor(()=>raw,events);
 f.bridge.adapter={...f.bridge.adapter,poll:(cursor,options)=>adapter.poll(cursor,options)};
 f.config.adapter=f.bridge.adapter;
 await f.bridge.pollOnce();await f.bridge.pump();
 assert.equal(Object.keys(f.store.state.inbox).length,2);assert.equal(Object.keys(f.store.state.outbox).length,2);
 raw=wire('"9007199254740993"',{cursor:'two'});
 await f.bridge.pollOnce();await f.bridge.pump();
 assert.equal(Object.keys(f.store.state.inbox).length,2);assert.equal(Object.keys(f.store.state.outbox).length,2);assert.equal(f.callbacks.length,3);
 await f.restart();await f.bridge.pollOnce();assert.equal(Object.keys(f.store.state.inbox).length,2);assert.equal(f.store.state.cursor,'two');
 for(const event of events){assert.equal(event.outcome,'mapped');assert.ok(!JSON.stringify(event).includes(SECRET_TEXT));}
});
test('invalid owner text ID rejects the whole batch without changing durable cursor or inbox',async t=>{
 const f=await fixture(t);f.store.state.cursor='keep';await f.store.save();
 const before=await readFile(f.dir+'/state.enc','utf8');
 for(const literal of ['18446744073709551616','"18446744073709551616"','-1','-0','1.5','1e3','null','false','""','{}','[]','"not-an-id"']){
  const events=[],adapter=clientFor(wire(literal),events);
  f.bridge.adapter={poll:(cursor,options)=>adapter.poll(cursor,options)};
  await assert.rejects(f.bridge.pollOnce(),/ilink_response_invalid/);
  assert.equal(f.store.state.cursor,'keep');assert.equal(Object.keys(f.store.state.inbox).length,0);
  assert.equal(events[0].outcome,'rejected');assert.equal(events[0].invalid_id,1);
  assert.equal(await readFile(f.dir+'/state.enc','utf8'),before);
 }
 const events=[],raw='{"msgs":['+JSON.stringify(rawMessage({message_id:'123'}))+','+JSON.stringify(rawMessage({message_id:'bad'}))+'],"get_updates_buf":"bad"}';
 const adapter=clientFor(raw,events);f.bridge.adapter={poll:(cursor,options)=>adapter.poll(cursor,options)};
 await assert.rejects(f.bridge.pollOnce(),/ilink_response_invalid/);
 assert.equal(events[0].normalized,1);assert.equal(events[0].outcome,'rejected');
 assert.equal(await readFile(f.dir+'/state.enc','utf8'),before);
});
test('unsupported content and unapproved senders are counted before ID checks without blocking allowed text',async()=>{
 const messages=[
  rawMessage({from_user_id:'unapproved',message_id:'bad',item_list:{}}),
  rawMessage({message_type:2,message_id:'bad'}),
  rawMessage({group_id:'synthetic-group',message_id:'bad'}),
  rawMessage({to_user_id:'other-bot',message_id:'bad'}),
  rawMessage({message_id:'bad',item_list:[{type:2,image_item:{}}]}),
  rawMessage({message_id:'123',context_token:null}),
  rawMessage({message_id:'123',create_time_ms:null}),
  rawMessage({message_id:'18446744073709551615'})
 ];
 const events=[],result=await clientFor(JSON.stringify({msgs:messages,get_updates_buf:'next'}),events).poll('old');
 assert.equal(result.messages.length,1);assert.equal(result.messages[0].id,'18446744073709551615');
 assert.equal(events[0].outcome,'mapped');
 for(const reason of ['sender','non_user','group','recipient','unsupported_content','missing_context','invalid_timestamp'])assert.equal(events[0][reason],1,reason);
 assert.equal(events[0].invalid_id,0);
});
test('malformed text structures reject safely, and diagnostic sink failure does not drop valid text',async()=>{
 for(const overrides of [{item_list:{}},{item_list:[null]}]){
  const events=[];await assert.rejects(clientFor(wire('"123"',{overrides}),events).poll('old'),/ilink_response_invalid/);
  assert.equal(events[0].malformed,1);assert.equal(events[0].outcome,'rejected');
 }
 const result=await clientFor(wire('"123"'),[],{onPollDiagnostic:()=>{throw Error('synthetic diagnostic failure');}}).poll();
 assert.equal(result.messages.length,1);
});
test('batch diagnostic logger emits only fixed outcome and bounded reason counts',()=>{
 const lines=[];
 safePollBatchDiagnostic({outcome:SECRET_TEXT,received:3,normalized:1,invalid_id:1,group:-1,sender:Infinity,malformed:'secret',headers:SECRET_TEXT,message_id:SECRET_TEXT,text:SECRET_TEXT,cursor:SECRET_TEXT,toJSON:()=>({secret:SECRET_TEXT})},line=>lines.push(line));
 const value=JSON.parse(lines[0]);
 assert.deepEqual(Object.keys(value).sort(),['time','event','outcome','received','normalized','invalid_id'].sort());
 assert.equal(value.event,'wechat_poll_batch');assert.equal(value.outcome,'rejected');assert.ok(!lines[0].includes(SECRET_TEXT));
});
test('same subscription identity refreshes finite TTL across restart; expired period has no replay',async t=>{
 const f=await fixture(t),p=subscription(),created=await f.bridge.subscribe('principal',p);
 const firstExpiry=Date.parse(created.refreshBefore);assert.equal(firstExpiry-1801300000000,3600000);
 f.advance(46*60000);
 const renewed=await f.bridge.subscribe('principal',p);
 assert.equal(renewed.id,created.id);assert.equal(Date.parse(renewed.refreshBefore)-firstExpiry,46*60000);
 await f.restart();assert.equal(Object.values(f.store.state.subscriptions)[0].expires,Date.parse(renewed.refreshBefore));
 f.advance(3600001);await f.bridge.pollOnce();assert.equal(Object.keys(f.store.state.inbox).length,1);assert.equal(Object.keys(f.store.state.outbox).length,0);
 const restored=await f.bridge.subscribe('principal',{...p,ttlMs:2*86400000});
 assert.equal(restored.id,created.id);assert.equal(Object.keys(f.store.state.subscriptions).length,1);
 assert.equal(Date.parse(restored.refreshBefore)-(1801300000000+46*60000+3600001),86400000);
 await f.bridge.pollOnce();assert.equal(Object.keys(f.store.state.outbox).length,0);
});
