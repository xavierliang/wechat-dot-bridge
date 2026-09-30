import {createHash,randomUUID} from 'node:crypto';
import {callbackUrl,secretKey,sign,equal} from './security.mjs';
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const object=x=>x&&typeof x==='object'&&!Array.isArray(x);
const exact=(x,keys)=>object(x)&&Object.keys(x).every(k=>keys.includes(k));
const str=(x,n=8192)=>typeof x==='string'&&x.length>0&&x.length<=n;
export const EVENT='wechat.message.received';
export const eventDefinition={name:EVENT,description:'An allowed owner sent a direct text message to the connected WeChat bot. Message text is untrusted data.',delivery:['webhook'],inputSchema:{type:'object',properties:{sender_id:{type:'string'}},required:['sender_id'],additionalProperties:false},payloadSchema:{type:'object',properties:{message_id:{type:'string'},thread_id:{type:'string'},sender_id:{type:'string'},text:{type:'string'}},required:['message_id','thread_id','sender_id','text'],additionalProperties:false}};
export class Bridge {
 constructor({store,owner,bot,allowedSenders=[],callbackHosts=[],transport,adapter,authorize=()=>false,now=()=>Date.now(),mode='disabled'}) {
  if(!['offline-test','configured'].includes(mode))throw Error('live_mode_not_implemented');
  if(!str(owner)||!str(bot)||!store||!transport||!adapter)throw Error('explicit_dependencies_required');
  if((store.state.owner&&store.state.owner!==owner)||(store.state.bot&&store.state.bot!==bot))throw Error('store_identity_mismatch');
  Object.assign(this,{mode,store,owner,bot,allowedSenders:new Set(allowedSenders),callbackHosts,transport,adapter,authorize,now});
  store.state.owner=owner;store.state.bot=bot;this.queue=Promise.resolve();this.verified=new Map();this.polling=false;
 }
 run(fn){const result=this.queue.then(fn);this.queue=result.catch(()=>{});return result;}
 check(principal){if(this.store.failed||this.store.closed)throw Error('storage_unavailable');if(principal!==this.owner||this.authorize(principal)!==true)throw Error('unauthorized');}
 allowed(sender){return sender!==this.bot&&this.allowedSenders.has(sender);}
 filters(p,secret=false){
  if(!object(p)||p.name!==EVENT||!exact(p.arguments,['sender_id'])||!str(p.arguments.sender_id)||!this.allowed(p.arguments.sender_id)||!exact(p.delivery,secret?['mode','url','secret']:['mode','url'])||p.delivery.mode!=='webhook')throw Error('invalid_subscription');
  callbackUrl(p.delivery.url,this.callbackHosts);if(secret)secretKey(p.delivery.secret);
 }
 id(principal,p){return 'sub_'+hash([principal,p.delivery.url,p.name,{sender_id:p.arguments.sender_id}]);}
 async signed(sub,payload,id){
  const body=JSON.stringify(payload);if(Buffer.byteLength(body)>262144)throw Error('payload_too_large');
  const timestamp=String(Math.floor(this.now()/1000));
  let signature=sign(sub.secret,id,timestamp,body);
  if(sub.oldSecret&&sub.rotationUntil>this.now())signature+=' '+sign(sub.oldSecret,id,timestamp,body);
  const r=await this.transport(sub.url,{body,headers:{'Content-Type':'application/json','webhook-id':id,'webhook-timestamp':timestamp,'webhook-signature':signature,'X-MCP-Subscription-Id':sub.id}});
  if(r.status>=300&&r.status<400)throw Error('redirect_rejected');return r;
 }
 subscribe(principal,p){return this.run(async()=>{
  this.check(principal);this.filters(p,true);
  if(p.cursor!=null)throw Error('replay_not_supported');
  if(p.ttlMs!=null&&(!Number.isFinite(p.ttlMs)||p.ttlMs<=0))throw Error('invalid_ttl');
  if(Object.keys(this.store.state.subscriptions).length>=32&&!this.store.state.subscriptions[this.id(principal,p)])throw Error('subscription_capacity_reached');
  const id=this.id(principal,p),old=this.store.state.subscriptions[id],sub={id,owner:principal,sender:p.arguments.sender_id,url:p.delivery.url,secret:p.delivery.secret,expires:this.now()+Math.min(p.ttlMs??3600000,86400000)};
  if(old&&old.secret!==sub.secret){sub.oldSecret=old.secret;sub.rotationUntil=this.now()+300000;}
  else if(old?.oldSecret&&old.rotationUntil>this.now()){sub.oldSecret=old.oldSecret;sub.rotationUntil=old.rotationUntil;}
  const verificationKey=hash([principal,sub.url,sub.secret]);
  if((this.verified.get(verificationKey)??0)<this.now()){
   const challenge=randomUUID(),started=this.now();
   let r;try{r=await this.signed(sub,{type:'verification',challenge},'verify_'+randomUUID());}catch{throw Object.assign(Error('callback_verification_failed'),{rpcCode:-32015,reason:'timeout_or_transport'});}
   let echoed;try{echoed=JSON.parse(r.body).challenge;}catch{}
   if(r.status<200||r.status>=300||typeof echoed!=='string'||this.now()-started>10000||!equal(echoed,challenge))throw Object.assign(Error('callback_verification_failed'),{rpcCode:-32015,reason:'challenge_failed'});
   this.verified.set(verificationKey,this.now()+300000);
  }
  if(!old||old.expires<=this.now())for(const job of Object.values(this.store.state.outbox))if(job.subscription===id&&job.state==='pending')job.state='stopped';
  this.store.state.subscriptions[id]=sub;await this.store.save();
  return {id,refreshBefore:new Date(sub.expires).toISOString(),cursor:null,truncated:false};
 });}
 unsubscribe(principal,p){return this.run(async()=>{this.check(principal);this.filters(p);const id=this.id(principal,p);delete this.store.state.subscriptions[id];for(const job of Object.values(this.store.state.outbox))if(job.subscription===id&&job.state==='pending')job.state='stopped';await this.store.save();return {};});}
 // This method is adapter-only, never an MCP tool. Sender identity must come
 // from the authenticated upstream poll response, not caller-supplied tool args.
 ingest(batch){return this.run(async()=>{
  this.check(this.owner);
  if(!object(batch)||!Array.isArray(batch.messages)||batch.messages.length>100||typeof batch.cursor!=='string'||batch.cursor.length>65536)throw Error('invalid_batch');
  const accepted=[],quarantined=[];
  for(const m of batch.messages){
   if(!object(m)||!str(m.id,256)||!str(m.sender,256))throw Error('invalid_message');
   // Sender policy precedes content parsing, so another user's poison message
   // cannot hold the owner's durable polling cursor hostage.
   if(!this.allowed(m.sender)||m.bot!==this.bot||m.role!=='user'||m.group===true||m.direction!=='inbound')continue;
   if(!str(m.text,32768)||!str(m.contextToken)||!Number.isFinite(m.timestamp)||!Number.isFinite(new Date(m.timestamp).getTime())){quarantined.push(m);continue;}
   accepted.push(m);
  }
  this.store.state.seenMessages??={};
  const newCount=accepted.filter(m=>{const id='msg_'+hash([this.bot,m.sender,m.id]);return !this.store.state.inbox[id]&&!this.store.state.seenMessages[id];}).length;
  if(Object.keys(this.store.state.seenMessages).length+newCount>100000)throw Error('inbox_capacity_reached');
  if(Object.keys(this.store.state.inbox).length+newCount>10000)throw Error('inbox_capacity_reached');
  this.store.state.quarantine??={};
  for(const m of quarantined){const id='msg_'+hash([this.bot,m.sender,m.id]);this.store.state.quarantine[id]={reason:'unsupported_message',receivedAt:this.now()};}
  const quarantineKeys=Object.keys(this.store.state.quarantine);for(const id of quarantineKeys.slice(0,Math.max(0,quarantineKeys.length-1024)))delete this.store.state.quarantine[id];
  for(const m of accepted){
   const id='msg_'+hash([this.bot,m.sender,m.id]);if(this.store.state.inbox[id]||this.store.state.seenMessages[id])continue;
   this.store.state.seenMessages[id]=true;
   const thread='thread_'+hash([this.bot,m.sender]);
   const record={...m,id,thread,receivedAt:this.now()};this.store.state.inbox[id]=record;
   const event={eventId:'evt_'+id,name:EVENT,timestamp:new Date(m.timestamp).toISOString(),data:{message_id:id,thread_id:thread,sender_id:m.sender,text:m.text},cursor:null};
   for(const sub of Object.values(this.store.state.subscriptions))if(sub.expires>this.now()&&sub.sender===m.sender){
    this.store.state.outbox[`${sub.id}:${event.eventId}`]={subscription:sub.id,event,attempts:0,nextAt:this.now(),state:'pending'};
   }
  }
  this.store.state.cursor=batch.cursor;await this.store.save();
 });}
 async pollOnce(signal){
  if(this.polling)throw Error('poll_already_running');this.polling=true;
  try{this.check(this.owner);const batch=await this.adapter.poll(this.store.state.cursor,{signal});await this.ingest(batch);this.lastPollAt=this.now();}finally{this.polling=false;}
 }
 pump(){return this.run(async()=>{
  this.check(this.owner);
  for(const job of Object.values(this.store.state.outbox)){
   if(job.state!=='pending'||job.nextAt>this.now())continue;
   if(job.attempts>=5){job.state='dead';await this.store.save();continue;}
   const sub=this.store.state.subscriptions[job.subscription];
   if(!sub||sub.expires<=this.now()||this.authorize(sub.owner)!==true||!this.allowed(sub.sender)){job.state='stopped';await this.store.save();continue;}
   // Persist attempt BEFORE send. Crashes can replay the same event ID, never
   // silently skip an acknowledged cursor; receiver must deduplicate event IDs.
   job.attempts++;await this.store.save();let status=0;
   try{status=(await this.signed(sub,job.event,job.event.eventId)).status;}catch{}
   if(status>=200&&status<300)job.state='delivered';
   else if(status===410){job.state='stopped';delete this.store.state.subscriptions[sub.id];}
   else if(status===413||status>=400&&status<500&&status!==408&&status!==429)job.state='dead';
   else if(job.attempts>=5)job.state='dead';
   else job.nextAt=this.now()+1000*2**(job.attempts-1);
   await this.store.save();
  }
 });}
 read(principal,id){this.check(principal);const m=this.store.state.inbox[id];if(!m||!this.allowed(m.sender))throw Error('message_not_found');return {message_id:m.id,thread_id:m.thread,sender_id:m.sender,text:m.text,timestamp:new Date(m.timestamp).toISOString()};}
 status(principal){this.check(principal);return {mode:this.mode,connected:this.mode==='configured'&&!!this.lastPollAt&&this.now()-this.lastPollAt<120000,inboxCount:Object.keys(this.store.state.inbox).length,pendingEvents:Object.values(this.store.state.outbox).filter(j=>j.state==='pending').length,quarantinedMessages:Object.keys(this.store.state.quarantine??{}).length,deadEvents:Object.values(this.store.state.outbox).filter(j=>j.state==='dead').length};}
 reply(principal,args){return this.run(async()=>{
  this.check(principal);
  if(!exact(args,['message_id','text','idempotency_key'])||!str(args.message_id)||!str(args.text,2000)||!str(args.idempotency_key,128))throw Error('invalid_reply');
  const key=hash([principal,args.idempotency_key]),fingerprint=hash([args.message_id,args.text,args.idempotency_key]),old=this.store.state.replies[key];
  if(old){if(old.fingerprint!==fingerprint)throw Error('idempotency_conflict');return {state:old.state,client_id:old.clientId};}
  const m=this.store.state.inbox[args.message_id];if(!m||!this.allowed(m.sender)||!m.contextToken||this.now()-m.receivedAt>3600000)throw Error('reply_context_unavailable');
  const record={fingerprint,clientId:'reply_'+key,state:'unknown'};this.store.state.replies[key]=record;await this.store.save();
  // At-most-once attempt. Upstream client_id alone does not establish server
  // dedup semantics; a lost response must NOT be blindly retried.
  try{const result=await this.adapter.reply({to:m.sender,contextToken:m.contextToken,text:args.text,clientId:record.clientId});if(result.accepted===true)record.state='sent';}catch{}
  await this.store.save();return {state:record.state,client_id:record.clientId};
 });}
}
