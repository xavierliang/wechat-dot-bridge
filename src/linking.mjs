import {randomBytes} from 'node:crypto';
import {ILinkError} from './ilink.mjs';

const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const text=(x,max=256)=>typeof x==='string'&&x.length>0&&x.length<=max&&!/[\u0000-\u001f\u007f]/.test(x);
const ACTIVE=new Set(['waiting','scanned','needs_verification','awaiting_owner_confirmation']);
const STATUSES=new Set([...ACTIVE,'expired','blocked','already_bound','bound','revoked']);
const emptyState=()=>({version:1,request:null,binding:null});
const copy=x=>structuredClone(x);
const fail=code=>new ILinkError(code);

/** Owner-only, single-account linking. All persistence callbacks are trusted
 * internal functions; their inputs include credentials and must be encrypted.
 * principal must come from verified authentication, never request JSON.
 */
export class LinkingService {
 #client;#owner;#loadSecret;#saveSecret;#onBind;#onRevoke;#now;#ttl;
 #state;#queue=Promise.resolve();#failed=false;#activeController;
 constructor({client,ownerPrincipal,loadSecret,saveSecret,onBind,onRevoke,now=()=>Date.now(),ttlMs=300000}={}) {
  if(!client||typeof client.requestQr!=='function'||typeof client.pollQr!=='function'||typeof client.validateBaseUrl!=='function'||!text(ownerPrincipal,512)||typeof loadSecret!=='function'||typeof saveSecret!=='function'||typeof now!=='function'||onBind!==undefined&&typeof onBind!=='function'||onRevoke!==undefined&&typeof onRevoke!=='function')throw fail('link_dependencies_required');
  if(!Number.isSafeInteger(ttlMs)||ttlMs<1000||ttlMs>300000)throw fail('link_ttl_invalid');
  this.#client=client;this.#owner=ownerPrincipal;this.#loadSecret=loadSecret;this.#saveSecret=saveSecret;this.#onBind=onBind;this.#onRevoke=onRevoke;this.#now=now;this.#ttl=ttlMs;
 }
 #check(principal){if(principal!==this.#owner)throw fail('link_unauthorized');}
 #run(principal,fn){
  try{this.#check(principal);}catch(error){return Promise.reject(error);}
  const result=this.#queue.then(async()=>{if(this.#failed)throw fail('link_storage_unavailable');await this.#load();return fn();});
  this.#queue=result.catch(()=>{});return result;
 }
 #validIdentity(binding) {
  return object(binding)&&text(binding.scannerId)&&text(binding.botId)&&text(binding.token,16384)&&this.#client.validateBaseUrl(binding.baseUrl)===binding.baseUrl;
 }
 async #load(){
  if(this.#state!==undefined)return;
  try{
   const state=await this.#loadSecret();if(state==null){this.#state=emptyState();return;}
   if(!object(state)||state.version!==1)throw fail('link_state_invalid');
   const {request:r,binding:b}=state;
   if(r!==null&&(!object(r)||!/^link_[A-Za-z0-9_-]{32}$/.test(r.id)||r.ownerPrincipal!==this.#owner||!STATUSES.has(r.status)||!Number.isSafeInteger(r.createdAt)||!Number.isSafeInteger(r.expiresAt)||r.expiresAt-r.createdAt<1000||r.expiresAt-r.createdAt>300000))throw fail('link_state_invalid');
   if(r&&ACTIVE.has(r.status)){
    if(!text(r.qrcode,8192)||!text(r.qrContent,65536)||this.#client.validateBaseUrl(r.baseUrl)!==r.baseUrl)throw fail('link_state_invalid');
    if(r.status==='awaiting_owner_confirmation'&&!this.#validIdentity(r.candidate))throw fail('link_state_invalid');
   }
   if(b!==null&&(!this.#validIdentity(b)||b.ownerPrincipal!==this.#owner||!r||r.status!=='bound'||b.requestId!==r.id||!Number.isSafeInteger(b.boundAt)))throw fail('link_state_invalid');
   if(r?.status==='bound'&&!b)throw fail('link_state_invalid');
   this.#state=copy(state);
  }catch{this.#failed=true;throw fail('link_storage_unavailable');}
 }
 async #save(next,transition,signal){
  if(signal?.aborted)throw fail('ilink_aborted');
  try{await this.#saveSecret(copy(next),copy(transition),signal);this.#state=next;}
  catch(error){if(error.message==='ilink_aborted')throw fail('ilink_aborted');this.#failed=true;throw fail('link_storage_unavailable');}
 }
 #request(requestId){const r=this.#state.request;if(!r||requestId!==undefined&&r.id!==requestId)throw fail('link_request_not_found');return r;}
 #public(){
  const {request:r,binding:b}=this.#state;
  if(!r)return {status:'unlinked',linked:false};
  const view={requestId:r.id,status:r.status,linked:Boolean(b),expiresAt:new Date(r.expiresAt).toISOString()};
  if(r.status==='awaiting_owner_confirmation'){view.scannerId=r.candidate.scannerId;view.botId=r.candidate.botId;}
  if(b){view.scannerId=b.scannerId;view.botId=b.botId;}
  return view;
 }
 #strip(r,status){return {id:r.id,ownerPrincipal:r.ownerPrincipal,createdAt:r.createdAt,expiresAt:r.expiresAt,status};}
 async #expire(){
  const r=this.#state.request;
  if(r&&ACTIVE.has(r.status)&&this.#now()>=r.expiresAt){await this.#save({...this.#state,request:this.#strip(r,'expired')},{type:'expire'});return true;}
  return false;
 }
 #networkSignal(signal){
  const controller=new AbortController();this.#activeController=controller;
  return signal?AbortSignal.any([controller.signal,signal]):controller.signal;
 }
 async begin({principal,signal}={}){return this.#run(principal,async()=>{
  if(signal?.aborted)throw fail('ilink_aborted');
  await this.#expire();if(this.#state.binding)throw fail('link_already_active');
  if(this.#state.request&&ACTIVE.has(this.#state.request.status))throw fail('link_request_in_progress');
  const combined=this.#networkSignal(signal);let qr;
  try{qr=await this.#client.requestQr({signal:combined});}finally{this.#activeController=undefined;}
  if(combined.aborted)throw fail('ilink_aborted');
  if(!object(qr)||!text(qr.qrcode,8192)||!text(qr.qrContent,65536))throw fail('link_qr_invalid');
  const createdAt=this.#now();
  const request={id:`link_${randomBytes(24).toString('base64url')}`,ownerPrincipal:this.#owner,createdAt,expiresAt:createdAt+this.#ttl,status:'waiting',qrcode:qr.qrcode,qrContent:qr.qrContent,baseUrl:this.#client.validateBaseUrl(qr.baseUrl)};
  await this.#save({version:1,request,binding:null},{type:'begin'},signal);return this.#public();
 });}
 async status({principal,requestId}={}){return this.#run(principal,async()=>{
  await this.#expire();if(requestId!==undefined)this.#request(requestId);return this.#public();
 });}
 // Sole public credential-bearing route. Serve only on a secure, authenticated
 // owner screen with no-store/no-referrer, never an MCP tool or ordinary log.
 async secureChallenge({principal,requestId}={}){return this.#run(principal,async()=>{
  await this.#expire();if(!requestId)throw fail('link_request_not_found');const r=this.#request(requestId);
  if(!['waiting','scanned','needs_verification'].includes(r.status))throw fail('link_challenge_unavailable');
  return {requestId:r.id,expiresAt:new Date(r.expiresAt).toISOString(),qrContent:r.qrContent};
 });}
 async poll({principal,requestId,verifyCode,signal}={}){return this.#run(principal,async()=>{
  if(signal?.aborted)throw fail('ilink_aborted');
  await this.#expire();if(!requestId)throw fail('link_request_not_found');const r=this.#request(requestId);
  if(!ACTIVE.has(r.status)||r.status==='awaiting_owner_confirmation')return this.#public();
  if(verifyCode!==undefined&&(r.status!=='needs_verification'||typeof verifyCode!=='string'||!/^[0-9]{1,16}$/.test(verifyCode)))throw fail('link_verification_code_invalid');
  const combined=this.#networkSignal(signal);let result;
  try{result=await this.#client.pollQr({qrcode:r.qrcode,baseUrl:r.baseUrl,verifyCode,signal:combined});}finally{this.#activeController=undefined;}
  if(combined.aborted)throw fail('ilink_aborted');
  if(await this.#expire())return this.#public();
  const next=copy(this.#state);const request=next.request;
  switch(result?.status){
   case 'wait':if(request.status!=='needs_verification')request.status='waiting';break;
   case 'scaned':request.status='scanned';break;
   case 'need_verifycode':request.status='needs_verification';break;
   case 'scaned_but_redirect':request.baseUrl=this.#client.validateBaseUrl(result.baseUrl);request.status='scanned';break;
   case 'confirmed':
    if(!this.#validIdentity(result))throw fail('link_candidate_invalid');
    request.status='awaiting_owner_confirmation';request.candidate={scannerId:result.scannerId,botId:result.botId,token:result.token,baseUrl:result.baseUrl};break;
   case 'expired':next.request=this.#strip(request,'expired');break;
   case 'verify_code_blocked':next.request=this.#strip(request,'blocked');break;
   // This is not evidence that this particular owner previously trusted a
   // scanner. No credential or sender allowlist is invented from this status.
   case 'binded_redirect':next.request=this.#strip(request,'already_bound');break;
   default:throw fail('link_qr_status_invalid');
  }
  await this.#save(next,{type:'poll'},signal);return this.#public();
 });}
 async confirm({principal,requestId,scannerId,signal}={}){return this.#run(principal,async()=>{
  if(signal?.aborted)throw fail('ilink_aborted');
  await this.#expire();if(!requestId)throw fail('link_request_not_found');const r=this.#request(requestId);
  if(this.#state.binding&&this.#state.binding.requestId===requestId&&this.#state.binding.scannerId===scannerId)return this.#public();
  if(r.status!=='awaiting_owner_confirmation')throw fail('link_confirmation_unavailable');
  if(!text(scannerId)||scannerId!==r.candidate.scannerId)throw fail('link_scanner_mismatch');
  const binding={ownerPrincipal:this.#owner,requestId:r.id,...r.candidate,boundAt:this.#now()};
  const next={version:1,request:this.#strip(r,'bound'),binding};
  try{await this.#onBind?.(copy(binding));}catch{this.#failed=true;throw fail('link_commit_failed');}
  await this.#save(next,{type:'bind',binding},signal);return this.#public();
 });}
 // Internal daemon use only. Do not expose this method through any HTTP/MCP
 // response, serialization, logging, metrics or other caller-visible output.
 async getActiveBinding({principal}={}){return this.#run(principal,async()=>{await this.#expire();return copy(this.#state.binding);});}
 async revoke({principal,requestId,signal}={}){
  this.#check(principal);
  if(signal?.aborted)throw fail('ilink_aborted');
  // Abort a pending poll immediately, before waiting for the serialization
  // queue. Only the configured owner can interrupt it.
  this.#activeController?.abort();
  return this.#run(principal,async()=>{
   if(signal?.aborted)throw fail('ilink_aborted');
   if(!requestId)throw fail('link_request_not_found');const r=this.#request(requestId);
   const previousBinding=this.#state.binding;
   const next={version:1,request:this.#strip(r,'revoked'),binding:null};
   const view={principal:this.#owner,requestId:r.id,botId:previousBinding?.botId,scannerId:previousBinding?.scannerId};
   try{await this.#onRevoke?.(view);}catch{this.#failed=true;throw fail('link_revoke_failed');}
   await this.#save(next,{type:'revoke',previousBinding},signal);return this.#public();
  });
 }
}
