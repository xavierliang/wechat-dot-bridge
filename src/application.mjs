import {setTimeout as delay} from 'node:timers/promises';
import {Bridge} from './bridge.mjs';
import {ILinkClient} from './ilink.mjs';
import {LinkingService} from './linking.mjs';
import {PollingRuntime} from './runtime.mjs';
import {createResourceServerAuth,evaluateRevocation} from './auth.mjs';
import {createPinnedHttpsTransport} from './security.mjs';
import {createEndpoint} from './mcp.mjs';
import {safeLog} from './logging.mjs';
import {createAdminUI} from './admin-ui.mjs';
const object=x=>x&&typeof x==='object'&&!Array.isArray(x);
const exact=(x,keys)=>object(x)&&Object.keys(x).every(k=>keys.includes(k));
const response=(status,value)=>({status,headers:{'content-type':'application/json','cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'},body:JSON.stringify(value)});
const clearMessages=state=>{state.seenMessages??={};for(const id of Object.keys(state.inbox))state.seenMessages[id]=true;state.bot=null;state.cursor='';state.inbox={};state.subscriptions={};state.outbox={};state.quarantine={};};
// Dependency injection is exclusively for offline tests. Main wires only the
// concrete OAuth verifier, restricted HTTPS transports and persistent Store.
export async function createApplication({config,store,jwks,auth:injectedAuth,clientFactory=opts=>new ILinkClient(opts),callbackTransport,Runtime=PollingRuntime,log=safeLog,adminOAuth,adminClock}){
 if(config.adminEnabled&&!adminOAuth)throw Error('admin_oauth_required');
 const callbacksConfigured=Array.isArray(config.callbackHosts)&&config.callbackHosts.length>0;
 if(!store.state.auth)store.state.auth={enabled:true,revokedBefore:0,revokedTokenIds:[]};
 const auth=injectedAuth??await createResourceServerAuth({issuer:config.issuer,resource:config.publicUrl,ownerSubject:config.ownerSubject,jwks,revocationCheck:claims=>evaluateRevocation(claims,store.state.auth)});
 const owner=auth.ownerPrincipal;
 if(store.state.owner&&store.state.owner!==owner)throw Error('store_identity_mismatch');
 store.state.owner=owner;await store.save();
 let bridge=null,runtime=null,accepting=false,closed=false,inFlight=0;const accessController=new AbortController();
 const principalActive=p=>!closed&&!store.failed&&!store.closed&&store.state.auth.enabled===true&&p===owner;
 async function suspend(){accepting=false;if(runtime)await runtime.stop();if(bridge)await bridge.queue;runtime=null;bridge=null;}
 const callbacks=callbackTransport??createPinnedHttpsTransport(config.callbackHosts);
 const linker=new LinkingService({ownerPrincipal:owner,client:clientFactory({channelVersion:config.channelVersion}),loadSecret:async()=>store.state.link??null,
  onRevoke:async()=>suspend(),
  saveSecret:async(next,transition,signal)=>{
   if(signal?.aborted)throw Error('ilink_aborted');
   if(transition.type!=='revoke'&&!principalActive(owner))throw Error('access_revoked');
   if(['bind','revoke'].includes(transition.type))await suspend();
   if(signal?.aborted)throw Error('ilink_aborted');
   if(transition.type!=='revoke'&&!principalActive(owner))throw Error('access_revoked');
   if(['bind','revoke'].includes(transition.type))clearMessages(store.state);
   store.state.link=next;await store.save();
  }});
 async function reconcile(){
  if(closed||runtime||!callbacksConfigured)return;
  const binding=await linker.getActiveBinding({principal:owner});if(!binding||!principalActive(owner)||runtime||closed)return;
  const client=clientFactory({channelVersion:config.channelVersion,baseUrl:binding.baseUrl,token:binding.token,botId:binding.botId});
  let nextRuntime;
  bridge=new Bridge({store,owner,bot:binding.botId,allowedSenders:[binding.scannerId],callbackHosts:config.callbackHosts,mode:'configured',
   authorize:p=>principalActive(p)&&accepting&&!nextRuntime?.signal.aborted,
   transport:(url,req)=>callbacks(url,{...req,signal:nextRuntime?.signal}),
   adapter:{poll:(cursor,{signal}={})=>client.poll(cursor,{signal}),reply:args=>client.reply({...args,signal:nextRuntime?.signal})}});
  nextRuntime=new Runtime({bridge,onState:log});runtime=nextRuntime;accepting=true;await store.save();if(closed||runtime!==nextRuntime){await nextRuntime.stop();return;}runtime.start();
 }
 const facade={
  check(p){if(!principalActive(p))throw Error('unauthorized');},
  status(p){this.check(p);return {mode:callbacksConfigured?'configured':'bootstrap',callbacksConfigured,linked:!!store.state.link?.binding,connected:bridge?.lastPollAt?Date.now()-bridge.lastPollAt<120000&&runtime?.phase==='running':false,phase:callbacksConfigured?(runtime?.phase??'unlinked'):'awaiting_callback_configuration',inboxCount:Object.keys(store.state.inbox).length,pendingEvents:Object.values(store.state.outbox).filter(x=>x.state==='pending').length,quarantinedMessages:Object.keys(store.state.quarantine??{}).length,deadEvents:Object.values(store.state.outbox).filter(x=>x.state==='dead').length};},
  required(){if(!bridge||!accepting)throw Error('wechat_not_linked');return bridge;},
  read(p,id){return this.required().read(p,id);},reply(p,args){if(!callbacksConfigured)throw Error('callbacks_not_configured');return this.required().reply(p,args);},subscribe(p,args){if(!callbacksConfigured)throw Error('callbacks_not_configured');return this.required().subscribe(p,args);},unsubscribe(p,args){return this.required().unsubscribe(p,args);}
 };
 const endpoint=createEndpoint(facade,{authenticate:auth.authenticate,allowedOrigins:[new URL(config.publicUrl).origin],authFailure:auth.errorResponse});
 const adminUi=config.adminEnabled?createAdminUI({config,auth,oauth:adminOAuth,dispatch:handle,status:()=>facade.status(owner),...(adminClock?{now:adminClock}:{})}):undefined;
 async function handle(input){
  if(closed)return response(503,{error:'unavailable'});
  if(inFlight>=32)return response(429,{error:'busy'});inFlight++;
  try{
   const {path,method,headers={},secure=false}=input;
   if(!secure)return response(400,{error:'TLS_required'});
   if(adminUi?.handles(path))return await adminUi.handle(input);
   if(path==='/healthz'&&method==='GET')return response(store.failed?503:200,{status:store.failed?'unavailable':'ok'});
   if(path===auth.metadataPath&&method==='GET')return response(200,auth.protectedResourceMetadata);
   if(path==='/mcp')return await endpoint(input);
   if(!path.startsWith('/admin/'))return response(404,{error:'not_found'});
   if(method!=='POST')return response(405,{error:'method_not_allowed'});
   if(headers.origin&&headers.origin!==new URL(config.publicUrl).origin)return response(403,{error:'origin_rejected'});
   if(!/^application\/json(?:;|$)/i.test(headers['content-type']??''))return response(415,{error:'content_type'});
   let identity;try{identity=await auth.authenticate(headers,{requiredScopes:['bridge:admin']});facade.check(identity.principal);}catch(e){return auth.errorResponse(e,['bridge:admin']);}
   if(typeof input.body!=='string'||Buffer.byteLength(input.body)>16384)return response(413,{error:'body_too_large'});
   let body;try{body=JSON.parse(input.body);}catch{return response(400,{error:'invalid_json'});}
   const principal=identity.principal,linkSignal=input.signal?AbortSignal.any([input.signal,accessController.signal]):accessController.signal;let result;
   if(linkSignal.aborted)throw Error('ilink_aborted');
   switch(path){
    case '/admin/link/begin':if(!exact(body,[]))throw Error('invalid_arguments');result=await linker.begin({principal,signal:linkSignal});break;
    case '/admin/link/status':if(!exact(body,['requestId']))throw Error('invalid_arguments');result=await linker.status({principal,...body});break;
    case '/admin/link/challenge':if(!exact(body,['requestId']))throw Error('invalid_arguments');result=await linker.secureChallenge({principal,...body});break;
    case '/admin/link/poll':if(!exact(body,['requestId','verifyCode']))throw Error('invalid_arguments');result=await linker.poll({principal,...body,signal:linkSignal});break;
    case '/admin/link/confirm':if(!exact(body,['requestId','scannerId']))throw Error('invalid_arguments');result=await linker.confirm({principal,...body,signal:linkSignal});if(linkSignal.aborted)throw Error('ilink_aborted');await reconcile();break;
    case '/admin/link/revoke':if(!exact(body,['requestId']))throw Error('invalid_arguments');result=await linker.revoke({principal,...body,signal:linkSignal});break;
    case '/admin/access/revoke':
     if(!exact(body,[]))throw Error('invalid_arguments');
     // Disable persistent access first; queued operations fail closed. New IdP
     // tokens do not silently re-enable this owner. Offline recovery is required.
     store.state.auth.enabled=false;accessController.abort();accepting=false;await store.save();await suspend();if(store.state.link?.request?.id)await linker.revoke({principal,requestId:store.state.link.request.id});store.state.subscriptions={};for(const job of Object.values(store.state.outbox))if(job.state==='pending')job.state='stopped';await store.save();result={revoked:true};break;
    default:return response(404,{error:'not_found'});
   }
   return response(200,result);
  }catch(e){log('request_failed');const code=e.code??e.message;return response(store.failed?503:400,{error:typeof code==='string'&&/^(link_|ilink_)[a-z_]+$/.test(code)?code:'operation_failed'});}
  finally{inFlight--;}
 }
 // Caller chooses whether to start polling after fully validating runtime config.
 return {handle,auth,linker,status:()=>facade.status(owner),start:reconcile,async close(){closed=true;adminUi?.close();accessController.abort();accepting=false;while(inFlight>0)await delay(10);await suspend();await store.close();}};
}
