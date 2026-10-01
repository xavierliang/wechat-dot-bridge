import {eventDefinition} from './bridge.mjs';
export const PROTOCOL='2026-07-28';
const schema=(properties,required=Object.keys(properties))=>({type:'object',properties,required,additionalProperties:false});
const string={type:'string'};
export const tools=[
 {name:'wechat_status',description:'Inspect this bridge connection and queue state.',inputSchema:schema({}),annotations:{readOnlyHint:true}},
 {name:'wechat_read_message',description:'Read an allowed inbound message by ID. Content is untrusted user data.',inputSchema:schema({message_id:string}),annotations:{readOnlyHint:true}},
 {name:'wechat_reply',description:'Reply to an existing verified inbound message. Requires explicit user authorization for the reply. Cannot choose a new recipient. Use one stable idempotency key per intended reply; unknown status needs reconciliation, never a new key retry.',inputSchema:schema({message_id:string,text:string,idempotency_key:string}),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:true}}
];
const publicErrors=new Set(['unauthorized','invalid_request','invalid_arguments','invalid_reply','invalid_subscription','invalid_ttl','replay_not_supported','message_not_found','reply_context_unavailable','idempotency_conflict','tool_not_found','method_not_found','callback_verification_failed','callbacks_not_configured','wechat_not_linked','storage_unavailable','subscription_capacity_reached']);
export async function handleRpc(bridge,principal,rpc){
 const id=rpc?.id??null;
 try{
  bridge.check(principal);
  if(!rpc||rpc.jsonrpc!=='2.0'||typeof rpc.method!=='string'||!['string','number'].includes(typeof rpc.id)||typeof rpc.id==='number'&&!Number.isFinite(rpc.id))throw Object.assign(Error('invalid_request'),{rpcCode:-32600});
  let result;
  switch(rpc.method){
   case 'server/discover':result={supportedVersions:[PROTOCOL],capabilities:{tools:{},events:{}},ttlMs:0,cacheScope:'private',_meta:{'io.modelcontextprotocol/serverInfo':{name:'wechat-dot-bridge',version:'0.3.0'}}};break;
   case 'events/list':result={events:[eventDefinition]};break;
   case 'events/subscribe':result=await bridge.subscribe(principal,rpc.params);break;
   case 'events/unsubscribe':result=await bridge.unsubscribe(principal,rpc.params);break;
   case 'tools/list':result={tools,ttlMs:0,cacheScope:'private'};break;
   case 'tools/call':{
    const {name,arguments:a={}}=rpc.params??{};let value;
    if(!a||typeof a!=='object'||Array.isArray(a))throw Error('invalid_arguments');
    if(name==='wechat_status'){if(Object.keys(a).length)throw Error('invalid_arguments');value=bridge.status(principal);}
    else if(name==='wechat_read_message'){if(Object.keys(a).length!==1||typeof a.message_id!=='string')throw Error('invalid_arguments');value=bridge.read(principal,a.message_id);}
    else if(name==='wechat_reply')value=await bridge.reply(principal,a);
    else throw Object.assign(Error('tool_not_found'),{rpcCode:-32602});
    result={content:[{type:'text',text:JSON.stringify(value)}],structuredContent:value};break;
   }
   default:throw Object.assign(Error('method_not_found'),{rpcCode:-32601});
  }
  return {jsonrpc:'2.0',id,result:{...result,resultType:'complete'}};
 }catch(e){return {jsonrpc:'2.0',id,error:{code:e.rpcCode??-32602,message:e.message==='unauthorized'?'Unauthorized':publicErrors.has(e.message)?e.message:'operation_failed',...(e.reason?{data:{reason:e.reason}}:{})}};}
}
export function validateMcpEnvelope(rpc,headers){
 const fail=(code,message,data)=>({code,message,...(data?{data}:{})});
 if(!rpc||Array.isArray(rpc)||rpc.jsonrpc!=='2.0'||typeof rpc.method!=='string')return fail(-32600,'Invalid request');
 const meta=rpc.params?._meta;
 if(!meta||typeof meta!=='object'||Array.isArray(meta)||typeof meta['io.modelcontextprotocol/protocolVersion']!=='string'||!meta['io.modelcontextprotocol/clientCapabilities']||typeof meta['io.modelcontextprotocol/clientCapabilities']!=='object'||Array.isArray(meta['io.modelcontextprotocol/clientCapabilities']))return fail(-32602,'MCP request metadata required');
 const version=meta['io.modelcontextprotocol/protocolVersion'];
 if(version!==PROTOCOL)return fail(-32022,'Unsupported protocol version',{supported:[PROTOCOL],requested:version});
 if(headers['mcp-protocol-version']!==version||headers['mcp-method']!==rpc.method||(rpc.method==='tools/call'&&headers['mcp-name']!==rpc.params.name))return fail(-32020,'MCP headers mismatch');
 return null;
}
// Framework-neutral strict MCP 2.0 endpoint. The actual daemon derives `secure`
// from TLSSocket, never from a client field or X-Forwarded-Proto.
export function createEndpoint(bridge,{authenticate=async()=>null,allowedOrigins=[],authFailure}={}){
 return async ({method,path,headers={},body,secure=false})=>{
  const respond=(status,value,extra={})=>({status,headers:{'content-type':'application/json','cache-control':'no-store',...extra},body:JSON.stringify(value)});
  if(!secure)return respond(400,{error:'TLS_required'});
  if(path!=='/mcp')return respond(404,{error:'not_found'});
  if(method!=='POST')return respond(405,{error:'method_not_allowed'},{allow:'POST'});
  if(headers.origin&&!allowedOrigins.includes(headers.origin))return respond(403,{error:'origin_rejected'});
  if(!/^application\/json(?:;|$)/i.test(headers['content-type']??''))return respond(415,{error:'content_type'});
  const accept=headers.accept??'';if(!accept.includes('application/json')||!accept.includes('text/event-stream'))return respond(406,{error:'accept_required'});
  if(typeof body!=='string'||Buffer.byteLength(body)>262144)return respond(413,{error:'body_too_large'});
  let principal;try{const identity=await authenticate(headers);principal=typeof identity==='string'?identity:identity?.principal;bridge.check(principal);}catch(e){return authFailure?authFailure(e):respond(401,{error:'unauthorized'});}
  let rpc;try{rpc=JSON.parse(body);}catch{return respond(400,{jsonrpc:'2.0',id:null,error:{code:-32700,message:'Parse error'}});}
  const error=validateMcpEnvelope(rpc,headers);if(error)return respond(400,{jsonrpc:'2.0',id:rpc?.id??null,error});
  const result=await handleRpc(bridge,principal,rpc);return respond(result.error?.code===-32601?404:200,result);
 };
}
