import {randomBytes} from 'node:crypto';
import {createRestrictedHttpsTransport} from './security.mjs';
import {normalizePoll,replyBody} from './ilink-contract.mjs';

export const ILINK_BASE_URL='https://ilinkai.weixin.qq.com';
export const ILINK_ALLOWED_HOSTS=Object.freeze(['ilinkai.weixin.qq.com']);
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const string=(x,max=8192)=>typeof x==='string'&&x.length>0&&x.length<=max&&!/[\u0000-\u001f\u007f]/.test(x);

// Error messages are fixed codes. Never attach upstream bodies, URLs, headers,
// causes, tokens, verification codes or QR data to diagnostic objects.
export class ILinkError extends Error {
 constructor(code,{retryable=false,delivery}={}) {super(code);this.name='ILinkError';this.code=code;this.retryable=retryable;if(delivery)this.delivery=delivery;}
}
export function validateIlinkBaseUrl(raw,allowedHosts=ILINK_ALLOWED_HOSTS) {
 if(!Array.isArray(allowedHosts)||!allowedHosts.length||allowedHosts.some(h=>typeof h!=='string'||!/^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+weixin\.qq\.com$/.test(h)))throw new ILinkError('ilink_allowlist_invalid');
 let url;try{url=new URL(raw);}catch{throw new ILinkError('ilink_base_url_rejected');}
 if(url.protocol!=='https:'||url.username||url.password||url.port||url.search||url.hash||url.pathname!=='/'||!allowedHosts.includes(url.hostname))throw new ILinkError('ilink_base_url_rejected');
 return url.origin;
}
export function encodeClientVersion(version) {
 if(typeof version!=='string'||!/^\d+\.\d+\.\d+$/.test(version))throw new ILinkError('ilink_version_invalid');
 const parts=version.split('.').map(Number);if(parts.some(n=>!Number.isSafeInteger(n)||n>255))throw new ILinkError('ilink_version_invalid');
 return String(parts[0]*65536+parts[1]*256+parts[2]);
}
function applicationFailure(data) {
 if(data.ret===-14||data.errcode===-14)throw new ILinkError('ilink_session_expired');
 return data.ret!==undefined&&data.ret!==0||data.errcode!==undefined&&data.errcode!==0;
}

export class ILinkClient {
 #transport;#hosts;#baseUrl;#token;#botId;#version;#clientVersion;
 constructor({transport,channelVersion='0.1.0',allowedHosts=ILINK_ALLOWED_HOSTS,baseUrl=ILINK_BASE_URL,token,botId}={}) {
  this.#baseUrl=validateIlinkBaseUrl(baseUrl,allowedHosts);this.#hosts=[...allowedHosts];
  this.#clientVersion=encodeClientVersion(channelVersion);this.#version=channelVersion;
  if(token!==undefined&&!string(token,16384))throw new ILinkError('ilink_credentials_invalid');
  if(botId!==undefined&&!string(botId,256))throw new ILinkError('ilink_credentials_invalid');
  if(transport!==undefined&&typeof transport!=='function')throw new ILinkError('ilink_transport_invalid');
  this.#transport=transport??createRestrictedHttpsTransport({allowedHosts:this.#hosts,timeoutMs:40000,maxResponseBytes:1048576});
  this.#token=token;this.#botId=botId;
 }
 validateBaseUrl(raw){return validateIlinkBaseUrl(raw,this.#hosts);}
 #baseInfo(){return {channel_version:this.#version,bot_agent:'DotBridge/0.1.0'};}
 #headers({authenticated=false,json=true}={}) {
  const headers={'iLink-App-Id':'bot','iLink-App-ClientVersion':this.#clientVersion};
  if(json){headers['Content-Type']='application/json';headers.AuthorizationType='ilink_bot_token';headers['X-WECHAT-UIN']=Buffer.from(String(randomBytes(4).readUInt32BE())).toString('base64');}
  if(authenticated){if(!this.#token||!this.#botId)throw new ILinkError('ilink_credentials_required');headers.Authorization=`Bearer ${this.#token}`;}
  return headers;
 }
 async #request(path,{baseUrl=this.#baseUrl,method='POST',data,authenticated=false,signal,delivery}={}) {
  const base=this.validateBaseUrl(baseUrl);
  if(signal?.aborted)throw new ILinkError('ilink_aborted',{delivery});
  const headers=this.#headers({authenticated,json:method==='POST'});
  let response;
  try{response=await this.#transport(new URL(path,base).toString(),{method,headers,body:method==='POST'?JSON.stringify(data):'',signal});}
  catch{throw new ILinkError(signal?.aborted?'ilink_aborted':delivery?'ilink_send_unknown':'ilink_transport_failed',{retryable:!delivery&&!signal?.aborted,delivery});}
  if(signal?.aborted)throw new ILinkError('ilink_aborted',{delivery});
  if(!object(response)||!Number.isInteger(response.status))throw new ILinkError('ilink_response_invalid',{delivery});
  if(response.status>=300&&response.status<400)throw new ILinkError('ilink_redirect_rejected',{delivery});
  if(response.status<200||response.status>=300)throw new ILinkError('ilink_http_failed',{retryable:!delivery&&(response.status===429||response.status>=500),delivery});
  if(typeof response.body!=='string'||Buffer.byteLength(response.body)>1048576)throw new ILinkError('ilink_response_invalid',{delivery});
  let parsed;try{parsed=JSON.parse(response.body);}catch{throw new ILinkError('ilink_response_invalid',{delivery});}
  if(!object(parsed))throw new ILinkError('ilink_response_invalid',{delivery});
  return parsed;
 }
 async getUpdates({cursor='',signal}={}) {
  if(typeof cursor!=='string'||cursor.length>65536)throw new ILinkError('ilink_cursor_invalid');
  const data=await this.#request('/ilink/bot/getupdates',{data:{get_updates_buf:cursor,base_info:this.#baseInfo()},authenticated:true,signal});
  if(applicationFailure(data))throw new ILinkError('ilink_poll_failed',{retryable:true});
  // An empty cursor is a long-poll timeout/no-change value, never a reset.
  const next=data.get_updates_buf===undefined||data.get_updates_buf===''?cursor:data.get_updates_buf;
  let batch;try{batch=normalizePoll({...data,get_updates_buf:next},this.#botId);}catch{throw new ILinkError('ilink_response_invalid');}
  return batch;
 }
 poll(cursor='',options={}){return this.getUpdates({cursor,...options});}
 async sendText({to,contextToken,text,clientId,signal}) {
  let body;try{body=replyBody({to,contextToken,text,clientId},this.#version);}catch{throw new ILinkError('ilink_reply_fields_required');}
  const data=await this.#request('/ilink/bot/sendmessage',{data:body,authenticated:true,signal,delivery:'unknown'});
  if(applicationFailure(data))return {accepted:false,state:'rejected',code:'ilink_send_rejected'};
  // Upstream currently tolerates missing ret. This adapter deliberately does not
  // claim success without an explicit acknowledgement, and never retries sends.
  return data.ret===0?{accepted:true,state:'sent'}:{accepted:false,state:'unknown'};
 }
 reply(args){return this.sendText(args);}
 async requestQr({signal}={}) {
  const data=await this.#request('/ilink/bot/get_bot_qrcode?bot_type=3',{baseUrl:ILINK_BASE_URL,data:{local_token_list:[]},signal});
  if(applicationFailure(data)||!string(data.qrcode,8192)||!string(data.qrcode_img_content,65536))throw new ILinkError('ilink_qr_response_invalid');
  return {qrcode:data.qrcode,qrContent:data.qrcode_img_content,baseUrl:ILINK_BASE_URL};
 }
 async pollQr({qrcode,baseUrl=ILINK_BASE_URL,verifyCode,signal}) {
  if(!string(qrcode,8192)||verifyCode!==undefined&&!/^[0-9]{1,16}$/.test(verifyCode))throw new ILinkError('ilink_qr_input_invalid');
  const query=new URLSearchParams({qrcode});if(verifyCode!==undefined)query.set('verify_code',verifyCode);
  const data=await this.#request(`/ilink/bot/get_qrcode_status?${query}`,{baseUrl,method:'GET',signal});
  if(applicationFailure(data))throw new ILinkError('ilink_qr_status_failed');
  const status=data.status;
  if(['wait','scaned','expired','need_verifycode','verify_code_blocked','binded_redirect'].includes(status))return {status};
  if(status==='scaned_but_redirect') {
   if(!string(data.redirect_host,253)||!/^[a-z0-9.-]+$/.test(data.redirect_host))throw new ILinkError('ilink_redirect_rejected');
   return {status,baseUrl:this.validateBaseUrl(`https://${data.redirect_host}`)};
  }
  if(status==='confirmed') {
   if(!string(data.bot_token,16384)||!string(data.ilink_bot_id,256)||!string(data.ilink_user_id,256))throw new ILinkError('ilink_qr_response_invalid');
   return {status,token:data.bot_token,botId:data.ilink_bot_id,scannerId:data.ilink_user_id,baseUrl:this.validateBaseUrl(data.baseurl??baseUrl)};
  }
  throw new ILinkError('ilink_qr_status_invalid');
 }
}
