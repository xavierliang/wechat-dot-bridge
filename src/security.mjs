import {createHmac, timingSafeEqual} from 'node:crypto';
import {isIP} from 'node:net';
import {lookup} from 'node:dns/promises';
import {request} from 'node:https';
import {markPollFailure,pollFailureDetails} from './poll-diagnostics.mjs';
const networkReasons=new Map([['ENOTFOUND','dns_failed'],['EAI_AGAIN','dns_failed'],['ECONNREFUSED','tcp_failed'],['ECONNRESET','tcp_failed'],['ETIMEDOUT','timeout'],['ENETUNREACH','tcp_failed'],['EHOSTUNREACH','tcp_failed'],['ERR_TLS_CERT_ALTNAME_INVALID','tls_failed'],['CERT_HAS_EXPIRED','tls_failed'],['DEPTH_ZERO_SELF_SIGNED_CERT','tls_failed'],['SELF_SIGNED_CERT_IN_CHAIN','tls_failed'],['UNABLE_TO_VERIFY_LEAF_SIGNATURE','tls_failed'],['UNABLE_TO_GET_ISSUER_CERT_LOCALLY','tls_failed'],['ERR_SSL_WRONG_VERSION_NUMBER','tls_failed']]);
const transportReasons=new Map([['callback_url_rejected','destination_rejected'],['callback_address_rejected','destination_rejected'],['timeout','timeout'],['aborted','aborted'],['aborted_or_timeout','timeout'],['redirect_rejected','redirect_rejected'],['response_failed','response_failed']]);
function transportFailure(error,stage){
 if(pollFailureDetails(error).stage)return error;
 const reason=networkReasons.get(error?.code)??transportReasons.get(error?.message)??'transport_failed';
 return markPollFailure(error,{stage:reason==='dns_failed'?'dns':stage,reason});
}
export function equal(a,b) { const x=Buffer.from(a), y=Buffer.from(b); return x.length===y.length && timingSafeEqual(x,y); }
export function secretKey(secret) {
  if(typeof secret!=='string'||!/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(secret)) throw Error('invalid_signing_secret');
  const key=Buffer.from(secret.slice(6),'base64');
  if(key.length<24||key.length>64||key.toString('base64')!==secret.slice(6)) throw Error('invalid_signing_secret');
  return key;
}
export function sign(secret,id,timestamp,body) {return 'v1,'+createHmac('sha256',secretKey(secret)).update(`${id}.${timestamp}.${body}`).digest('base64');}
// Deliberately conservative: this prototype supports public IPv4 only. IPv6,
// mapped IPv6, transition ranges, and all special/reserved IPv4 ranges fail closed.
export function publicAddress(ip) {
 if(isIP(ip)!==4) return false;
 const [a,b,c]=ip.split('.').map(Number);
 return !(a===0||a===10||a===127||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192||a===100&&b>=64&&b<=127||a===198&&(b===18||b===19||b===51&&c===100)||a===203&&b===0&&c===113);
}
export function callbackUrl(raw, allowedHosts) {
 const u=new URL(raw);
 if(u.protocol!=='https:'||u.username||u.password||u.hash||(u.port&&u.port!=='443')||!allowedHosts.includes(u.hostname)||isIP(u.hostname)||u.hostname.includes(':')) throw Error('callback_url_rejected');
 return u;
}
export async function validateDestination(raw, allowedHosts, resolve=lookup) {
 // Resolve the same family the socket can use. Dual-stack public services may
 // advertise AAAA records, but this transport never connects over IPv6.
 const u=callbackUrl(raw,allowedHosts), addresses=await resolve(u.hostname,{family:4,all:true,verbatim:true});
 if(!addresses.length||addresses.some(x=>!publicAddress(x.address))) throw Error('callback_address_rejected');
 return {u,address:addresses[0].address};
}
// No generic fetch: DNS is revalidated each connection, then pinned. Host/SNI
// remain the original hostname; certificate verification cannot be disabled.
export function createRestrictedHttpsTransport({allowedHosts=[],resolve=lookup,timeoutMs=10000,maxResponseBytes=262144,requestImpl=request}={}) {
 if(!Number.isFinite(timeoutMs)||timeoutMs<1||timeoutMs>65000||!Number.isInteger(maxResponseBytes)||maxResponseBytes<1||maxResponseBytes>1048576)throw Error('invalid_transport_limits');
 return async (url,{method='POST',headers={},body='',signal}={})=>{
  if(!['GET','POST'].includes(method)||typeof body!=='string'||Buffer.byteLength(body)>1048576)throw Error('invalid_transport_request');
  const deadline=Date.now()+timeoutMs;
  const controller=new AbortController();
  const onAbort=()=>controller.abort(Error('aborted'));
  if(signal?.aborted)throw Error('aborted');
  signal?.addEventListener('abort',onAbort,{once:true});
  const timer=setTimeout(()=>controller.abort(Error('timeout')),timeoutMs);
  let rejectAbort,stage='destination';
  const aborted=new Promise((_,reject)=>{rejectAbort=()=>reject(controller.signal.reason);controller.signal.addEventListener('abort',rejectAbort,{once:true});});
  try {
   const {u,address}=await Promise.race([validateDestination(url,allowedHosts,resolve),aborted]);
   if(controller.signal.aborted||Date.now()>=deadline)throw Error('timeout');
   stage='transport';
   return await Promise.race([new Promise((resolveResult,reject)=>{
    const req=requestImpl(u,{method,headers:{...headers,host:u.host},signal:controller.signal,agent:false,family:4,autoSelectFamily:false,servername:u.hostname,rejectUnauthorized:true,
     lookup:(_host,opts,cb)=>opts?.all?cb(null,[{address,family:4}]):cb(null,address,4)},res=>{
     stage='response';
     const chunks=[];let size=0;
     res.on('data',c=>{size+=c.length;if(size>maxResponseBytes)res.destroy(Error('response_too_large'));else chunks.push(c);});
     res.on('error',()=>reject(markPollFailure(Error('response_failed'),{stage:'response',reason:size>maxResponseBytes?'response_too_large':'response_failed',httpStatus:res.statusCode})));res.on('end',()=>{
      if(res.statusCode>=300&&res.statusCode<400)return reject(markPollFailure(Error('redirect_rejected'),{stage:'http',reason:'redirect_rejected',httpStatus:res.statusCode}));
      resolveResult({status:res.statusCode,body:Buffer.concat(chunks).toString(),headers:res.headers??{}});
     });
    });
    req.on('error',error=>reject(markPollFailure(Error(controller.signal.aborted?'aborted_or_timeout':'transport_failed'),{stage:'transport',reason:controller.signal.aborted?(signal?.aborted?'aborted':'timeout'):(networkReasons.get(error?.code)??'transport_failed')})));req.end(method==='GET'?undefined:body);
   }),aborted]);
  }catch(error){throw transportFailure(error,stage);}
  finally{clearTimeout(timer);signal?.removeEventListener('abort',onAbort);controller.signal.removeEventListener('abort',rejectAbort);}
 };
}
export function createPinnedHttpsTransport(allowedHosts,resolve=lookup,timeoutMs=10000){
 if(timeoutMs>10000)throw Error('invalid_timeout');
 return createRestrictedHttpsTransport({allowedHosts,resolve,timeoutMs});
}
