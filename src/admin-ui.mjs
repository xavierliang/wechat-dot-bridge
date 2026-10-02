import {randomBytes} from 'node:crypto';
import QRCode from 'qrcode';
import {equal} from './security.mjs';
import {ADMIN_PATH, ADMIN_CALLBACK_PATH} from './admin-oauth.mjs';
import {markLoginFailure,loginFailureReason,providerFailureReason,safeLoginDiagnostic} from './login-diagnostics.mjs';

const COOKIE = '__Host-bridge_admin';
const random = () => randomBytes(32).toString('base64url');
const TRANSACTION_MS = 300000, IDLE_MS = 900000, SESSION_MS = 3600000;
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cookie = (id, age = 3600) => `${COOKIE}=${id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${age}`;
const routes = new Set([ADMIN_PATH, ADMIN_CALLBACK_PATH, '/admin/login','/admin/logout', '/admin/ui/begin','/admin/ui/challenge','/admin/ui/poll','/admin/ui/confirm','/admin/ui/revoke']);
const securityHeaders = {
 'content-type':'text/html; charset=utf-8', 'cache-control':'no-store',
 'pragma':'no-cache', 'referrer-policy':'no-referrer', 'x-content-type-options':'nosniff',
 'x-frame-options':'DENY', 'cross-origin-opener-policy':'same-origin',
 'content-security-policy':"default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
};
const response = (status, body = '', headers = {}) => ({status, headers:{...securityHeaders,...headers}, body});
const redirect = (location, headers = {}) => response(303, '', {location,...headers});
// A no-referrer document serializes a native form POST's Origin as null.
// Query-free admin documents with forms need same-origin referrers, including
// QR action responses used by subsequent native form submissions. Protocol
// callbacks, redirects and errors keep no-referrer so code/state cannot leak.
const adminFormPage = output => ({...output,headers:{...output.headers,'referrer-policy':'same-origin'}});
const page = body => `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WeChat bridge 管理</title><style>body{font:16px/1.6 system-ui;max-width:760px;margin:3rem auto;padding:0 1rem;color:#202b35}button,input{font:inherit;padding:.5rem;margin:.3rem 0}button{cursor:pointer}code{overflow-wrap:anywhere}img{max-width:100%}.notice{padding:1rem;background:#eef3f7}form{margin:1rem 0}label{display:block}</style><main><h1>WeChat bridge 管理</h1>${body}</main></html>`;
function parseCookie(headers) {
 if (headers.cookie === undefined) return undefined;
 if (typeof headers.cookie !== 'string' || headers.cookie.length > 8192) throw Error('invalid_cookie');
 const matches = headers.cookie.split(';').map(x => x.trim()).filter(x => x.startsWith(COOKIE+'='));
 if (matches.length > 1) throw Error('invalid_cookie');
 const value = matches[0]?.slice(COOKIE.length+1);
 if (value !== undefined && !/^[A-Za-z0-9_-]{43}$/.test(value)) throw Error('invalid_cookie');
 return value;
}

// Opaque, bounded, server-side sessions. No bearer/ID/refresh token, PKCE
// verifier is put in cookies, HTML, localStorage, URLs or logs. The standard
// authorization redirect carries one-use state/nonce and a PKCE challenge.
export function createAdminUI({config, auth, oauth, dispatch, status, now = Date.now, diagnostic=safeLoginDiagnostic}) {
 const origin = new URL(config.publicUrl).origin, sessions = new Map();
 const csp=securityHeaders['content-security-policy'].replace("form-action 'self'",`form-action 'self' ${new URL(config.issuer).origin}`);
 const response=(status,body='',headers={})=>({status,headers:{...securityHeaders,'content-security-policy':csp,...headers},body});
 let closed = false;
 function drop(id) {const s=sessions.get(id);if(s){s.controller.abort();s.token=undefined;s.transaction=undefined;sessions.delete(id);}}
 function prune() {for(const [id,s] of sessions)if(s.expires<=now() || s.idle<=now())drop(id);}
 function fresh() {
  prune();
  if(sessions.size>=128){const candidate=[...sessions].find(([,s])=>!s.token);if(candidate)drop(candidate[0]);}
  if(closed || sessions.size>=128)throw Error('session_capacity');
  const id=random(), s={csrf:random(),expires:now()+TRANSACTION_MS,idle:now()+TRANSACTION_MS,controller:new AbortController(),pending:new Set()};sessions.set(id,s);return {id,s};
 }
 const live = (id,s) => !closed && sessions.get(id)===s && s.expires>now() && s.idle>now() && !s.controller.signal.aborted;
 async function authorize(id,s) {
  if (!live(id,s) || !s.token) throw Error('login_required');
  const identity = await auth.authenticate({authorization:'Bearer '+s.token},{requiredScopes:['bridge:admin']});
  if (!live(id,s) || identity.principal!==auth.ownerPrincipal) throw Error('login_required');
  s.idle=Math.min(s.expires,now()+IDLE_MS);return identity;
 }
 function form(s, path, label, inputs='') {
  return `<form method="post" action="${path}"><input type="hidden" name="csrf" value="${escape(s.csrf)}">${inputs}<button type="submit">${escape(label)}</button></form>`;
 }
 async function operation(id,s,path,body,input) {
  await authorize(id,s);
  const signal=input?.signal ? AbortSignal.any([input.signal,s.controller.signal]) : s.controller.signal;
  const pending=dispatch({path,method:'POST',secure:true,headers:{authorization:'Bearer '+s.token,'content-type':'application/json'},body:JSON.stringify(body),signal});
  s.pending.add(pending);let result;try{result=await pending;}finally{s.pending.delete(pending);}
  await authorize(id,s);
  if(result.status!==200)throw Error('admin_operation_failed');
  return JSON.parse(result.body);
 }
 async function render(id,s,{qr,notice=''}={}) {
  await authorize(id,s);
  if(s.pending.size)return adminFormPage(response(200,page('<p>操作仍在等待。可以退出管理会话以取消等待中的请求。</p>'+form(s,'/admin/logout','退出并取消等待')+'<p><a href="/admin">刷新状态</a></p>')));
  const link=await operation(id,s,'/admin/link/status',{}), state=status();
  const hidden=link.requestId?`<input type="hidden" name="requestId" value="${escape(link.requestId)}">`:'';
  let body=`<p class="notice">${state.callbacksConfigured?'事件回调域名已配置。':'启动准备模式：事件回调域名尚未配置，订阅、消息轮询和发送均关闭。'}</p><p>微信状态：<strong>${escape(link.status)}</strong>；运行状态：${escape(state.phase)}</p>`;
  if(notice)body+=`<p>${escape(notice)}</p>`;
  if(state.unapprovedCallbackHost)body+=`<p>实际订阅请求提供的回调域名（尚未批准或验证）：<code>${escape(state.unapprovedCallbackHost)}</code>。订阅仍被拒绝，消息收发仍关闭；管理员确认前不会连接此域名。</p>`;
  // WeChat IDs contain @ but are exact identity labels, not email addresses.
  // Keep Cloudflare's email rewrite off these escaped owner-only labels; the
  // page CSP intentionally disallows its injected email decoding script.
  if(link.scannerId)body+=`<p>实际扫码账号：<!--email_off--><code>${escape(link.scannerId)}</code><!--/email_off--></p><p>机器人：<!--email_off--><code>${escape(link.botId)}</code><!--/email_off--></p>`;
  if(qr)body+=`<p>仅用你要绑定的微信账号扫描；扫码后还必须确认实际账号。</p><img alt="微信绑定二维码" src="${qr}">`;
  if(!link.linked && !['waiting','scanned','needs_verification','awaiting_owner_confirmation'].includes(link.status))body+=form(s,'/admin/ui/begin','创建新的微信绑定二维码');
  if(['waiting','scanned','needs_verification'].includes(link.status)){
   body+=form(s,'/admin/ui/challenge','显示当前二维码',hidden);
   const verification=link.status==='needs_verification'?'<label>微信验证码 <input name="verifyCode" inputmode="numeric" pattern="[0-9]{1,16}" required autocomplete="off"></label>':'';
   body+=form(s,'/admin/ui/poll','检查扫码状态',hidden+verification);
  }
  if(link.status==='awaiting_owner_confirmation')body+=form(s,'/admin/ui/confirm','确认绑定这个微信账号',hidden+'<label>请逐字输入上方实际扫码账号 ID <input name="scannerId" required autocomplete="off" maxlength="256"></label>');
  if(link.requestId)body+=form(s,'/admin/ui/revoke','撤销绑定 / 取消当前扫码',hidden);
  body+='<p>若扫码账号不对，请撤销本次绑定，再创建新二维码。不会自动信任另一扫码账号。</p><p><a href="/admin">刷新状态</a></p>';
  body+=form(s,'/admin/logout','退出此管理会话');
  body+='<p>退出会销毁本浏览器的管理会话并取消尚在等待的请求，不会撤销已确认的微信绑定或 Auth0 的其他登录。要停用微信访问，请先撤销绑定。</p>';
  await authorize(id,s);return adminFormPage(response(200,page(body)));
 }
 return {
  handles(path) {return routes.has(path.split('?')[0]);},
  async handle(input) {
   const {method,headers={},body='',secure=false}=input;
   let id,s,stage='request';
   const fail=(reason,message='invalid_callback')=>{throw markLoginFailure(Error(message),reason);};
   try {
    if(!secure)return response(400,page('<p>需要 HTTPS。</p>'));
    if(typeof input.path!=='string' || input.path.length>8192 || input.path.includes('#'))throw Error('invalid_request');
    const url=new URL(input.path,origin), path=url.pathname;
    if(url.origin!==origin || !routes.has(path) || (path!==ADMIN_CALLBACK_PATH && url.search))throw Error('invalid_request');
    prune();id=parseCookie(headers);s=sessions.get(id);
    if(path===ADMIN_CALLBACK_PATH){
     stage='callback';
     if(method!=='GET')fail('request_rejected');
     if(!id)fail('callback_cookie_missing');
     if(!s || !live(id,s))fail('callback_session_unavailable');
     const transaction=s.transaction;s.transaction=undefined; // consume before any await, even on denial
     if(!transaction)fail('callback_transaction_missing');
     if(transaction.expires<=now())fail('callback_transaction_expired');
     const allowed=new Set(['code','state','iss','session_state','error','error_description','error_uri']);
     for(const name of url.searchParams.keys())if(!allowed.has(name)||url.searchParams.getAll(name).length!==1)fail('callback_parameters_rejected');
     if(!equal(url.searchParams.get('state')??'',transaction.state))fail('callback_state_mismatch');
     if(url.searchParams.has('error'))fail(providerFailureReason(url.searchParams.get('error')));
     if(!url.searchParams.get('code'))fail('callback_code_missing');
     stage='oauth_exchange';
     const tokens=await oauth.exchange(url,transaction);
     if(!live(id,s) || transaction.expires<=now())fail('login_expired','login_expired');
     stage='api_token';
     const identity=await auth.authenticate({authorization:'Bearer '+tokens.accessToken},{requiredScopes:['bridge:admin']});
     if(!live(id,s) || identity.principal!==auth.ownerPrincipal)throw Error('login_required');
     const expires=Math.min(now()+SESSION_MS,identity.expiresAt*1000,tokens.idExpiresAt);
     if(!Number.isFinite(expires)||expires<=now())throw Error('login_expired');
     drop(id);const next=fresh();next.s.token=tokens.accessToken;next.s.expires=expires;next.s.idle=Math.min(expires,now()+IDLE_MS);
     return redirect(ADMIN_PATH,{'set-cookie':cookie(next.id,Math.floor((expires-now())/1000))});
    }
    if(path===ADMIN_PATH){
     if(method!=='GET')return response(405,'',{'allow':'GET'});
     if(s?.token){try{return await render(id,s);}catch{drop(id);s=undefined;}}
     if(!s){({id,s}=fresh());}
     return adminFormPage(response(200,page('<p>只有预先配置的 owner 可以管理此桥接。登录不会自动创建微信二维码或绑定账号。</p>'+form(s,'/admin/login','通过身份提供方登录')+form(s,'/admin/logout','取消登录 / 清除此会话')),{'set-cookie':cookie(id,300)}));
    }
    if(method!=='POST')return response(405,'',{'allow':'POST'});
    if(!s || !live(id,s) || headers.origin!==origin || (headers['sec-fetch-site'] && headers['sec-fetch-site']!=='same-origin'))return response(403,page('<p>请求已拒绝，请从管理页重试。</p><p><a href="/admin">返回管理页并刷新状态</a></p>'));
    if(!/^application\/x-www-form-urlencoded(?:;|$)/i.test(headers['content-type']??'') || typeof body!=='string' || Buffer.byteLength(body)>8192)throw Error('invalid_form');
    const values=new URLSearchParams(body);
    for(const key of values.keys())if(values.getAll(key).length!==1)throw Error('invalid_form');
    if(!equal(values.get('csrf')??'',s.csrf))return response(403,page('<p>表单已过期或已使用，请刷新管理页。</p>'));
    s.csrf=random(); // one use, including failed operations
    const allowed={
     '/admin/login':['csrf'], '/admin/logout':['csrf'], '/admin/ui/begin':['csrf'],
     '/admin/ui/challenge':['csrf','requestId'], '/admin/ui/poll':['csrf','requestId','verifyCode'],
     '/admin/ui/confirm':['csrf','requestId','scannerId'], '/admin/ui/revoke':['csrf','requestId'],
    }[path];
    if(!allowed || [...values.keys()].some(k=>!allowed.includes(k)))throw Error('invalid_form');
    if(path==='/admin/logout'){
     drop(id);
     // Wait for dispatched work to observe cancellation or finish an already
     // started durable commit before acknowledging logout. No late commits.
     await Promise.allSettled([...s.pending]);
     return redirect(ADMIN_PATH,{'set-cookie':cookie('',0)});
    }
    if(path==='/admin/login'){
     stage='oauth_begin';
     if(s.token || s.transaction)fail('login_already_pending','login_already_pending');
     const transaction={state:random(),nonce:random(),verifier:random(),expires:now()+TRANSACTION_MS};s.transaction=transaction;
     const location=await oauth.begin(transaction);
     if(!live(id,s) || s.transaction!==transaction || transaction.expires<=now())throw Error('login_expired');
     return redirect(location,{'content-security-policy':csp});
    }
    stage='admin_action';
    await authorize(id,s);
    const action=path.slice('/admin/ui/'.length), args=Object.fromEntries([...values].filter(([k])=>k!=='csrf'));
    const result=await operation(id,s,'/admin/link/'+action,args,input);
    if(action==='begin'||action==='challenge'){
     const challenge=action==='begin'?await operation(id,s,'/admin/link/challenge',{requestId:result.requestId},input):result;
     if(typeof challenge.qrContent!=='string'||Buffer.byteLength(challenge.qrContent)>2048)throw Error('qr_display_unavailable');
     const qr=await QRCode.toDataURL(challenge.qrContent,{errorCorrectionLevel:'M',width:320,margin:4});
     return await render(id,s,{qr});
    }
    return await render(id,s,{notice:action==='revoke'?'当前微信绑定或扫码已撤销。':''});
   } catch(error) {
    // Do not leak OAuth response bodies, code/state/verifier, tokens, upstream
    // QR data, file paths or exception messages into pages or diagnostics.
    const requestId=randomBytes(8).toString('hex');
    const fallback={request:'request_rejected',callback:'callback_parameters_rejected',oauth_begin:'oauth_unavailable',oauth_exchange:'oauth_exchange_failed',api_token:'api_token_invalid',admin_action:'request_rejected'}[stage];
    try{diagnostic({stage,reason:loginFailureReason(error,fallback),requestId});}catch{}
    return response(400,page('<p>登录或操作失败，可能已过期、权限不符或身份提供方不可用。</p><p><a href="/admin">返回管理页并刷新状态</a></p><p>诊断编号：<code>'+requestId+'</code></p>'));
   }
  },
  close(){closed=true;for(const id of sessions.keys())drop(id);},
 };
}
