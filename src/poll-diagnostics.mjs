// Private metadata carries classifications across wrappers, never raw errors,
// causes, URLs, headers, response bodies, cursors, identities or messages.
const stages=new Set(['poll','request','destination','dns','transport','response','http','json','application','normalize']);
const reasons=new Set(['unclassified','destination_rejected','dns_failed','tcp_failed','tls_failed','timeout','aborted','transport_failed','response_failed','response_too_large','redirect_rejected','http_failed','response_invalid','json_invalid','upstream_error','fields_invalid']);
const codes=new Set(['poll_failed','ilink_transport_failed','ilink_aborted','ilink_response_invalid','ilink_redirect_rejected','ilink_http_failed','ilink_poll_failed','ilink_session_expired','ilink_cursor_invalid','ilink_credentials_required','ilink_credentials_invalid','ilink_base_url_rejected','ilink_allowlist_invalid','storage_unavailable','inbox_capacity_reached','storage_capacity_reached','unauthorized','invalid_message','invalid_batch','callbacks_not_configured','poll_already_running']);
const types=new Set(['missing','null','array','object','string','number','boolean']);
const marked=new WeakMap();
function sanitize(input={}) {
 const result={};
 for(const [key,allowed] of [['stage',stages],['reason',reasons],['code',codes],['retType',types],['errcodeType',types],['msgsType',types],['cursorType',types]])
  if(allowed.has(input[key]))result[key]=input[key];
 for(const [key,min,max] of [['httpStatus',100,599],['ret',-2147483648,2147483647],['errcode',-2147483648,2147483647],['elapsedMs',0,3600000]])
  if(Number.isInteger(input[key])&&input[key]>=min&&input[key]<=max)result[key]=input[key];
 return result;
}
export function markPollFailure(error,details) {
 if(error&&typeof error==='object')marked.set(error,sanitize(details));
 return error;
}
export function pollFailureDetails(error){return {...marked.get(error)};}
const fieldType=value=>value===undefined?'missing':value===null?'null':Array.isArray(value)?'array':typeof value;
export function pollResponseShape(data) {
 return sanitize({ret:data.ret,errcode:data.errcode,retType:fieldType(data.ret),errcodeType:fieldType(data.errcode),msgsType:fieldType(data.msgs),cursorType:fieldType(data.get_updates_buf)});
}
export function pollFailureDiagnostic(error,elapsedMs) {
 let code;try{code=error?.code??error?.message;}catch{}
 return {stage:'poll',reason:'unclassified',code:codes.has(code)?code:'poll_failed',...pollFailureDetails(error),...sanitize({elapsedMs})};
}
export function safePollDiagnostic(details,write=line=>process.stderr.write(line+'\n')) {
 write(JSON.stringify({time:new Date().toISOString(),event:'wechat_poll_failed',stage:'poll',reason:'unclassified',code:'poll_failed',...sanitize(details)}));
}
