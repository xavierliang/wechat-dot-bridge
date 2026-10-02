import {normalizeMessageId} from './ilink-json.mjs';
// Never serialize errors or upstream objects. All output fields have fixed
// names, allowlisted enum values, bounded numbers, types or booleans.
const outcomes=new Set(['acknowledged','rejected','unknown']);
const acknowledgements=new Set(['none','ret_zero','message_id']);
const stages=new Set(['request','destination','dns','transport','response','http','json','application']);
const reasons=new Set(['unclassified','destination_rejected','dns_failed','tcp_failed','tls_failed','timeout','aborted','transport_failed','response_failed','response_too_large','redirect_rejected','http_failed','response_invalid','json_invalid','upstream_error','fields_invalid','acknowledged','acknowledgement_missing','ambiguous_error']);
const codes=new Set(['ilink_send_unknown','ilink_send_rejected','ilink_aborted','ilink_reply_fields_required','ilink_response_invalid','ilink_redirect_rejected','ilink_http_failed','ilink_session_expired','ilink_credentials_required','ilink_base_url_rejected','ilink_allowlist_invalid']);
const types=new Set(['missing','null','array','object','string','number','boolean']);
const type=v=>v===undefined?'missing':v===null?'null':Array.isArray(v)?'array':typeof v;
export function sendResponseShape(data) {
 const id=normalizeMessageId(data.message_id);
 return {ret:data.ret,errcode:data.errcode,retType:type(data.ret),errcodeType:type(data.errcode),errmsgType:type(data.errmsg),errmsgNonempty:typeof data.errmsg==='string'&&data.errmsg.length>0,messageIdPresent:data.message_id!==undefined,messageIdType:type(data.message_id),messageIdValid:id!==null&&id!=='0'};
}
export function sendDiagnostic(input={}) {
 const result={outcome:'unknown',stage:'request',reason:'unclassified',acknowledgement:'none'};
 for(const [key,allowed] of [['outcome',outcomes],['stage',stages],['reason',reasons],['code',codes],['acknowledgement',acknowledgements],['retType',types],['errcodeType',types],['errmsgType',types],['messageIdType',types]])if(allowed.has(input[key]))result[key]=input[key];
 for(const [key,min,max] of [['httpStatus',100,599],['ret',-2147483648,2147483647],['errcode',-2147483648,2147483647],['elapsedMs',0,3600000]])if(Number.isInteger(input[key])&&input[key]>=min&&input[key]<=max)result[key]=input[key];
 for(const key of ['messageIdPresent','messageIdValid','errmsgNonempty'])if(typeof input[key]==='boolean')result[key]=input[key];
 return result;
}
export function safeSendDiagnostic(details,write=line=>process.stderr.write(line+'\n')) {
 write(JSON.stringify({time:new Date().toISOString(),event:'wechat_send_result',...sendDiagnostic(details)}));
}
