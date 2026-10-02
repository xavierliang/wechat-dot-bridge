import {normalizeMessageId} from './ilink-json.mjs';
// Pure DTO mapping only. No networking, QR login, tokens, or live adapter.
export function normalizePoll(response,bot,{allowedSenders,counts={}}={}){
 if((response.ret!==undefined&&response.ret!==0)||(response.errcode!==undefined&&response.errcode!==0))throw Error(response.ret===-14||response.errcode===-14?'ilink_session_expired':'ilink_poll_failed');
 // Omitted default-valued fields are valid; explicit nulls/types still fail.
 const msgs=response.msgs===undefined?[]:response.msgs;
 if(!Array.isArray(msgs)||typeof response.get_updates_buf!=='string')throw Error('ilink_invalid_response');
 Object.assign(counts,{received:msgs.length,normalized:0,non_user:0,group:0,recipient:0,sender:0,unsupported_content:0,malformed:0,invalid_id:0,missing_context:0,invalid_timestamp:0});
 const messages=[];
 for(const m of msgs){
  if(!m||typeof m!=='object'||Array.isArray(m)){counts.malformed++;throw Error('ilink_invalid_response');}
  if(m.message_type!==1||m.message_state!==2){counts.non_user++;continue;}
  if(m.group_id){counts.group++;continue;}
  if(m.to_user_id!==bot){counts.recipient++;continue;}
  // Reject unapproved senders before parsing content/IDs so their malformed
  // messages cannot block the owner's cursor. Bridge also rechecks ownership.
  if(typeof m.from_user_id!=='string'||!m.from_user_id||m.from_user_id.length>256||allowedSenders&&!allowedSenders.has(m.from_user_id)){counts.sender++;continue;}
  const items=m.item_list??[];
  if(!Array.isArray(items)||items.some(i=>!i||typeof i!=='object'||Array.isArray(i))){counts.malformed++;throw Error('ilink_invalid_response');}
  const text=items.filter(i=>i.type===1&&typeof i.text_item?.text==='string').map(i=>i.text_item.text).join('\n');
  if(!text){counts.unsupported_content++;continue;}
  const id=normalizeMessageId(m.message_id);
  // Never acknowledge a text message whose identity cannot be preserved.
  if(id===null){counts.invalid_id++;throw Error('ilink_invalid_message_id');}
  if(typeof m.context_token!=='string'||!m.context_token){counts.missing_context++;continue;}
  if(!Number.isFinite(m.create_time_ms)){counts.invalid_timestamp++;continue;}
  messages.push({id,bot,sender:m.from_user_id,role:'user',direction:'inbound',group:false,text,contextToken:m.context_token,timestamp:m.create_time_ms});
  counts.normalized++;
 }
 return {messages,cursor:response.get_updates_buf};
}
export function replyBody({to,contextToken,text,clientId},channelVersion){
 if(![to,contextToken,text,clientId,channelVersion].every(x=>typeof x==='string'&&x.length))throw Error('ilink_reply_fields_required');
 return {msg:{from_user_id:'',to_user_id:to,client_id:clientId,message_type:2,message_state:2,context_token:contextToken,item_list:[{type:1,text_item:{text}}]},base_info:{channel_version:channelVersion,bot_agent:'DotBridge/0.1.0'}};
}
