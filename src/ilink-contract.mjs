// Pure DTO mapping only. No networking, QR login, tokens, or live adapter.
export function normalizePoll(response,bot){
 if((response.ret!==undefined&&response.ret!==0)||(response.errcode!==undefined&&response.errcode!==0))throw Error(response.ret===-14||response.errcode===-14?'ilink_session_expired':'ilink_poll_failed');
 // Omitted default-valued fields are valid; explicit nulls/types still fail.
 const msgs=response.msgs===undefined?[]:response.msgs;
 if(!Array.isArray(msgs)||typeof response.get_updates_buf!=='string')throw Error('ilink_invalid_response');
 const messages=[];
 for(const m of msgs){
  if(m.message_type!==1||m.message_state!==2||m.group_id||m.to_user_id!==bot)continue;
  const text=(m.item_list??[]).filter(i=>i.type===1&&typeof i.text_item?.text==='string').map(i=>i.text_item.text).join('\n');
  if(!text||!m.context_token||!Number.isSafeInteger(m.message_id)||!Number.isFinite(m.create_time_ms)||typeof m.from_user_id!=='string')continue;
  messages.push({id:String(m.message_id),bot,sender:m.from_user_id,role:'user',direction:'inbound',group:false,text,contextToken:m.context_token,timestamp:m.create_time_ms});
 }
 return {messages,cursor:response.get_updates_buf};
}
export function replyBody({to,contextToken,text,clientId},channelVersion){
 if(![to,contextToken,text,clientId,channelVersion].every(x=>typeof x==='string'&&x.length))throw Error('ilink_reply_fields_required');
 return {msg:{from_user_id:'',to_user_id:to,client_id:clientId,message_type:2,message_state:2,context_token:contextToken,item_list:[{type:1,text_item:{text}}]},base_info:{channel_version:channelVersion,bot_agent:'DotBridge/0.1.0'}};
}
