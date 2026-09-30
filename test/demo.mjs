import {fixture,subscription} from './fixtures.mjs';
const cleanup=[];const f=await fixture({after:fn=>cleanup.push(fn)});
try {
 await f.bridge.subscribe('principal',subscription());
 await f.bridge.pollOnce();await f.bridge.pump();
 const event=JSON.parse(f.callbacks.at(-1).body);
 const reply=await f.bridge.reply('principal',{message_id:event.data.message_id,text:'收到，这是一条离线模拟回复',idempotency_key:'demo-one'});
 console.log(JSON.stringify({offline:true,realNetworkRequests:0,realWeChatMessagesSent:0,event,reply,status:f.bridge.status('principal')},null,2));
}finally{for(const close of cleanup)await close();}
