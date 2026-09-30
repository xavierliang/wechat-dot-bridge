import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Store} from '../src/store.mjs';
import {Bridge,EVENT} from '../src/bridge.mjs';
// Fixed synthetic keys only. Never reuse outside these offline fixtures.
export const KEY=Buffer.alloc(32,7),SECRET='whsec_'+Buffer.alloc(32,9).toString('base64');
export const subscription=()=>({name:EVENT,arguments:{sender_id:'synthetic-owner'},delivery:{mode:'webhook',url:'https://callback.example.test/events',secret:SECRET},cursor:null});
export const message=(overrides={})=>({id:'1',bot:'synthetic-bot',sender:'synthetic-owner',role:'user',direction:'inbound',group:false,text:'你好，dot',contextToken:'synthetic-context',timestamp:1801300000000,...overrides});
export async function fixture(t,options={}){
 const dir=await mkdtemp(join(tmpdir(),'wechat-bridge-test-'));let store=await Store.open(dir,KEY);const sent=[],callbacks=[];let time=1801300000000,granted=true;
 const adapter={poll:async()=>({cursor:'next',messages:[message()]}),reply:async m=>{sent.push(m);return {accepted:true};}};
 const transport=async(url,r)=>{callbacks.push({url,...r});const p=JSON.parse(r.body);return {status:200,body:JSON.stringify(p.type==='verification'?{challenge:p.challenge}:{})};};
 const config={store,owner:'principal',bot:'synthetic-bot',allowedSenders:['synthetic-owner'],callbackHosts:['callback.example.test'],authorize:p=>granted&&p==='principal',now:()=>time,transport,adapter,mode:'offline-test',...options};
 const bridge=new Bridge(config);
 const f={dir,store,bridge,sent,callbacks,config,setTime:n=>{time=n;},advance:n=>{time+=n;},revoke:()=>{granted=false;},restart:async()=>{await store.close();store=await Store.open(dir,KEY);f.store=store;f.bridge=new Bridge({...config,store});return f.bridge;}};
 t.after(async()=>{await store.close();await rm(dir,{recursive:true});});return f;
}
