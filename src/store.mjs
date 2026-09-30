import {mkdir,readFile,open,rename,chmod} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {join} from 'node:path';
import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
export class Store {
 static async open(dir,key) {
  if(!Buffer.isBuffer(key)||key.length!==32)throw Error('external_storage_key_required');
  await mkdir(dir,{recursive:true,mode:0o700});
  const lockPath=join(dir,'owner.sqlite');
  const lock=new DatabaseSync(lockPath);
  try{lock.exec('PRAGMA busy_timeout=0; CREATE TABLE IF NOT EXISTS lock_marker (id INTEGER); BEGIN EXCLUSIVE;');}
  catch{lock.close();throw Error('store_already_open');}
  await chmod(lockPath,0o600);
  const s=new Store();s.dir=dir;s.key=Buffer.from(key);s.lock=lock;s.closed=false;s.writeQueue=Promise.resolve();
  try {
   try {
    const e=JSON.parse(await readFile(join(dir,'state.enc'),'utf8'));
    const d=createDecipheriv('aes-256-gcm',key,Buffer.from(e.iv,'base64'));d.setAuthTag(Buffer.from(e.tag,'base64'));
    s.state=JSON.parse(Buffer.concat([d.update(Buffer.from(e.data,'base64')),d.final()]).toString());
   }catch(e){if(e.code!=='ENOENT')throw e;s.state={version:1,owner:null,bot:null,cursor:'',inbox:{},subscriptions:{},outbox:{},replies:{}};}
   return s;
  }catch(e){lock.close();throw e;}
 }
 save(){const result=this.writeQueue.then(()=>this.writeSnapshot());this.writeQueue=result.catch(()=>{});return result;}
 async writeSnapshot(){
  try {
  if(this.closed||this.failed)throw Error('store_unavailable');
  const plain=JSON.stringify(this.state);if(Buffer.byteLength(plain)>33554432)throw Error('storage_capacity_reached');
  const iv=randomBytes(12),c=createCipheriv('aes-256-gcm',this.key,iv),data=Buffer.concat([c.update(plain),c.final()]);
  const h=await open(join(this.dir,'state.tmp'),'w',0o600);
  try{await h.writeFile(JSON.stringify({iv:iv.toString('base64'),tag:c.getAuthTag().toString('base64'),data:data.toString('base64')}));await h.sync();}finally{await h.close();}
  await rename(join(this.dir,'state.tmp'),join(this.dir,'state.enc'));
  const dir=await open(this.dir,'r');try{await dir.sync();}finally{await dir.close();}
  }catch(e){this.failed=true;throw e;}
 }
 async close(){if(!this.closed){await this.writeQueue;this.closed=true;this.key.fill(0);this.lock.close();}}
}
