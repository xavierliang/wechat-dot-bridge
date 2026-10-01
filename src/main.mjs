import {pathToFileURL} from 'node:url';
import {loadConfig,loadSecrets} from './config.mjs';
import {Store} from './store.mjs';
import {createApplication} from './application.mjs';
import {createHttpsServer} from './http-server.mjs';
import {safeLog} from './logging.mjs';
import {createAdminOAuth} from './admin-oauth.mjs';
export async function main(){
 process.umask(0o077);
 const config=loadConfig(),secrets=await loadSecrets(config);
 const store=await Store.open(config.dataDir,secrets.storageKey);secrets.storageKey.fill(0);
 const shutdown=new AbortController();let application,server;
 try{
  const adminOAuth=config.adminEnabled?createAdminOAuth(config,secrets.adminClientSecret):undefined;
  application=await createApplication({config,store,jwks:secrets.jwks,adminOAuth});
  server=createHttpsServer({application,publicUrl:config.publicUrl,tlsKey:secrets.tlsKey,tlsCert:secrets.tlsCert,shutdownSignal:shutdown.signal});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(config.port,config.bind,resolve);});
  await application.start();safeLog('ready');
 }catch{shutdown.abort();server?.close();await application?.close();await store.close();throw Error('startup_failed');}
 let stopping=false;
 async function stop(){
  if(stopping)return;stopping=true;safeLog('shutdown');shutdown.abort();
  const watchdog=setTimeout(()=>process.exit(1),65000);watchdog.unref();
  const closed=new Promise(resolve=>server.close(resolve));server.closeIdleConnections();
  try{await application.close();await closed;clearTimeout(watchdog);process.exitCode=0;}catch{safeLog('shutdown');process.exitCode=1;}
 }
 process.once('SIGINT',stop);process.once('SIGTERM',stop);
 return {application,server,stop};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{safeLog('startup_failed');process.exitCode=1;});
