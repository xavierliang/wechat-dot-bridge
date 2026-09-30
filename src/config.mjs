import {readFile,stat} from 'node:fs/promises';
import {isIP} from 'node:net';
const required=(e,k)=>{const v=e[k];if(typeof v!=='string'||!v.trim())throw Error('missing_'+k);return v.trim();};
const httpsUrl=(v)=>{const u=new URL(v);if(u.protocol!=='https:'||u.username||u.password||u.hash||u.search||isIP(u.hostname))throw Error('invalid_https_configuration');return u;};
export function loadConfig(env=process.env){
 if(env.BRIDGE_ENABLE_LIVE!=='true')throw Error('live_mode_disabled');
 const publicUrl=httpsUrl(required(env,'BRIDGE_PUBLIC_URL'));if(publicUrl.pathname!=='/mcp'||publicUrl.port)throw Error('public_mcp_url_required');
 const issuer=httpsUrl(required(env,'BRIDGE_AUTH_ISSUER')).toString();
 const callbackHosts=required(env,'BRIDGE_CALLBACK_HOSTS').split(',').map(x=>x.trim());
 if(callbackHosts.some(h=>!h||h!==h.toLowerCase()||isIP(h)||!/^[a-z0-9.-]+$/.test(h)))throw Error('invalid_callback_hosts');
 const bind=env.BRIDGE_BIND_HOST??'127.0.0.1';if(!['127.0.0.1','0.0.0.0'].includes(bind))throw Error('invalid_bind_host');
 const port=Number(env.BRIDGE_PORT??8443);if(!Number.isInteger(port)||port<1024||port>65535)throw Error('invalid_port');
 return {publicUrl:publicUrl.toString(),issuer:required(env,'BRIDGE_AUTH_ISSUER'),ownerSubject:required(env,'BRIDGE_OWNER_SUBJECT'),callbackHosts,bind,port,
  jwksFile:required(env,'BRIDGE_JWKS_FILE'),storageKeyFile:required(env,'BRIDGE_STORAGE_KEY_FILE'),tlsKeyFile:required(env,'BRIDGE_TLS_KEY_FILE'),tlsCertFile:required(env,'BRIDGE_TLS_CERT_FILE'),dataDir:required(env,'BRIDGE_DATA_DIR'),channelVersion:env.BRIDGE_CHANNEL_VERSION??'0.1.0'};
}
export async function loadSecrets(config){
 const keyInfo=await stat(config.storageKeyFile);if((keyInfo.mode&0o077)!==0)throw Error('storage_key_permissions_required');
 const key=await readFile(config.storageKeyFile);if(key.length!==32)throw Error('storage_key_must_be_32_raw_bytes');
 const tlsInfo=await stat(config.tlsKeyFile);if((tlsInfo.mode&0o077)!==0)throw Error('tls_key_permissions_required');
 const [tlsKey,tlsCert,jwksText]=await Promise.all([readFile(config.tlsKeyFile),readFile(config.tlsCertFile),readFile(config.jwksFile,'utf8')]);
 let jwks;try{jwks=JSON.parse(jwksText);}catch{throw Error('invalid_jwks_file');}
 return {storageKey:key,tlsKey,tlsCert,jwks};
}
