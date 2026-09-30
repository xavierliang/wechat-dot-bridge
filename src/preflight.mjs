import {loadConfig,loadSecrets} from './config.mjs';
import {createSecureContext} from 'node:tls';
import {createResourceServerAuth} from './auth.mjs';
try{
 const config=loadConfig(),secrets=await loadSecrets(config);
 await createResourceServerAuth({issuer:config.issuer,resource:config.publicUrl,ownerSubject:config.ownerSubject,jwks:secrets.jwks,revocationCheck:()=>false});
 createSecureContext({key:secrets.tlsKey,cert:secrets.tlsCert,minVersion:'TLSv1.2'});secrets.storageKey.fill(0);
 console.log('Local configuration parses. No network was contacted; registration, certificate chain/hostname, linking, and live callback are not verified.');
}catch(e){const code=/^(missing_BRIDGE_[A-Z_]+|[a-z_]+)$/.test(e.message??'')?e.message:'preflight_failed';console.error(code);process.exitCode=1;}
