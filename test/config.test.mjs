import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,chmod,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {loadConfig,loadSecrets} from '../src/config.mjs';

const env={BRIDGE_ENABLE_LIVE:'true',BRIDGE_PUBLIC_URL:'https://bridge.example.invalid/mcp',BRIDGE_AUTH_ISSUER:'https://identity.example.invalid/',BRIDGE_OWNER_SUBJECT:'synthetic-owner',BRIDGE_JWKS_FILE:'/synthetic/jwks',BRIDGE_STORAGE_KEY_FILE:'/synthetic/key',BRIDGE_TLS_KEY_FILE:'/synthetic/tls.key',BRIDGE_TLS_CERT_FILE:'/synthetic/tls.crt',BRIDGE_DATA_DIR:'/synthetic/data'};
test('absent or empty callbacks bootstrap safely; malformed hosts never become wildcards',()=>{
 for(const value of [undefined,'','  '])assert.deepEqual(loadConfig({...env,BRIDGE_CALLBACK_HOSTS:value}).callbackHosts,[]);
 for(const value of ['*','*.example.invalid','https://events.example.invalid','127.0.0.1','events.example.invalid,','events.example.invalid,events.example.invalid','UPPER.example.invalid','events.example.invalid:443'])assert.throws(()=>loadConfig({...env,BRIDGE_CALLBACK_HOSTS:value}),/invalid_callback_hosts/);
 const c=loadConfig({...env,BRIDGE_CALLBACK_HOSTS:'events.example.invalid'});assert.deepEqual(c.callbackHosts,['events.example.invalid']);assert.ok(Object.isFrozen(c.callbackHosts));
});
test('admin UI is opt-in and requires an explicit confidential client and secret file',()=>{
 assert.equal(loadConfig(env).adminEnabled,false);
 assert.throws(()=>loadConfig({...env,BRIDGE_ADMIN_UI_ENABLED:'yes'}),/invalid_admin_ui_gate/);
 assert.throws(()=>loadConfig({...env,BRIDGE_ADMIN_UI_ENABLED:'true'}),/missing_BRIDGE_ADMIN_CLIENT_ID/);
 assert.throws(()=>loadConfig({...env,BRIDGE_ADMIN_UI_ENABLED:'true',BRIDGE_ADMIN_CLIENT_ID:'synthetic-client'}),/missing_BRIDGE_ADMIN_CLIENT_SECRET_FILE/);
 assert.throws(()=>loadConfig({...env,BRIDGE_ENABLE_LIVE:'false'}),/live_mode_disabled/);
});
test('admin client secret must be an owner-only nonempty bounded file',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'synthetic-admin-config-'));t.after(()=>rm(dir,{recursive:true}));
 const config={storageKeyFile:join(dir,'storage'),tlsKeyFile:join(dir,'tls'),tlsCertFile:join(dir,'cert'),jwksFile:join(dir,'jwks'),adminEnabled:true,adminClientSecretFile:join(dir,'client')};
 await writeFile(config.storageKeyFile,Buffer.alloc(32,7),{mode:0o600});await writeFile(config.tlsKeyFile,'synthetic',{mode:0o600});await writeFile(config.tlsCertFile,'synthetic');await writeFile(config.jwksFile,'{"keys":[]}');
 await writeFile(config.adminClientSecretFile,'synthetic-not-real',{mode:0o644});await chmod(config.adminClientSecretFile,0o644);
 await assert.rejects(loadSecrets(config),/admin_secret_permissions_required/);await chmod(config.adminClientSecretFile,0o600);
 assert.equal((await loadSecrets(config)).adminClientSecret,'synthetic-not-real');
 for(const value of ['','space inside','x'.repeat(8193)]){await writeFile(config.adminClientSecretFile,value);await assert.rejects(loadSecrets(config),/invalid_admin_client_secret/);}
});
