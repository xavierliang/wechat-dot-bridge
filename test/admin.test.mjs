import test from 'node:test';
import assert from 'node:assert/strict';
import {adminFixture,mcpInput,ORIGIN,OWNER} from './admin-fixtures.mjs';

const requestId=body=>body.match(/name="requestId" value="([^"]+)"/)?.[1];
test('public admin page has only login controls; all binding operations require a session and POST',async t=>{
 const f=await adminFixture(t),b=f.browser(),r=await b.request('/admin');
 assert.equal(r.status,200);assert.ok(!r.body.includes('synthetic-scanner'));assert.equal(f.upstream.length,0);assert.equal(f.issuer.requests.length,0);
 assert.ok(r.headers['content-security-policy'].includes("form-action 'self' https://identity.example.invalid"));
 for(const path of ['/admin/ui/begin','/admin/ui/poll','/admin/ui/confirm','/admin/ui/revoke','/admin/logout','/admin/login'])assert.equal((await b.request(path)).status,405);
 assert.equal((await b.request('/admin/ui/begin','POST')).status,400);assert.equal(f.upstream.length,0);
 const noCookie=await f.app.handle({path:'/admin/ui/begin',method:'POST',secure:true,headers:{origin:ORIGIN},body:''});assert.equal(noCookie.status,403);
});
test('real openid-client discovery/code/PKCE/JWKS validation creates a rotated secure server-only session',async t=>{
 const f=await adminFixture(t),b=f.browser();const callback=await b.begin(),oldCookie=b.cookie;
 const r=await b.request(callback.pathname+callback.search);assert.equal(r.status,303,r.body);assert.notEqual(b.cookie,oldCookie);
 for(const flag of ['__Host-bridge_admin=','Path=/','Secure','HttpOnly','SameSite=Lax'])assert.ok(r.headers['set-cookie'].includes(flag));
 assert.ok(!r.headers['set-cookie'].includes('Domain='));
 const page=await b.request('/admin');assert.equal(page.status,200);assert.ok(page.body.includes('启动准备模式'));
 for(const token of f.issuer.accessTokens)assert.ok(!JSON.stringify([page,r]).includes(token));
 assert.ok(page.headers['content-security-policy'].includes("default-src 'none'"));assert.equal(page.headers['cache-control'],'no-store');
 assert.ok(f.issuer.requests.some(x=>x.url.endsWith('/jwks')));assert.equal(f.upstream.length,0);
});
test('wrong state consumes the transaction before token exchange; replay remains rejected',async t=>{
 const f=await adminFixture(t),b=f.browser(),url=await b.begin(),good=url.pathname+url.search;url.searchParams.set('state','wrong');
 assert.equal((await b.request(url.pathname+url.search)).status,400);assert.equal((await b.request(good)).status,400);
 assert.equal(f.issuer.requests.filter(x=>x.url.endsWith('/oauth/token')).length,0);
});
test('callback requires its browser cookie and rejects duplicate or token-bearing callback parameters',async t=>{
 for(const variant of ['no-cookie','duplicate-state','token']){
  const f=await adminFixture(t),b=f.browser(),url=await b.begin();
  if(variant==='duplicate-state')url.searchParams.append('state',url.searchParams.get('state'));
  if(variant==='token')url.searchParams.set('access_token','synthetic-injected');
  const response=await (variant==='no-cookie'?f.browser():b).request(url.pathname+url.search);assert.equal(response.status,400);
  assert.equal(f.issuer.requests.filter(x=>x.url.endsWith('/oauth/token')).length,0);
 }
});
test('successful callback cannot be replayed and authorization code is exchanged once',async t=>{
 const f=await adminFixture(t),b=f.browser(),url=await b.begin();assert.equal((await b.request(url.pathname+url.search)).status,303);
 assert.equal((await b.request(url.pathname+url.search)).status,400);assert.equal(f.issuer.requests.filter(x=>x.url.endsWith('/oauth/token')).length,1);
});
test('expired login transaction and API session fail closed',async t=>{
 const f=await adminFixture(t),b=f.browser(),url=await b.begin();f.advance(300001);assert.equal((await b.request(url.pathname+url.search)).status,400);
 await b.login();f.advance(900001);assert.equal((await b.request('/admin/ui/begin','POST')).status,403);assert.equal(f.upstream.length,0);
});
for(const [name,issuer] of [
 ['wrong nonce',{idClaims:{nonce:'wrong'}}],['wrong ID owner',{idClaims:{sub:'different-owner'}}],
 ['wrong ID audience',{idClaims:{aud:'different-client'}}],['wrong ID issuer',{idClaims:{iss:'https://other.invalid/'}}],
 ['expired ID token',{idClaims:{exp:1}}],['bad ID signature',{badIdSignature:true}],
 ['wrong API owner',{accessClaims:{sub:'different-owner'}}],['wrong API audience',{accessClaims:{aud:'https://other.invalid/mcp'}}],
 ['wrong API issuer',{accessClaims:{iss:'https://other.invalid/'}}],['expired API token',{accessClaims:{exp:1}}],
 ['ordinary MCP scope',{accessClaims:{scope:'bridge:mcp'}}],['missing API scope',{accessClaims:{scope:undefined}}],
 ['ID token used as API token',{accessType:'JWT'}],['missing jti',{accessClaims:{jti:undefined}}],
 ['overlong API lifetime',{accessClaims:{exp:Math.floor(Date.now()/1000)+7200}}],
])test('login rejects '+name,async t=>{
 const f=await adminFixture(t,{issuer}),b=f.browser(),url=await b.begin();const r=await b.request(url.pathname+url.search);assert.equal(r.status,400,name);
 for(const token of f.issuer.accessTokens)assert.ok(!JSON.stringify(r).includes(token));
 assert.equal(f.upstream.length,0);assert.ok(!(await b.request('/admin')).body.includes('实际扫码账号'));
});
test('untrusted discovery endpoints are rejected before sending the client secret',async t=>{
 const f=await adminFixture(t,{issuer:{metadata:{token_endpoint:'https://attacker.example.invalid/token'}}}),b=f.browser();await b.request('/admin');const r=await b.request('/admin/login','POST');assert.equal(r.status,400);assert.equal(f.issuer.requests.length,1);
});
test('CSRF, Origin, fetch-site, duplicate fields and repeated form submissions cannot create QR',async t=>{
 const f=await adminFixture(t),b=f.browser();await b.login();const csrf=b.csrf;
 assert.equal((await b.request('/admin/ui/begin','POST',{csrf:'wrong'})).status,403);
 assert.equal((await b.request('/admin/ui/begin','POST',{}, {headers:{origin:'https://evil.invalid'}})).status,403);
 assert.equal((await b.request('/admin/ui/begin','POST',{}, {headers:{'sec-fetch-site':'cross-site'}})).status,403);
 assert.equal((await b.request('/admin/ui/begin','POST',{}, {body:'csrf='+csrf+'&csrf='+csrf})).status,400);
 assert.equal(f.upstream.length,0);
 const begun=await b.request('/admin/ui/begin','POST');assert.equal(begun.status,200);assert.ok(begun.body.includes('data:image/png;base64,'));assert.equal(f.upstream.length,1);
 assert.equal((await b.request('/admin/ui/begin','POST',{csrf})).status,403);assert.equal(f.upstream.length,1);
});
test('full UI QR candidate confirmation, account switch protection, unlink and logout remain owner-controlled',async t=>{
 const f=await adminFixture(t),b=f.browser();await b.login();const begun=await b.request('/admin/ui/begin','POST'),id=requestId(begun.body);
 assert.ok(id);const candidate=await b.request('/admin/ui/poll','POST',{requestId:id});assert.ok(candidate.body.includes('synthetic-scanner-A'));assert.equal(f.store.state.link.binding,null);
 assert.equal((await b.request('/admin/ui/confirm','POST',{requestId:id,scannerId:'synthetic-scanner-B'})).status,400);assert.equal(f.store.state.link.binding,null);
 await b.request('/admin');const confirmed=await b.request('/admin/ui/confirm','POST',{requestId:id,scannerId:'synthetic-scanner-A'});assert.equal(confirmed.status,200);assert.equal(f.store.state.link.binding.scannerId,'synthetic-scanner-A');assert.equal(f.runtimes.length,0);
 assert.ok(!confirmed.body.includes('synthetic-private-bot-token'));assert.ok(!confirmed.body.includes('synthetic-private-qr'));
 await b.request('/admin/ui/revoke','POST',{requestId:id});assert.equal(f.store.state.link.binding,null);
 f.setScanner('synthetic-scanner-B');const second=await b.request('/admin/ui/begin','POST'),id2=requestId(second.body);assert.notEqual(id,id2);
 await b.request('/admin/ui/poll','POST',{requestId:id2});assert.equal((await b.request('/admin/ui/confirm','POST',{requestId:id,scannerId:'synthetic-scanner-A'})).status,400);
 await b.request('/admin');assert.equal((await b.request('/admin/ui/confirm','POST',{requestId:id2,scannerId:'synthetic-scanner-B'})).status,200);
 const oldCookie=b.cookie,oldCsrf=b.csrf;assert.equal((await b.request('/admin/logout','POST')).status,303);
 const stale=await f.app.handle({path:'/admin/ui/revoke',method:'POST',secure:true,headers:{cookie:oldCookie,origin:ORIGIN,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:oldCsrf,requestId:id2}).toString()});assert.equal(stale.status,403);
 assert.equal(f.store.state.link.binding.scannerId,'synthetic-scanner-B','local logout is not an implicit persistent unlink');
});
test('logout invalidates a pending code exchange without resurrecting a session',async t=>{
 let enter,release;const started=new Promise(r=>{enter=r;});
 const f=await adminFixture(t,{issuer:{tokenGate:()=>{enter();return new Promise(r=>{release=r;});}}}),b=f.browser(),url=await b.begin();
 await b.request('/admin');const pending=b.request(url.pathname+url.search);await started;
 const logout=await b.request('/admin/logout','POST');assert.equal(logout.status,303);release();assert.equal((await pending).status,400);
 assert.equal((await b.request('/admin/ui/begin','POST')).status,403);assert.equal(f.upstream.length,0);
});
test('logout aborts an in-flight QR creation before encrypted binding state is saved',async t=>{
 const f=await adminFixture(t),b=f.browser();await b.login();let entered,release;const started=new Promise(r=>{entered=r;});
 f.setQrGate(signal=>{entered();return new Promise(r=>{signal.addEventListener('abort',r,{once:true});});});const pending=b.request('/admin/ui/begin','POST');await started;
 await b.request('/admin');assert.equal((await b.request('/admin/logout','POST')).status,303);assert.equal((await pending).status,400);assert.equal(f.store.state.link?.request??null,null);
});
test('logout cancels confirmation paused at inner authorization and drains it before acknowledging',async t=>{
 const f=await adminFixture(t,{callbackHosts:['events.example.invalid']}),b=f.browser();await b.login();
 const start=await b.request('/admin/ui/begin','POST'),id=requestId(start.body);await b.request('/admin/ui/poll','POST',{requestId:id});
 let enter,release,count=0;const entered=new Promise(r=>{enter=r;});
 f.setAuthGate(()=>{if(++count===3){enter();return new Promise(r=>{release=r;});}});
 const pending=b.request('/admin/ui/confirm','POST',{requestId:id,scannerId:'synthetic-scanner-A'});await entered;
 await b.request('/admin');let acknowledged=false;const logout=b.request('/admin/logout','POST').then(r=>{acknowledged=true;return r;});
 await new Promise(r=>setImmediate(r));assert.equal(acknowledged,false);release();
 assert.equal((await pending).status,400);assert.equal((await logout).status,303);
 assert.equal(f.store.state.link.binding,null);assert.equal(f.runtimes.length,0);
});
test('revoked owner permission invalidates an existing session before UI data or binding work',async t=>{
 const f=await adminFixture(t),b=f.browser();await b.login();f.store.state.auth.enabled=false;await f.store.save();const r=await b.request('/admin/ui/begin','POST');assert.equal(r.status,400);assert.equal(f.upstream.length,0);
 const page=await b.request('/admin');assert.ok(page.body.includes('通过身份提供方登录'));assert.ok(!page.body.includes('实际扫码账号'));
});
test('anonymous session pressure never evicts an authenticated owner or locks out fresh login',async t=>{
 const f=await adminFixture(t),owner=f.browser();await owner.login();
 for(let i=0;i<150;i++)assert.equal((await f.browser().request('/admin')).status,200);
 assert.ok((await owner.request('/admin')).body.includes('启动准备模式'));await f.browser().login();
});
test('scanner identity is escaped and never trusted as HTML',async t=>{
 const f=await adminFixture(t),b=f.browser();await b.login();const r=await b.request('/admin/ui/begin','POST');f.setScanner('<img src=x onerror=alert(1)>');const page=await b.request('/admin/ui/poll','POST',{requestId:requestId(r.body)});
 assert.equal(page.status,200);assert.ok(page.body.includes('&lt;img'));assert.ok(!page.body.includes('<img src=x'));
});
test('empty callback allowlist permits authenticated MCP discovery/status, refuses subscribe/reply, and starts no runtime',async t=>{
 const f=await adminFixture(t),token=await f.issuer.access({},'bridge:mcp');await f.app.start();
 for(const method of ['server/discover','tools/list','events/list'])assert.ok(JSON.parse((await f.app.handle(mcpInput(token,method))).body).result);
 const state=JSON.parse((await f.app.handle(mcpInput(token,'tools/call',{name:'wechat_status'}))).body).result.structuredContent;assert.equal(state.mode,'bootstrap');assert.equal(state.callbacksConfigured,false);
 for(const [method,args] of [['events/subscribe',{}],['tools/call',{name:'wechat_reply',arguments:{message_id:'synthetic',text:'hello',idempotency_key:'one'}}]]){
  const r=JSON.parse((await f.app.handle(mcpInput(token,method,args))).body);assert.equal(r.error.message,'callbacks_not_configured');
 }
 assert.equal((await f.app.handle(mcpInput('not-a-token','server/discover'))).status,401);
 assert.equal(f.runtimes.length,0);assert.equal(f.upstream.length,0);assert.equal(f.callbacks.length,0);
});
