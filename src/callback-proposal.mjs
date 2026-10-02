import {isIP} from 'node:net';
import {secretKey} from './security.mjs';
import {EVENT} from './bridge.mjs';
const object=x=>x&&typeof x==='object'&&!Array.isArray(x);
const exact=(x,keys)=>object(x)&&Object.keys(x).every(k=>keys.includes(k));
const hostname=/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

// Inspect an authenticated, bound owner's subscription attempt without granting
// access, resolving DNS, sending a challenge, or retaining its URL/signing key.
// The returned hostname is an unverified proposal, never a transport allowlist.
export function observedCallbackHost(p,binding) {
 if(!binding||typeof binding.scannerId!=='string'||!binding.scannerId||typeof binding.botId!=='string'||!binding.botId||!object(p)||p.name!==EVENT||!exact(p.arguments,['sender_id'])||p.arguments.sender_id!==binding.scannerId||binding.scannerId===binding.botId||!exact(p.delivery,['mode','url','secret'])||p.delivery.mode!=='webhook'||typeof p.delivery.url!=='string'||p.delivery.url.length>8192||p.cursor!=null||p.ttlMs!=null&&(!Number.isFinite(p.ttlMs)||p.ttlMs<=0))throw Error('invalid_callback_proposal');
 const u=new URL(p.delivery.url);
 if(u.protocol!=='https:'||u.username||u.password||u.hash||(u.port&&u.port!=='443')||isIP(u.hostname)||u.hostname.length>253||!hostname.test(u.hostname))throw Error('invalid_callback_proposal');
 const key=secretKey(p.delivery.secret);key.fill(0);
 return u.hostname;
}
