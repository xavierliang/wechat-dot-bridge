import {createServer} from 'node:https';
import {safeLog} from './logging.mjs';
const MAX_BODY=262144;
export function createRequestHandler({application,publicUrl,shutdownSignal}){
 const host=new URL(publicUrl).host;
 return async(req,res)=>{
  const controller=new AbortController();
  const abort=()=>controller.abort();req.once('aborted',abort);res.once('close',abort);
  const signal=shutdownSignal?AbortSignal.any([controller.signal,shutdownSignal]):controller.signal;
  function send(output){if(!res.destroyed){res.writeHead(output.status,{...output.headers,'strict-transport-security':'max-age=31536000'});res.end(output.body);}}
  try{
   if(req.socket.encrypted!==true||req.headers.host!==host){send({status:400,body:'{"error":"invalid_origin"}'});req.resume();return;}
   if(typeof req.url!=='string'||!req.url.startsWith('/')||req.url.includes('?')||req.url.includes('#')){send({status:400,body:'{"error":"invalid_path"}'});req.resume();return;}
   if(req.headers['content-length']&&(!/^\d+$/.test(req.headers['content-length'])||Number(req.headers['content-length'])>MAX_BODY)){send({status:413,body:'{"error":"body_too_large"}'});req.resume();return;}
   const chunks=[];let size=0;
   for await(const c of req){size+=c.length;if(size>MAX_BODY){send({status:413,body:'{"error":"body_too_large"}'});return;}chunks.push(c);}
   const output=await application.handle({path:req.url,method:req.method,headers:req.headers,body:Buffer.concat(chunks).toString('utf8'),secure:true,signal});send(output);
  }catch{safeLog('request_failed');send({status:500,body:'{"error":"request_failed"}'});}
  finally{req.removeListener('aborted',abort);res.removeListener('close',abort);}
 };
}
export function createHttpsServer({application,publicUrl,tlsKey,tlsCert,shutdownSignal}){
 const server=createServer({key:tlsKey,cert:tlsCert,minVersion:'TLSv1.2',maxHeaderSize:16384},createRequestHandler({application,publicUrl,shutdownSignal}));
 server.requestTimeout=15000;server.headersTimeout=10000;server.keepAliveTimeout=5000;server.maxConnections=64;server.maxRequestsPerSocket=100;
 return server;
}
