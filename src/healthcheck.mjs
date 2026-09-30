import {request} from 'node:https';
// Connect locally but verify the actual configured hostname/certificate.
try{
 const u=new URL(process.env.BRIDGE_PUBLIC_URL);if(u.protocol!=='https:')throw Error();
 const req=request({hostname:'127.0.0.1',port:Number(process.env.BRIDGE_PORT??8443),path:'/healthz',method:'GET',servername:u.hostname,headers:{host:u.host},rejectUnauthorized:true},res=>{res.resume();res.on('end',()=>{process.exitCode=res.statusCode===200?0:1;});});
 req.setTimeout(4000,()=>req.destroy());req.on('error',()=>{process.exitCode=1;});req.end();
}catch{process.exitCode=1;}
