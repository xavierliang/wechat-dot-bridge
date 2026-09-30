import {setTimeout as delay} from 'node:timers/promises';
const pause=(ms,signal)=>delay(ms,undefined,{signal});
// Owns only runtime lifecycle. No constructor starts network work.
export class PollingRuntime {
 constructor({bridge,wait=pause,onState=()=>{}}){this.bridge=bridge;this.wait=wait;this.onState=onState;this.controller=new AbortController();this.phase='idle';this.started=false;this.done=Promise.resolve();}
 get signal(){return this.controller.signal;}
 setPhase(phase){this.phase=phase;this.onState(phase);}
 start(){
  if(this.started)throw Error('runtime_already_started');this.started=true;this.setPhase('starting');
  this.done=Promise.all([this.pollLoop(),this.deliveryLoop()]);return this;
 }
 async pollLoop(){
  let failures=0;
  while(!this.signal.aborted){
   try{await this.bridge.pollOnce(this.signal);failures=0;this.setPhase('running');await this.wait(250,this.signal);}
   catch(e){
    if(this.signal.aborted)break;
    if(['ilink_session_expired','storage_unavailable','inbox_capacity_reached','storage_capacity_reached','unauthorized','invalid_message','invalid_batch'].includes(e.code??e.message)){
     this.setPhase(e.code==='ilink_session_expired'?'relink_required':'blocked');this.controller.abort();break;
    }
    this.setPhase('retrying');failures++;try{await this.wait(Math.min(60000,1000*2**Math.min(failures-1,6)),this.signal);}catch{break;}
   }
  }
 }
 async deliveryLoop(){
  while(!this.signal.aborted){
   try{await this.bridge.pump();await this.wait(250,this.signal);}
   catch{if(!this.signal.aborted){this.setPhase('blocked');this.controller.abort();}break;}
  }
 }
 async stop(){this.controller.abort();await this.done;await this.bridge.queue;if(!['relink_required','blocked'].includes(this.phase))this.setPhase('stopped');}
}
