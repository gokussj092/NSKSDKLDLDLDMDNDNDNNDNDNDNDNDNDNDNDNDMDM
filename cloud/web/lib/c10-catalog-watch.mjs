/** Short-lived HTTPS long-poll: Server VPN version only; no user account, FCM or identifiers. */
import {activeCatalogVersion} from "./server-vpn-catalog.mjs";
export const WATCH_SECONDS=12;
export const MAX_OPEN_WATCHES=64;
let activeWatches=0;
const json=(value,status=200)=>Response.json(value,{status,headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
const pause=(ms,signal)=>new Promise(resolve=>{
 if(signal?.aborted){resolve();return;}
 const done=()=>{clearTimeout(timer);signal?.removeEventListener("abort",done);resolve();};
 const timer=setTimeout(done,ms);
 signal?.addEventListener("abort",done,{once:true});
});
export async function catalogWatchRequest(request,{versionProvider=activeCatalogVersion,wait=pause}={}){
 let knownVersion;
 try{
  if(request.method!=="POST"||
    request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase()!=="application/json"||
    Number(request.headers.get("content-length")||0)>256)return json({error:{code:"INVALID_REQUEST"}},400);
  const input=await request.json();
  if(!input||Array.isArray(input)||typeof input!=="object"||
    Object.keys(input).length!==1||!Number.isSafeInteger(input.knownVersion)||
    input.knownVersion<0||input.knownVersion>999999999)return json({error:{code:"INVALID_REQUEST"}},400);
  knownVersion=input.knownVersion;
 }catch{return json({error:{code:"INVALID_REQUEST"}},400);}
 if(activeWatches>=MAX_OPEN_WATCHES)
  return json({error:{code:"RATE_LIMITED"}},429);
 activeWatches++;
 try{
  const start=Date.now();
  let current=versionProvider();
  while(current<=knownVersion && Date.now()-start<WATCH_SECONDS*1000 && !request.signal?.aborted){
   await wait(1500,request.signal);
   if(request.signal?.aborted)break;
   current=versionProvider();
  }
  return json({apiVersion:"v1",catalogVersion:current,
   changed:current>knownVersion,checkOnly:true});
 }catch{return json({error:{code:"SERVICE_UNAVAILABLE"}},503);}
 finally{activeWatches--;}
}
