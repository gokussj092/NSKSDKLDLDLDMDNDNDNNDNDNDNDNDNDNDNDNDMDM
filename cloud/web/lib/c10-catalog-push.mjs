/** C10: only public catalog version goes to the FCM topic. No user tokens stored by SP-DECODE. */
import {createSign,randomUUID} from "node:crypto";
import {activeCatalogVersion} from "./server-vpn-catalog.mjs";
const LOCK="spc10:catalog:notify-lock";
const SENT="spc10:catalog:last-announced";
const TOPIC="spdecode-vpn-catalog";
const validProject=/^[a-z][a-z0-9-]{5,62}$/;
export function pushSettings(env=process.env){
  let service=null;
  try{
   const value=JSON.parse(env.CLOUD_FCM_SERVICE_ACCOUNT_JSON||"");
   if(value.type==="service_account" && value.private_key?.includes("PRIVATE KEY") &&
      typeof value.client_email==="string" && value.client_email.endsWith(".gserviceaccount.com"))
     service=value;
  }catch{}
  const project=env.CLOUD_FCM_PROJECT_ID||"";
  return {enabled:env.CLOUD_FCM_ENABLED==="true"&&Boolean(service)&&validProject.test(project)&&
    service.project_id===project,project,service};
}
const base64url=value=>Buffer.from(JSON.stringify(value)).toString("base64url");
function jwt(service,now){
 const h=base64url({alg:"RS256",typ:"JWT"}),b=base64url({
  iss:service.client_email,scope:"https://www.googleapis.com/auth/firebase.messaging",
  aud:"https://oauth2.googleapis.com/token",iat:now,exp:now+300
 });
 const sign=createSign("RSA-SHA256");sign.update(h+"."+b);sign.end();
 return h+"."+b+"."+sign.sign(service.private_key,"base64url");
}
export async function publishCatalogUpdate(redis,{env=process.env,fetchImpl=fetch}={}){
 const cfg=pushSettings(env);
 if(!cfg.enabled)return {status:"not_configured"};
 const version=activeCatalogVersion(env);
 const before=Number(await redis.get(SENT)||0);
 if(before>=version)return {status:"unchanged",version};
 const lockId=randomUUID();
 if(await redis.set(LOCK,lockId,{NX:true,EX:90})!=="OK")
   return {status:"busy",version};
 try {
  const latest=Number(await redis.get(SENT)||0);
  if(latest>=version)return {status:"unchanged",version};
  const now=Math.floor(Date.now()/1000);
  const auth=await fetchImpl("https://oauth2.googleapis.com/token",{
   method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},
   body:new URLSearchParams({grant_type:"urn:ietf:params:oauth:grant-type:jwt-bearer",assertion:jwt(cfg.service,now)}),
   cache:"no-store",redirect:"error",signal:AbortSignal.timeout(8000)
  });
  if(!auth.ok)throw Error("FCM_AUTH_FAILED");
  const parsed=await auth.json();
  if(typeof parsed.access_token!=="string"||parsed.access_token.length<20)throw Error("FCM_AUTH_INVALID");
  const url="https://fcm.googleapis.com/v1/projects/"+cfg.project+"/messages:send";
  const send=await fetchImpl(url,{method:"POST",headers:{
   "Content-Type":"application/json","Authorization":"Bearer "+parsed.access_token
  },body:JSON.stringify({message:{topic:TOPIC,
    data:{type:"catalog_update",catalogVersion:String(version)},
    android:{priority:"NORMAL",ttl:"86400s"}}}),
   cache:"no-store",redirect:"error",signal:AbortSignal.timeout(8000)
  });
  if(!send.ok)throw Error("FCM_SEND_FAILED");
  await redis.set(SENT,String(version));
  return {status:"published",version};
 }finally{
  // Other worker may have acquired a new lock after expiry; never delete theirs.
  if(await redis.get(LOCK)===lockId)await redis.del(LOCK);
 }
}
export const catalogTopic=TOPIC;
