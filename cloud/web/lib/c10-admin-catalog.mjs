import {adminSettings,authenticateAdmin,validMutation} from "./c6-admin-auth.mjs";
import {opsStore} from "./c6-ops-store.mjs";
import {publishCatalogUpdate,pushSettings} from "./c10-catalog-push.mjs";
const reply=(body,status=200)=>Response.json(body,{status,headers:{"Cache-Control":"private, no-store"}});
export async function publishRequest(request,{storeProvider=opsStore,fetchImpl=fetch}={}){
 const cfg=adminSettings();
 if(!cfg.enabled)return reply({status:"error",code:"ADMIN_DISABLED"},503);
 if(!validMutation(request,cfg))return reply({status:"error",code:"CSRF_REJECTED"},403);
 try{
  const redis=await storeProvider();
  if(!await authenticateAdmin(redis,request,cfg))return reply({status:"error",code:"UNAUTHORIZED"},401);
  // Deliberately no request body: the server decides the current monotonic version.
  if(request.headers.get("content-length") && request.headers.get("content-length")!=="0")
   return reply({status:"error",code:"INVALID_REQUEST"},400);
  const status=await publishCatalogUpdate(redis,{fetchImpl});
  return reply(status,status.status==="not_configured"?503:200);
 }catch{return reply({status:"error",code:"PUBLISH_FAILED"},503);}
}
export async function publishStatusRequest(request,{storeProvider=opsStore}={}){
 if(!adminSettings().enabled)return reply({status:"error",code:"ADMIN_DISABLED"},503);
 try{
  const redis=await storeProvider();
  if(!await authenticateAdmin(redis,request))return reply({status:"error",code:"UNAUTHORIZED"},401);
  return reply({status:"ok",configured:pushSettings().enabled,
   lastAnnounced:Number(await redis.get("spc10:catalog:last-announced")||0)});
 }catch{return reply({status:"error",code:"SERVICE_UNAVAILABLE"},503);}
}
