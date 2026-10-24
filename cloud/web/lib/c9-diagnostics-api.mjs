/** C9 Android-only authenticated diagnostics. No public unauthenticated reporting. */
import {settings} from "./c3-config.mjs";
import {store,throttle} from "./c3-store.mjs";
import {requireSession} from "./c3-session.mjs";
import {enabled,notEnabled,boundedBody,failure} from "./c3-gateway.mjs";
import {recordIncident,recordOptInInstallation} from "./c9-diagnostics.mjs";
const send=(value,status=200)=>Response.json(value,{status,headers:{"Cache-Control":"no-store"}});
const serviceIds=new Set(["files","httpInjector","serverVpn"]);
const errorCode=/^[A-Z][A-Z0-9_]{2,49}$/;
const formatCode=/^[a-z0-9][a-z0-9._-]{0,31}$/;
const versions=/^\d{1,3}(?:\.\d{1,3}){0,3}$/;
export async function diagnosticRequest(request,{storeProvider=store}={}){
 if(!enabled())return notEnabled();
 try{
  const redis=await storeProvider();
  const claims=await requireSession(redis,request,settings());
  if(!claims)return failure("UNAUTHORIZED",401);
  if(claims.rateLimited)return failure("RATE_LIMITED",429);
  const payload=await boundedBody(request,1024);
  if(!payload||typeof payload!=="object"||Array.isArray(payload))return failure("INVALID_REQUEST",400);
  if(payload.type==="activity"){
   if(Object.keys(payload).sort().join(",")!=="consent,installationId,type"||
      payload.consent!==true||typeof payload.installationId!=="string"||
      !/^[0-9a-f]{32}$/.test(payload.installationId))return failure("INVALID_REQUEST",400);
   if(!await throttle(redis,"spc9:activity:"+claims.jti,3,3600))return failure("RATE_LIMITED",429);
   await recordOptInInstallation(redis,payload.installationId,settings().signingKey);
   return send({status:"ok",registered:true});
  }
  if(payload.type==="report"){
   if(Object.keys(payload).sort().join(",")!=="appVersion,code,format,service,type"||
      !serviceIds.has(payload.service)||typeof payload.code!=="string"||
      !errorCode.test(payload.code)||typeof payload.format!=="string"||
      !formatCode.test(payload.format)||typeof payload.appVersion!=="string"||
      !versions.test(payload.appVersion))return failure("INVALID_REQUEST",400);
   if(!await throttle(redis,"spc9:report:"+claims.jti,3,86400))return failure("RATE_LIMITED",429);
   const id=await recordIncident(redis,{service:payload.service,format:payload.format,
       code:payload.code,source:"user",appVersion:payload.appVersion});
   return send({status:"ok",reportId:id},201);
  }
  return failure("INVALID_REQUEST",400);
 }catch(error){
  if(error?.code==="INVALID_REQUEST"||error?.code==="INVALID_BASE64")return failure("INVALID_REQUEST",400);
  return failure("SERVICE_UNAVAILABLE",503);
 }
}
