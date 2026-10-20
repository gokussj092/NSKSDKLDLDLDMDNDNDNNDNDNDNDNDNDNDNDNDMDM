/** Authenticated Android-only C8 catalog broker. No arbitrary URLs in inputs. */
import {randomUUID} from "node:crypto";
import {settings} from "./c3-config.mjs";
import {store,reserveSlot,releaseSlot} from "./c3-store.mjs";
import {requireSession} from "./c3-session.mjs";
import {enabled,notEnabled,failure,boundedBody,fetchWorker} from "./c3-gateway.mjs";
import {maintenanceEnabled,serviceMaintenanceEnabled,recordWorkerResult} from "./c6-ops-store.mjs";
import {providerEnabled,downloadVpnCatalog,VpnProviderError} from "./server-vpn-provider.mjs";

export async function decodeServerVpn(request,opts={}){
  if(!enabled())return notEnabled();
  let redis,claims,lease=null,providerId="";
  try{
    redis=await (opts.storeProvider||store)();
    if(await maintenanceEnabled(redis))return failure("SERVICE_UNAVAILABLE",503);
    if(await serviceMaintenanceEnabled(redis,"serverVpn"))return failure("SERVICE_MAINTENANCE",503);
    claims=await requireSession(redis,request,settings());
    if(!claims)return failure("UNAUTHORIZED",401);
    if(claims.rateLimited)return failure("RATE_LIMITED",429);
    const payload=await boundedBody(request,1024);
    if(!payload||typeof payload!=="object"||Array.isArray(payload)||
       Object.keys(payload).length!==2||typeof payload.id!=="string"||
       payload.consent!==true)return failure("INVALID_REQUEST",400);
    providerId=payload.id;
    if(!providerEnabled(providerId))return failure("REMOTE_NOT_CONFIGURED",503);
    lease=randomUUID();
    if(!await reserveSlot(redis,claims.jti,lease))return failure("RATE_LIMITED",429);
    const bytes=await downloadVpnCatalog(providerId);
    const response=await fetchWorker("server-vpn",{
      providerId,dataBase64:bytes.toString("base64"),
    },settings(),opts);
    try{
      let errorCode="";
      if(!response.ok)errorCode=(await response.clone().json()).error?.code||"";
      await recordWorkerResult(redis,response.ok?"success":"failed",{
        kind:"server-vpn",format:providerId,bytes:bytes.length,errorCode,
      });
    }catch{}
    return response;
  }catch(error){
    if(redis&&lease)try{await recordWorkerResult(redis,"failed",{kind:"server-vpn",format:providerId,bytes:0,
      errorCode:error?.code||"SERVICE_UNAVAILABLE"});}catch{}
    if(error instanceof VpnProviderError){
      const statuses={REMOTE_NOT_CONFIGURED:503,UNSUPPORTED_FORMAT:422,
        REMOTE_NETWORK_DENIED:502,REMOTE_PROVIDER_UNAVAILABLE:502,
        REMOTE_RESPONSE_INVALID:422,REMOTE_TOO_LARGE:413};
      return failure(error.code,statuses[error.code]||503);
    }
    return failure(error?.code==="INVALID_REQUEST"?"INVALID_REQUEST":"SERVICE_UNAVAILABLE",
      error?.code==="INVALID_REQUEST"?400:503);
  }finally{
    if(redis&&lease)try{await releaseSlot(redis,claims.jti,lease);}catch{}
  }
}
