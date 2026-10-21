/** Authenticated Android-only C8 catalog broker. No arbitrary URLs in inputs. */
import {randomUUID} from "node:crypto";
import {settings} from "./c3-config.mjs";
import {store,reserveSlot,releaseSlot} from "./c3-store.mjs";
import {requireSession} from "./c3-session.mjs";
import {enabled,notEnabled,failure,boundedBody,fetchWorker} from "./c3-gateway.mjs";
import {maintenanceEnabled,serviceMaintenanceEnabled,recordWorkerResult} from "./c6-ops-store.mjs";
import {providerEnabled,downloadVpnCatalog,mkkSourceIds,VpnProviderError} from "./server-vpn-provider.mjs";
import {providerAllowed} from "./c12-provider-controls.mjs";

export async function decodeServerVpn(request,opts={}){
  if(!enabled())return notEnabled();
  let redis,claims,lease=null,providerId="",downloadedBytes=0,started=null;
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
    if(!providerEnabled(providerId) || !await providerAllowed(providerId))
      return failure("REMOTE_NOT_CONFIGURED",503);
    lease=randomUUID();
    started=performance.now();
    if(!await reserveSlot(redis,claims.jti,lease))return failure("RATE_LIMITED",429);
    let bytes;
    if(providerId==="mkk-hyper"){
      // A single api_server.json call silently omitted static users and
      // subscription catalogs. Fetch each fixed source without caller URLs.
      // Preserve independent failures as explicit source statuses.
      const sources=await Promise.all(mkkSourceIds().map(async name=>{
        try{
          const payload=await downloadVpnCatalog(providerId,name);
          return {name,status:"ok",dataBase64:payload.toString("base64")};
        }catch(error){
          if(!(error instanceof VpnProviderError))throw error;
          return {name,status:"error",error:error.code};
        }
      }));
      if(!sources.some(item=>item.status==="ok"))
        return failure("REMOTE_PROVIDER_UNAVAILABLE",502);
      bytes=Buffer.from(JSON.stringify({kind:"spdecode-mkk-sources-v1",sources}),"utf8");
      // Worker input has a 16 MiB hard bound; never ship a partial bundle
      // because of the transport cap without explicitly returning an error.
      if(bytes.length>12*1024*1024)return failure("REMOTE_TOO_LARGE",413);
    }else{
      bytes=await downloadVpnCatalog(providerId);
    }
    downloadedBytes=bytes.length;
    const response=await fetchWorker("server-vpn",{
      providerId,dataBase64:bytes.toString("base64"),
    },settings(),opts);
    try{
      let errorCode="";
      if(!response.ok)errorCode=(await response.clone().json()).error?.code||"";
      await recordWorkerResult(redis,response.ok?"success":"failed",{
        kind:"server-vpn",format:providerId,bytes:bytes.length,errorCode,
        latencyMs:performance.now()-started,
        appVersion:request.headers.get("x-spdecode-app-version"),
      });
    }catch{}
    return response;
  }catch(error){
    // Distinguish worker schema/output failures from transient network errors.
    // Persist only sanitized buckets and length; never log VPN payload bytes.
    const workerErrors={
      INVALID_WORKER_JSON:"REMOTE_DECODER_FAILED",
      INVALID_WORKER_SHAPE:"REMOTE_DECODER_FAILED",
      INVALID_WORKER_RESULT:"REMOTE_DECODER_FAILED",
      OUTPUT_OVER_LIMIT:"OUTPUT_TOO_LARGE",
    };
    const code=error?.code||workerErrors[error?.message]||"SERVICE_UNAVAILABLE";
    if(redis&&lease)try{await recordWorkerResult(redis,"failed",{kind:"server-vpn",format:providerId,bytes:downloadedBytes,
      errorCode:code,latencyMs:started===null?null:performance.now()-started,
      appVersion:request.headers.get("x-spdecode-app-version")});}catch{}
    if(code==="REMOTE_DECODER_FAILED")return failure(code,502);
    if(code==="OUTPUT_TOO_LARGE")return failure(code,413);
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
