/** Authenticated Android-only C8 catalog broker. No arbitrary URLs in inputs. */
import {randomUUID} from "node:crypto";
import {settings} from "./c3-config.mjs";
import {store,reserveSlot,releaseSlot} from "./c3-store.mjs";
import {requireSession} from "./c3-session.mjs";
import {enabled,notEnabled,failure,boundedBody,fetchWorker} from "./c3-gateway.mjs";
import {maintenanceEnabled,serviceMaintenanceEnabled,recordWorkerResult} from "./c6-ops-store.mjs";
import {providerEnabled,downloadVpnCatalog,mkkSourceIds,VpnProviderError} from "./server-vpn-provider.mjs";
import {providerAllowed} from "./c12-provider-controls.mjs";
import {packPairedVpnCatalogs} from "./paired-vpn-catalogs.mjs";
import {packMkkSources} from "./mkk-source-bundle.mjs";
import {sharedCatalog} from "./server-vpn-result-cache.mjs";
import {catalogCacheConfig} from "./server-vpn-cache-controls.mjs";

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
    const appVersion=request.headers.get("x-spdecode-app-version");
    // Only a cache-miss lease owner reserves a decoder worker slot.
    const load=async()=>{
      lease=randomUUID();
      if(!await reserveSlot(redis,claims.jti,lease)){
        lease=null;
        return failure("RATE_LIMITED",429);
      }
      started=performance.now();
      const response=await loadServerVpnResult(providerId,opts,n=>{downloadedBytes=n;});
    try{
      let errorCode="",outcome=response.ok?"success":"failed";
      const result=await response.clone().json();
      if(!response.ok)errorCode=result.error?.code||"";
      else if(providerId==="mkk-hyper" && result.isPartial===true){
        // Decoding succeeded but some vendor sources failed; this is not a
        // completely successful catalog. Preserve the warning in diagnostics.
        outcome="warning";errorCode="PARTIAL_SOURCE_FAILURE";
      }
      await recordWorkerResult(redis,outcome,{
        kind:"server-vpn",format:providerId,bytes:downloadedBytes,errorCode,
        latencyMs:performance.now()-started,
        appVersion,
      });
    }catch{}

      return response;
    };
    return await sharedCatalog(redis,await catalogCacheConfig(redis,providerId,load));
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

/** Shared fixed-provider loader used by authenticated requests and the internal scheduler. */
export async function loadServerVpnResult(providerId,opts={},onBytes=()=>{}){
    let bytes,httpConexionRefreshed=false;
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
        throw new VpnProviderError("REMOTE_PROVIDER_UNAVAILABLE");
      const bundle=packMkkSources(sources);
      if(!bundle.sources.some(item=>item.status==="ok"))
        throw new VpnProviderError("REMOTE_TOO_LARGE");
      // Each omitted source is explicitly marked REMOTE_TOO_LARGE. Remaining
      // sources are passed intact, with the worker's partial warning visible.
      bytes=bundle.payload;
    }else if(["speicers-turbo-vpn","jyfast-vpn-ultra","abowaged-vpn","http-socketclay","http-wakko","v2ray-tunnel-plus","onspace-vpn","superflash-vpn","turbomx-vpn"].includes(providerId)){
      const names=providerId==="jyfast-vpn-ultra"?["free","premium"]:providerId==="abowaged-vpn"?["servers","udp"]:providerId==="v2ray-tunnel-plus"?["base64","raw"]:["servers","users"];
      const sources=await Promise.all(names.map(async name=>[name,await downloadVpnCatalog(providerId,name)]));
      bytes=packPairedVpnCatalogs(providerId,Object.fromEntries(sources));
    }else if(providerId==="http-conexion"){
      try{bytes=await downloadVpnCatalog(providerId);}
      catch(error){
        if(!(error instanceof VpnProviderError)||!["REMOTE_PROVIDER_UNAVAILABLE","REMOTE_RESPONSE_INVALID"].includes(error.code))throw error;
        bytes=await downloadVpnCatalog(providerId,"servers",{forceRefresh:true});httpConexionRefreshed=true;
      }
    }else{
      bytes=await downloadVpnCatalog(providerId);
    }
    onBytes(bytes.length);
    let response=await fetchWorker("server-vpn",{
      providerId,dataBase64:bytes.toString("base64"),
    },settings(),opts);
    if(providerId==="http-conexion"&&!httpConexionRefreshed&&!response.ok){
      let code;try{code=(await response.clone().json()).error?.code;}catch{}
      if(["DECODE_FAILED","REMOTE_DECODER_FAILED"].includes(code)){
        bytes=await downloadVpnCatalog(providerId,"servers",{forceRefresh:true});onBytes(bytes.length);
        response=await fetchWorker("server-vpn",{providerId,dataBase64:bytes.toString("base64")},settings(),opts);
      }
    }
    return response;
}
