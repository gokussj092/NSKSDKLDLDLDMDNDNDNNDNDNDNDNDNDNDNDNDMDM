/** C3.5 session-gated remote imports; only the broker knows external URLs. */
import {jsonReply} from "./responses.mjs";
import {sharedCatalog} from "./server-vpn-result-cache.mjs";
import {catalogCacheConfig} from "./server-vpn-cache-controls.mjs";
import { randomUUID } from "node:crypto";
import {providerAllowed} from "./c12-provider-controls.mjs";
import { settings } from "./c3-config.mjs";
import { store, reserveSlot, releaseSlot } from "./c3-store.mjs";
import { requireSession } from "./c3-session.mjs";
import { enabled, notEnabled, failure, boundedBody, fetchWorker } from "./c3-gateway.mjs";
import { maintenanceEnabled, serviceMaintenanceEnabled, recordWorkerResult } from "./c6-ops-store.mjs";
import {
  isExternalImportError, parseEhiReference, ehiConfigured, nurConfigured,
  importEhiReference, downloadNur,
  parseMnrReference, importMnrReference, parseHttpCustomReference, importHttpCustomReference,
} from "./c35-provider.mjs";
const ownKeys=(value,expected)=> value && typeof value==="object" && !Array.isArray(value)
  && Object.keys(value).length===expected.length && expected.every(key=>Object.hasOwn(value,key));

export async function externalImportRequest(request,kind,opts={}) {
  if (!enabled()) return notEnabled();
  if (kind==="ehi" && !ehiConfigured() || kind==="nur" && !nurConfigured() ||
      kind==="mnr" && process.env.CLOUD_SERVER_VPN_ENABLED!=="true")
    return failure("REMOTE_NOT_CONFIGURED",503);
  let redis,claims,lease=null,started=null;
  try {
    // Authorize before reading any uploaded body or opening external socket.
    redis=await (opts.storeProvider||store)();
    if(await maintenanceEnabled(redis))return failure("SERVICE_UNAVAILABLE",503);
    // Keep the legacy exact-provider entrypoints unchanged. The unified
    // endpoint authorizes the session before it even reads the provider input.
    if(kind!=="cloud" && await serviceMaintenanceEnabled(redis,
        kind==="hc"?"files":kind==="ehi"?"httpInjector":"serverVpn"))
      return failure("SERVICE_MAINTENANCE",503);
    if(kind!=="cloud" && !await providerAllowed(
        kind==="hc"?"hc-cloud":kind==="ehi"?"ehi-cloud":kind==="mnr"?"mnr-tunnel-plus":"nur-tunnel"))
      return failure("REMOTE_NOT_CONFIGURED",503);
    claims=await requireSession(redis,request,settings());
    if (!claims) return failure("UNAUTHORIZED",401);
    if (claims.rateLimited) return failure("RATE_LIMITED",429);
    const body=await boundedBody(request,4096);
    if(kind==="cloud") {
      // Old APKs omit provider and are always HTTP Injector.
      const hasProvider=Object.hasOwn(body||{},"provider");
      if(!ownKeys(body,hasProvider?["provider","reference","consent"]:["reference","consent"]))
        return failure("INVALID_REQUEST",400);
      kind=hasProvider?body.provider:"ehi";
      if(!["ehi","hc"].includes(kind))return failure("INVALID_REQUEST",400);
      delete body.provider;
      if(kind==="ehi"&&!ehiConfigured())return failure("REMOTE_NOT_CONFIGURED",503);
      if(await serviceMaintenanceEnabled(redis,kind==="hc"?"files":"httpInjector"))
        return failure("SERVICE_MAINTENANCE",503);
      if(!await providerAllowed(kind==="hc"?"hc-cloud":"ehi-cloud"))
        return failure("REMOTE_NOT_CONFIGURED",503);
    }
    if(kind==="ehi" || kind==="mnr" || kind==="hc") {
      const combined=kind==="hc"&&body?.decode===true;
      if(!ownKeys(body,combined?["reference","consent","decode"]:["reference","consent"])||body.consent!==true)
        return failure("USER_CONSENT_REQUIRED",400);
      if(kind==="hc")parseHttpCustomReference(body.reference);
      else if(kind==="mnr")parseMnrReference(body.reference);else parseEhiReference(body.reference);
    }else if(kind==="nur") {
      if(!ownKeys(body,["consent"])||body.consent!==true)
        return failure("USER_CONSENT_REQUIRED",400);
    }else return failure("INVALID_REQUEST",400);
    if(kind==="nur"){
      const load=async()=>{
        const requestId=randomUUID();
        if(!await reserveSlot(redis,claims.jti,requestId))return failure("RATE_LIMITED",429);
        lease=requestId;started=performance.now();
        let count=0;
        const response=await loadNurCatalogResult(opts,n=>{count=n;});
        let errorCode="";
        if(!response.ok){try{errorCode=(await response.clone().json()).error?.code||"";}catch{}}
        try{await recordWorkerResult(redis,response.ok?"success":"failed",{
          kind:"catalog",bytes:count,errorCode,latencyMs:performance.now()-started,
          appVersion:request.headers.get("x-spdecode-app-version")});}catch{}
        return response;
      };
      return await sharedCatalog(redis,await catalogCacheConfig(redis,"nur-tunnel",load));
    }
    const requestId=randomUUID();
    if(!await reserveSlot(redis,claims.jti,requestId)) return failure("RATE_LIMITED",429);
    lease=requestId;
    started=performance.now();
    const vendor=opts.vendor || {};
    if(kind==="hc"){
      const bytes=Buffer.from(await importHttpCustomReference(body.reference,vendor));
      try {
        if(body.decode===true){
          // Fetch and decode in one authenticated operation. Only credential-gated
          // inputs return the original encrypted file for the existing RAM-only dialog.
          const response=await fetchWorker("file",{format:"hc",dataBase64:bytes.toString("base64")},settings(),opts);
          const code=response.ok?"":(await response.clone().json()).error?.code||"";
          try{await recordWorkerResult(redis,response.ok?"success":"failed",{kind:"file",format:"hc",bytes:bytes.length,
            errorCode:code,latencyMs:performance.now()-started,appVersion:request.headers.get("x-spdecode-app-version")});}catch{}
          if(!["PASSWORD_REQUIRED","HWID_REQUIRED","HWID_PASSWORD_REQUIRED"].includes(code))return response;
          return jsonReply({apiVersion:"v1",status:"credentials_required",kind:"encrypted_file",format:"hc",code,
            sourceBytes:bytes.length,dataBase64:bytes.toString("base64")},200);
        }
        // Older clients keep their original download-only contract.
        try{await recordWorkerResult(redis,"success",{kind:"file",format:"hc",bytes:bytes.length,
          latencyMs:performance.now()-started,appVersion:request.headers.get("x-spdecode-app-version")});}catch{}
        return jsonReply({apiVersion:"v1",status:"success",kind:"encrypted_file",format:"hc",
          sourceBytes:bytes.length,dataBase64:bytes.toString("base64")},200);
      }finally{bytes.fill(0);}
    }
    if(kind==="mnr"){
      const bytes=await importMnrReference(body.reference,vendor);
      const result=await fetchWorker("file",{format:"stp",dataBase64:bytes.toString("base64")},settings(),opts);
      let errorCode="";
      if(!result.ok){try{errorCode=(await result.clone().json()).error?.code||"";}catch{}}
      try{await recordWorkerResult(redis,result.ok?"success":"failed",{
        kind:"file",format:"stp",bytes:bytes.length,errorCode,latencyMs:performance.now()-started,
        appVersion:request.headers.get("x-spdecode-app-version"),
      });}catch{}
      return result;
    }
    if(kind==="ehi"){
      const ehi=await importEhiReference(body.reference,vendor);
      const result=await fetchWorker("file",{format:"ehi",dataBase64:ehi.toString("base64")},settings(),opts);
      let errorCode="";
      if(!result.ok){try{errorCode=(await result.clone().json()).error?.code||"";}catch{}}
      try{await recordWorkerResult(redis,result.ok?"success":"failed",{
        kind:"ehi",bytes:ehi.length,errorCode,latencyMs:performance.now()-started,
        appVersion:request.headers.get("x-spdecode-app-version"),
      });}catch{}
      return result;
    }
    return failure("INVALID_REQUEST",400);
  }catch(error) {
    // Count provider/download failures after authorization, without storing URLs.
    if(redis && lease){
      try{await recordWorkerResult(redis,"failed",{
        kind:kind==="nur"?"catalog":["mnr","hc"].includes(kind)?"file":"ehi",format:kind==="hc"?"hc":kind==="mnr"?"stp":undefined,bytes:0,
        errorCode:typeof error?.code==="string"?error.code:"SERVICE_UNAVAILABLE",
        latencyMs:started===null?null:performance.now()-started,
        appVersion:request.headers.get("x-spdecode-app-version"),
      });}catch{}
    }
    if (isExternalImportError(error)) return failure(error.code,error.status);
    if (error?.code==="INVALID_REQUEST")return failure("INVALID_REQUEST",400);
    if (error?.code==="INPUT_TOO_LARGE")return failure("INPUT_TOO_LARGE",413);
    return failure("SERVICE_UNAVAILABLE",503);
  }finally{
    if(redis&&lease)try{await releaseSlot(redis,claims.jti,lease);}catch{}
  }
}

export async function loadNurCatalogResult(opts={},onBytes=()=>{}){
  const catalog=await downloadNur(opts.vendor||{});
  onBytes(catalog.length);
  return fetchWorker("catalog",{dataBase64:catalog.toString("base64")},settings(),opts);
}
