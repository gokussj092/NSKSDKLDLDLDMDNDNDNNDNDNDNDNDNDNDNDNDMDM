/** C3.5 session-gated remote imports; only the broker knows external URLs. */
import {jsonReply} from "./responses.mjs";
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
      if(!ownKeys(body,["reference","consent"])||body.consent!==true)
        return failure("USER_CONSENT_REQUIRED",400);
      if(kind==="hc")parseHttpCustomReference(body.reference);
      else if(kind==="mnr")parseMnrReference(body.reference);else parseEhiReference(body.reference);
    }else if(kind==="nur") {
      if(!ownKeys(body,["consent"])||body.consent!==true)
        return failure("USER_CONSENT_REQUIRED",400);
    }else return failure("INVALID_REQUEST",400);
    const requestId=randomUUID();
    if(!await reserveSlot(redis,claims.jti,requestId)) return failure("RATE_LIMITED",429);
    lease=requestId;
    started=performance.now();
    const vendor=opts.vendor || {};
    if(kind==="hc"){
      // Return encrypted bytes once. The Android file path holds them only in
      // RAM for password/HWID interaction; no server cache, retry or plaintext.
      const bytes=await importHttpCustomReference(body.reference,vendor);
      try{await recordWorkerResult(redis,"success",{kind:"file",format:"hc",bytes:bytes.length,
        latencyMs:performance.now()-started,appVersion:request.headers.get("x-spdecode-app-version")});}catch{}
      return jsonReply({apiVersion:"v1",status:"success",kind:"encrypted_file",format:"hc",
        sourceBytes:bytes.length,dataBase64:bytes.toString("base64")},200);
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
    const catalog=await downloadNur(vendor);
    const result=await fetchWorker("catalog",{dataBase64:catalog.toString("base64")},settings(),opts);
    let errorCode="";
    if(!result.ok){try{errorCode=(await result.clone().json()).error?.code||"";}catch{}}
    try{await recordWorkerResult(redis,result.ok?"success":"failed",{
      kind:"catalog",bytes:catalog.length,errorCode,latencyMs:performance.now()-started,
      appVersion:request.headers.get("x-spdecode-app-version"),
    });}catch{}
    return result;
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
