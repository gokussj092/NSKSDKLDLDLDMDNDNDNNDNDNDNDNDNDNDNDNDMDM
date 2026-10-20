/** C3.5 session-gated remote imports; only the broker knows external URLs. */
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
} from "./c35-provider.mjs";
const ownKeys=(value,expected)=> value && typeof value==="object" && !Array.isArray(value)
  && Object.keys(value).length===expected.length && expected.every(key=>Object.hasOwn(value,key));

export async function externalImportRequest(request,kind,opts={}) {
  if (!enabled()) return notEnabled();
  if (kind==="ehi" && !ehiConfigured() || kind==="nur" && !nurConfigured())
    return failure("REMOTE_NOT_CONFIGURED",503);
  let redis,claims,lease=null;
  try {
    // Authorize before reading any uploaded body or opening external socket.
    redis=await (opts.storeProvider||store)();
    if(await maintenanceEnabled(redis))return failure("SERVICE_UNAVAILABLE",503);
    if(await serviceMaintenanceEnabled(redis,kind==="ehi"?"httpInjector":"serverVpn"))
      return failure("SERVICE_MAINTENANCE",503);
    if(!await providerAllowed(kind==="ehi"?"ehi-cloud":"nur-tunnel"))
      return failure("REMOTE_NOT_CONFIGURED",503);
    claims=await requireSession(redis,request,settings());
    if (!claims) return failure("UNAUTHORIZED",401);
    if (claims.rateLimited) return failure("RATE_LIMITED",429);
    const body=await boundedBody(request,4096);
    if(kind==="ehi") {
      if(!ownKeys(body,["reference","consent"])||body.consent!==true)
        return failure("USER_CONSENT_REQUIRED",400);
      parseEhiReference(body.reference);
    }else if(kind==="nur") {
      if(!ownKeys(body,["consent"])||body.consent!==true)
        return failure("USER_CONSENT_REQUIRED",400);
    }else return failure("INVALID_REQUEST",400);
    const requestId=randomUUID();
    if(!await reserveSlot(redis,claims.jti,requestId)) return failure("RATE_LIMITED",429);
    lease=requestId;
    const vendor=opts.vendor || {};
    if(kind==="ehi"){
      const ehi=await importEhiReference(body.reference,vendor);
      const result=await fetchWorker("file",{format:"ehi",dataBase64:ehi.toString("base64")},settings(),opts);
      let errorCode="";
      if(!result.ok){try{errorCode=(await result.clone().json()).error?.code||"";}catch{}}
      try{await recordWorkerResult(redis,result.ok?"success":"failed",{
        kind:"ehi",bytes:ehi.length,errorCode,
      });}catch{}
      return result;
    }
    const catalog=await downloadNur(vendor);
    const result=await fetchWorker("catalog",{dataBase64:catalog.toString("base64")},settings(),opts);
    let errorCode="";
    if(!result.ok){try{errorCode=(await result.clone().json()).error?.code||"";}catch{}}
    try{await recordWorkerResult(redis,result.ok?"success":"failed",{
      kind:"catalog",bytes:catalog.length,errorCode,
    });}catch{}
    return result;
  }catch(error) {
    // Count provider/download failures after authorization, without storing URLs.
    if(redis && lease){
      try{await recordWorkerResult(redis,"failed",{
        kind:kind==="nur"?"catalog":"ehi",bytes:0,
        errorCode:typeof error?.code==="string"?error.code:"SERVICE_UNAVAILABLE",
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
