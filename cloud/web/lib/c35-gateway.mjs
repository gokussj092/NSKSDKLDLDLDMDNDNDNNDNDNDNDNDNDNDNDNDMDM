/** C3.5 session-gated remote imports; only the broker knows external URLs. */
import {jsonReply} from "./responses.mjs";
import {sharedCatalog} from "./server-vpn-result-cache.mjs";
import {catalogCacheConfig} from "./server-vpn-cache-controls.mjs";
import { randomUUID } from "node:crypto";
import {providerAllowed} from "./c12-provider-controls.mjs";
import { settings } from "./c3-config.mjs";
import { store, reserveSlot, releaseSlot } from "./c3-store.mjs";
import { requireSession } from "./c3-session.mjs";
import {takeStreakAccountToken,withDecodeStreak} from "./commerce/decode-account-streak.mjs";
import {takePlayTesterFields} from "./commerce/play-testers.mjs";
import { enabled, notEnabled, failure, boundedBody, fetchWorker } from "./c3-gateway.mjs";
import { maintenanceEnabled, serviceMaintenanceEnabled, recordWorkerResult } from "./c6-ops-store.mjs";
import {
  isExternalImportError, parseEhiReference, ehiConfigured, nurConfigured,
  importEhiReference, downloadNur,
  parseMnrReference, importMnrReference, parseHttpCustomReference, importHttpCustomReference,
  isHttpCustomReference, parseHexCustomReference, importHexCustomReference,
  hexCustomConfigured, isHexCustomReference, isMnrReference,
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
    const streakToken=takeStreakAccountToken(body,claims);
    const testerFields=takePlayTesterFields(body,claims);
    if(kind==="cloud") {
      // Old APKs omit provider and are always HTTP Injector.
      const hasProvider=Object.hasOwn(body||{},"provider");
      const hasDecode=Object.hasOwn(body||{},"decode");
      if(!ownKeys(body,hasProvider?
          (hasDecode?["provider","reference","consent","decode"]:["provider","reference","consent"]):
          (hasDecode?["reference","consent","decode"]:["reference","consent"])))
        return failure("INVALID_REQUEST",400);
      // Never trust the app's provider field blindly: detect the provider
      // from the reference itself. A present provider is used only when it
      // matches the reference; otherwise the detected provider wins.
      // Order mirrors the app (hc, hexcustom, mnr, ehi): mnr is checked
      // before ehi because a bare 10-char id also fits the injector key
      // alphabet, while mnrtunneludp:// never parses as ehi.
      const detected=isHexCustomReference(body.reference)?"hexcustom"
        :isMnrReference(body.reference)?"mnr"
        :isHttpCustomReference(body.reference)?"hc"
        :(()=>{try{parseEhiReference(body.reference);return "ehi";}catch{return null;}})();
      if(hasProvider && !["ehi","hc","hexcustom","mnr"].includes(body.provider))
        return failure("INVALID_REQUEST",400);
      kind=detected||(hasProvider?body.provider:"ehi");
      delete body.provider;
      if(kind==="ehi"&&!ehiConfigured())return failure("REMOTE_NOT_CONFIGURED",503);
      if(kind==="hexcustom"&&!hexCustomConfigured())return failure("REMOTE_NOT_CONFIGURED",503);
      if(await serviceMaintenanceEnabled(redis,
        kind==="hc"||kind==="hexcustom"?"files":kind==="mnr"?"serverVpn":"httpInjector"))
        return failure("SERVICE_MAINTENANCE",503);
      if(!await providerAllowed(kind==="hc"?"hc-cloud":kind==="hexcustom"?"hexcustom-cloud":kind==="mnr"?"mnr-tunnel-plus":"ehi-cloud"))
        return failure("REMOTE_NOT_CONFIGURED",503);
    }
    if(kind==="ehi" || kind==="mnr" || kind==="hc" || kind==="hexcustom") {
      const combined=(kind==="hc"||kind==="hexcustom")&&body?.decode===true;
      if(!ownKeys(body,combined?["reference","consent","decode"]:["reference","consent"])||body.consent!==true)
        return failure("USER_CONSENT_REQUIRED",400);
      if(kind==="hc")parseHttpCustomReference(body.reference);
      else if(kind==="mnr")parseMnrReference(body.reference);
      else if(kind==="hexcustom")parseHexCustomReference(body.reference);
      else parseEhiReference(body.reference);
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
          if(!["PASSWORD_REQUIRED","HWID_REQUIRED","HWID_PASSWORD_REQUIRED"].includes(code))
            return await withDecodeStreak(response,claims,streakToken,{...opts,tester:testerFields});
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
    if(kind==="hexcustom"){
      // Both Hex Tunnel's legacy envelope and Hex Custom HXS3 use .hexcm.
      // Dispatch only by authenticated file bytes; the worker alone decides
      // whether the HXS3 password is required. Never fetch the same cloud key
      // again after asking for a password (one-use links may expire).
      const bytes=Buffer.from(await importHexCustomReference(body.reference,vendor));
      try {
        const result=await fetchWorker("file",{format:"hexcm",dataBase64:bytes.toString("base64")},settings(),opts);
        let errorCode="";
        if(!result.ok){try{errorCode=(await result.clone().json()).error?.code||"";}catch{}}
        try{await recordWorkerResult(redis,result.ok?"success":"failed",{
          kind:"file",format:"hexcm",bytes:bytes.length,errorCode,latencyMs:performance.now()-started,
          appVersion:request.headers.get("x-spdecode-app-version"),
        });}catch{}
        if(body.decode===true && errorCode==="PASSWORD_REQUIRED" &&
           bytes.length>=74 && bytes.subarray(0,4).equals(Buffer.from("HXS3")) &&
           bytes[4]===3 && (bytes[5]&1)===1) {
          return jsonReply({apiVersion:"v1",status:"credentials_required",
            kind:"encrypted_file",format:"hexcm",code:"PASSWORD_REQUIRED",
            sourceBytes:bytes.length,dataBase64:bytes.toString("base64")},200);
        }
        return await withDecodeStreak(result,claims,streakToken,{...opts,tester:testerFields});
      } finally { bytes.fill(0); }
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
      return await withDecodeStreak(result,claims,streakToken,{...opts,tester:testerFields});
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
      return await withDecodeStreak(result,claims,streakToken,{...opts,tester:testerFields});
    }
    return failure("INVALID_REQUEST",400);
  }catch(error) {
    // Count provider/download failures after authorization, without storing URLs.
    if(redis && lease){
      try{await recordWorkerResult(redis,"failed",{
        kind:kind==="nur"?"catalog":["mnr","hc","hexcustom"].includes(kind)?"file":"ehi",format:kind==="hc"?"hc":kind==="mnr"?"stp":kind==="hexcustom"?"hexcm":undefined,bytes:0,
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
