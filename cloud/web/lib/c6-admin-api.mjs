import { adminSettings, adminLogin, authenticateAdmin, validMutation,
  cookieHeader, deleteCookie, revokeAdmin } from "./c6-admin-auth.mjs";
import { opsStore, maintenanceEnabled, setMaintenance, aggregateMetrics, usageReport,
  SERVICE_IDS,serviceMaintenanceStates,setServiceMaintenance,resetErrorBaselines } from "./c6-ops-store.mjs";
import {throttle} from "./c3-store.mjs";
import { settings } from "./c3-config.mjs";
import {admissionPolicy,setAdmissionPolicy} from "./c11-play-admission.mjs";
import {v1ProtectionStatus,v1PolicyStatus,changeV1Policy,changeV1Retirement} from "./v1-protection-policy.mjs";
import {v2PolicyStatus,changeV2Availability} from "./v2-availability-policy.mjs";
import {v2PlayPolicyStatus,changeV2PlayPolicy,changeV2PlaySettings} from "./v2-play-policy.mjs";
import {v2DevicePolicyStatus,changeV2DevicePolicy,PATCH_MONTHS,TEST_HOURS} from "./v2-device-admission-policy.mjs";
import {admissionDiagnostics} from "./v2-admission-diagnostics.mjs";
import {v2Settings} from "./v2-config.mjs";
import {providerOverview,updateProvider,updateMethodState,updateDisplayVersion,PUBLIC_PROVIDER_IDS} from "./c12-provider-controls.mjs";
import {currentSnapshot} from "./catalog-chunk-api.mjs";
import {chunksEnabled} from "./catalog-snapshots.mjs";
import { ehiConfigured,nurConfigured } from "./c35-provider.mjs";
import { jsonReply } from "./responses.mjs";
import {readOpsReport,hostHealth} from "./c14-ops-observability.mjs";
import {purgeRetainedErrors,clearOperationalAlerts,setAlertPause} from "./c15-admin-operations.mjs";

const error=(code,status)=>jsonReply({status:"error",error:{code}},status);
const api=(body,status=200,headers={})=>jsonReply({status:"ok",...body},status,headers);
const own=(o,keys)=>o && typeof o==="object"&&!Array.isArray(o) &&
  Object.keys(o).length===keys.length && keys.every(k=>Object.hasOwn(o,k));
async function parseSmallJson(request,max=1024) {
  const indicated=request.headers.get("content-length");
  if(indicated && (!/^\d+$/.test(indicated)||Number(indicated)>max))return null;
  if(!request.body)return null;
  const chunks=[],reader=request.body.getReader();let size=0;
  try {
    for(;;){
      const {done,value}=await reader.read();if(done)break;
      size+=value.byteLength;if(size>max)return null;
      chunks.push(value);
    }
    return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(Buffer.concat(chunks)));
  }catch{return null;}finally{reader.releaseLock();}
}
export async function loginRequest(request,options={}) {
  const cfg=adminSettings();
  if(!cfg.enabled)return error("ADMIN_DISABLED",503);
  if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
  try {
    const body=await parseSmallJson(request,2048);
    if(!own(body,["username","password"]) || typeof body.username!=="string" || typeof body.password!=="string")
      return error("INVALID_REQUEST",400);
    const redis=await (options.storeProvider||opsStore)();
    const result=await adminLogin(redis,request,body.username,body.password,cfg);
    if(result.error)return error(result.error,result.status);
    return api({expiresIn:result.expiresIn},200,{
      "Set-Cookie":cookieHeader(result.token),
    });
  }catch{return error("SERVICE_UNAVAILABLE",503);}
}
export async function statusRequest(request,options={}) {
  if(!adminSettings().enabled)return error("ADMIN_DISABLED",503);
  try{
    const redis=await (options.storeProvider||opsStore)();
    if(!await authenticateAdmin(redis,request))return error("UNAUTHORIZED",401);
    const [maintenance,legacyMetrics,ping,serviceMaintenance,playAdmission,providerControls,v1Protection,v1Policy,v2PolicyState,v2PlayPolicy,v2DevicePolicy]=await Promise.all([
      maintenanceEnabled(redis),aggregateMetrics(redis),redis.ping(),serviceMaintenanceStates(redis),
      admissionPolicy(redis),providerOverview(),v1ProtectionStatus(),v1PolicyStatus(),v2PolicyStatus(),v2PlayPolicyStatus(),v2DevicePolicyStatus(),
    ]);
    // Show reset-adjusted current errors when detailed aggregate hashes exist.
    // The legacy counter remains a fallback for prior deployments/tests.
    const current=typeof redis.hGetAll==="function"?await usageReport(redis,1):null;
    const metrics=current?{window:"utc_today",successfulDecodes:legacyMetrics.successfulDecodes,
      failedDecodes:current.failedDecodes,warnings:current.warnings}:legacyMetrics;
    const cfg=settings();
    // Worker origin cannot be user-controlled.
    let workerReady=false;
    if(process.env.WORKER_INTERNAL_URL==="http://decoder-worker:8787"){
      try{
        const response=await (options.fetchImpl||fetch)(
          "http://decoder-worker:8787/ready",{
            signal:AbortSignal.timeout(3500),cache:"no-store",redirect:"error",
          });
        workerReady=response.ok;
      }catch{}
    }
    // Aggregate-only attestation diagnostics, accessible only after admin login.
    // Use the private service DNS and its server-only token. Never expose keys,
    // certificates, device identifiers or individual network addresses.
    let attestationDiagnostics=null;
    if(process.env.CLOUD_KEY_ATTESTATION_URL==="http://key-attestation:8788/verify" &&
       (process.env.CLOUD_KEY_ATTESTATION_TOKEN||"").length>=32){
      try{
        const report=await (options.fetchImpl||fetch)("http://key-attestation:8788/stats",{
          method:"GET",cache:"no-store",redirect:"error",signal:AbortSignal.timeout(2500),
          headers:{"X-SP-Attestation-Token":process.env.CLOUD_KEY_ATTESTATION_TOKEN}});
        if(report.ok){
          const summary=await parseSmallJson(report,16384);
          const known=["OS_PATCH_OUTDATED","VENDOR_BOOT_PATCH_OUTDATED","OS_PATCH_MISSING",
            "VERIFIED_BOOT","CHALLENGE","CERT_PATH","CHAIN_FORMAT","CERT_EXTENSION",
            "CERT_CONSTRAINT","CERT_INVALID","SECURITY_LEVEL","KEY_MISMATCH",
            "APP_ID_MISSING","APP_ID_MISMATCH","POLICY_INVALID","VERIFICATION_EXCEPTION"];
          if(Number.isSafeInteger(summary.uptimeSeconds) && summary.uptimeSeconds>=0 &&
             summary.rejections && typeof summary.rejections==="object" && !Array.isArray(summary.rejections)){
            const counts={};
            for(const key of known){
              const n=summary.rejections[key];
              if(Number.isSafeInteger(n)&&n>=0)counts[key]=n;
            }
            const countMap=value=>Object.fromEntries(Object.entries(value||{}).filter(([key,n])=>
              /^[A-Z][A-Z0-9_]{1,63}$/.test(key)&&Number.isSafeInteger(n)&&n>=0));
            const accepted=Number.isSafeInteger(summary.accepted)&&summary.accepted>=0?summary.accepted:null;
            const rejected=Object.values(counts).reduce((a,b)=>a+b,0);
            const total=accepted===null?null:accepted+rejected;
            attestationDiagnostics={uptimeSeconds:summary.uptimeSeconds,rejections:counts,
              accepted,rejected,total,rejectionPercent:total?Math.round(10000*rejected/total)/100:null,
              unit:"verification_attempts",rootDetection:"unknown",
              observations:countMap(summary.observations),certificatePathReasons:countMap(summary.certificatePathReasons),
              updatedAt:new Date().toISOString()};
          }
        }
      }catch{}
    }
    const v2Runtime=v2Settings(process.env,{playIntegrityRequired:v2PlayPolicy.integrityRequired,playPolicy:v2PlayPolicy});
    return api({
      services:{apiConfigured:cfg.configured,redisConnected:ping==="PONG",
        workerReady,ehiImportConfigured:ehiConfigured(),
        nurCatalogImportConfigured:nurConfigured()},
      maintenance,serviceMaintenance,playAdmission,providerControls,v1Protection,v1Policy,
      v2Policy:{...v2PolicyState,configured:v2Settings(process.env,{playIntegrityRequired:v2PlayPolicy.integrityRequired,playPolicy:v2PlayPolicy}).configured},
      v2PlayPolicy,v2DevicePolicy,attestationDiagnostics,
      v2Runtime:{googleConfigured:Boolean(v2Runtime.account),hardwareRequired:v2Runtime.requireHardware,
       actionRequired:v2Runtime.requireAction,raspMode:v2Runtime.rasp.mode,raspAccessMode:v2Runtime.rasp.accessMode},
      admissionDiagnostics:await admissionDiagnostics(redis),
      maintenanceLocked:process.env.CLOUD_FORCE_MAINTENANCE==="true",metrics,
      observation:"Counters are aggregate-only; no user content or keys are logged.",
    });
  }catch{return error("SERVICE_UNAVAILABLE",503);}
}
export async function maintenanceRequest(request,options={}) {
  const cfg=adminSettings();
  if(!cfg.enabled)return error("ADMIN_DISABLED",503);
  if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
  try{
    const redis=await (options.storeProvider||opsStore)();
    if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
    const body=await parseSmallJson(request,256);
    const general=own(body,["enabled"]),specific=own(body,["enabled","service"]);
    if((!general&&!specific)||typeof body.enabled!=="boolean"||
      (specific&&!SERVICE_IDS.includes(body.service)))return error("INVALID_REQUEST",400);
    if(general)await setMaintenance(redis,body.enabled);
    else await setServiceMaintenance(redis,body.service,body.enabled);
    return api({maintenance:await maintenanceEnabled(redis),
      serviceMaintenance:await serviceMaintenanceStates(redis)});
  }catch(cause){
    if(cause?.message==="MAINTENANCE_LOCKED")return error("MAINTENANCE_LOCKED",409);
    return error("SERVICE_UNAVAILABLE",503);
  }
}
/** Closed administrative controls; availability has priority over protection. */
export const v1ProtectionRequest=(request,options={})=>v1PolicyRequest(request,'advancedProtection',options);
export const v1AvailabilityRequest=(request,options={})=>v1PolicyRequest(request,'apiEnabled',options);
async function v1PolicyRequest(request,field,options) {
 const cfg=adminSettings();if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try {
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  if(!await throttle(redis,"spc6:v1-policy:rate",10,60))return error("RATE_LIMITED",429);
  const body=await parseSmallJson(request,256);
  const confirmation=(field==='apiEnabled'?'API_V1_':'V1_PROTECCION_')+(body?.enabled?'ACTIVAR':'DESACTIVAR');
  if(!own(body,["enabled","confirmation","expectedRevision"])||typeof body.enabled!=="boolean"||body.confirmation!==confirmation||
    !Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0)return error("INVALID_REQUEST",400);
  const v1Policy=await changeV1Policy(field,body.enabled,body.expectedRevision,options.policyOptions);
  try {
   await redis.lPush("spc6:v1-protection:audit",JSON.stringify({at:Date.now(),field,enabled:body.enabled,revision:v1Policy.revision}));
   await redis.lTrim("spc6:v1-protection:audit",0,99);await redis.expire("spc6:v1-protection:audit",8*86400);
  }catch{}
  return api({v1Policy},200,{"Cache-Control":"private, no-store"});
 }catch(e) {
  if(['V1_POLICY_CONFLICT','STORE_BUSY'].includes(e.message))return error(e.message,409);
  return error("SERVICE_UNAVAILABLE",503);
 }
}

/** Admin-only 48-hour cutoff for API V1, independent of V2 policy. */
export async function v1RetirementRequest(request,options={}) {
 const cfg=adminSettings();if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  if(!await throttle(redis,"spc6:v1-policy:rate",10,60))return error("RATE_LIMITED",429);
  const body=await parseSmallJson(request,256);
  if(!own(body,["action","confirmation","expectedRevision"])||
    !["schedule","cancel"].includes(body.action)||
    body.confirmation!==(body.action==="schedule"?"API_V1_PROGRAMAR_48H":"API_V1_CANCELAR_PROGRAMACION")||
    !Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0)
    return error("INVALID_REQUEST",400);
  const v1Policy=await changeV1Retirement(body.action,body.expectedRevision,options.policyOptions);
  try{
   await redis.lPush("spc6:v1-protection:audit",JSON.stringify({
    at:Date.now(),field:"retirement",action:body.action,retireAt:v1Policy.retireAt??null,
    revision:v1Policy.revision}));
   await redis.lTrim("spc6:v1-protection:audit",0,99);
   await redis.expire("spc6:v1-protection:audit",8*86400);
  }catch{}
  return api({v1Policy},200,{"Cache-Control":"private, no-store"});
 }catch(e){
  if(["V1_POLICY_CONFLICT","STORE_BUSY"].includes(e?.message))return error(e.message,409);
  if(e?.message==="V1_POLICY_INVALID")return error(e.message,400);
  return error("SERVICE_UNAVAILABLE",503);
 }
}

/** Authenticated independent V2 availability control; never relaxes V2 integrity. */
export async function v2AvailabilityRequest(request,options={}) {
 const cfg=adminSettings();if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try {
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  if(!await throttle(redis,"spc6:v2-policy:rate",10,60))return error("RATE_LIMITED",429);
  const body=await parseSmallJson(request,256);
  if(!own(body,["enabled","confirmation","expectedRevision"])||
     typeof body.enabled!=="boolean"||
     body.confirmation!==(body.enabled?"API_V2_ACTIVAR":"API_V2_DESACTIVAR")||
     !Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0)
    return error("INVALID_REQUEST",400);
  const v2Policy=await changeV2Availability(body.enabled,body.expectedRevision,options.policyOptions);
  try {
   await redis.lPush("spc6:v2-availability:audit",JSON.stringify({
     at:Date.now(),enabled:body.enabled,revision:v2Policy.revision}));
   await redis.lTrim("spc6:v2-availability:audit",0,99);
   await redis.expire("spc6:v2-availability:audit",8*86400);
  }catch{}
  return api({v2Policy:{...v2Policy,configured:v2Settings().configured}},200,{"Cache-Control":"private, no-store"});
 }catch(e){
  if(["V2_POLICY_CONFLICT","STORE_BUSY"].includes(e?.message))return error(e.message,409);
  return error("SERVICE_UNAVAILABLE",503);
 }
}

/** Session-authenticated QA controls; core attestation chain and APK signatures remain mandatory. */
export async function v2DeviceAdmissionRequest(request,options={}){
 const cfg=adminSettings();if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  if(!await throttle(redis,"spc6:v2-device:rate",30,60))return error("RATE_LIMITED",429);
  const body=await parseSmallJson(request,512);
  if(!own(body,["patchMonths","enforcePatch","enforceBoot","durationHours","expectedRevision","confirmation"])||
   !PATCH_MONTHS.includes(body.patchMonths)||typeof body.enforcePatch!=="boolean"||
   typeof body.enforceBoot!=="boolean"||!TEST_HOURS.includes(body.durationHours)||
   !Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0||
   body.confirmation!=="V2_DISPOSITIVOS_CONFIGURAR")
   return error("INVALID_REQUEST",400);
  const policy=await changeV2DevicePolicy(body,options.policyOptions);
  try {
   await redis.lPush("spc6:v2-device-policy:audit",JSON.stringify({
    at:Date.now(),patchMonths:policy.patchMonths,enforcePatch:policy.enforcePatch,
    enforceBoot:policy.enforceBoot,expiresAt:policy.expiresAt,revision:policy.revision}));
   await redis.lTrim("spc6:v2-device-policy:audit",0,99);
   await redis.expire("spc6:v2-device-policy:audit",8*86400);
  }catch{}
  return api({v2DevicePolicy:policy},200,{"Cache-Control":"private, no-store"});
 }catch(e){
  if(["V2_DEVICE_POLICY_CONFLICT","STORE_BUSY"].includes(e?.message))return error(e.message,409);
  if(e?.message==="V2_DEVICE_POLICY_INVALID")return error(e.message,400);
  return error("SERVICE_UNAVAILABLE",503);
 }
}

/** Authenticated permanent Play settings with optimistic concurrency and audit. */
export async function v2PlayIntegrityRequest(request,options={}){
 const cfg=adminSettings();if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  if(!await throttle(redis,"spc6:v2-play:rate",30,60))return error("RATE_LIMITED",429);
  const body=await parseSmallJson(request,2048);
  const modern=own(body,["settings","confirmation","expectedRevision"]);
  const legacy=own(body,["integrityRequired","confirmation","expectedRevision"]);
  if((!modern&&!legacy)||!Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0||
     (modern?body.confirmation!=="V2_PLAY_CONFIGURAR":
       typeof body.integrityRequired!=="boolean"||body.confirmation!==
         (body.integrityRequired?"V2_PLAY_ACTIVAR":"V2_PLAY_BETA_15_DIAS")))return error("INVALID_REQUEST",400);
  const v2PlayPolicy=modern?
    await changeV2PlaySettings(body.settings,body.expectedRevision,options.policyOptions):
    await changeV2PlayPolicy(body.integrityRequired,body.expectedRevision,options.policyOptions);
  try{
   await redis.lPush("spc6:v2-play:audit",JSON.stringify({
    at:Date.now(),mode:v2PlayPolicy.mode,deviceIntegrity:v2PlayPolicy.deviceIntegrity,
    requireLicensed:v2PlayPolicy.requireLicensed,requireAction:v2PlayPolicy.requireAction,revision:v2PlayPolicy.revision}));
   await redis.lTrim("spc6:v2-play:audit",0,99);
   await redis.expire("spc6:v2-play:audit",8*86400);
  }catch{}
  return api({v2PlayPolicy},200,{"Cache-Control":"private, no-store"});
 }catch(e){
  if(["V2_PLAY_POLICY_CONFLICT","STORE_BUSY"].includes(e?.message))return error(e.message,409);
  if(e?.message==="V2_PLAY_POLICY_INVALID")return error(e.message,400);
  return error("SERVICE_UNAVAILABLE",503);
 }
}

export async function logoutRequest(request,options={}) {
  const cfg=adminSettings();
  if(!cfg.enabled)return error("ADMIN_DISABLED",503);
  if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
  try {
    const redis=await (options.storeProvider||opsStore)();
    const claims=await authenticateAdmin(redis,request,cfg);
    if(!claims)return error("UNAUTHORIZED",401);
    await revokeAdmin(redis,claims);
    return api({loggedOut:true},200,{"Set-Cookie":deleteCookie()});
  }catch{return error("SERVICE_UNAVAILABLE",503);}
}

/** Confidential operator-only, anonymous metrics. Never expose on /api/site. */
export async function reportRequest(request,options={}) {
  if(!adminSettings().enabled)return error("ADMIN_DISABLED",503);
  try {
    const redis=await (options.storeProvider||opsStore)();
    if(!await authenticateAdmin(redis,request))return error("UNAUTHORIZED",401);
    const url=new URL(request.url);
    const keys=[...url.searchParams.keys()];
    if(keys.some(k=>k!=="days") || keys.length>1)return error("INVALID_REQUEST",400);
    const days=url.searchParams.get("days")||"7";
    if(!["1","7"].includes(days))return error("INVALID_REQUEST",400);
    return api({report:await usageReport(redis,Number(days))},200,
      {"Cache-Control":"private, no-store, max-age=0"});
  }catch{return error("SERVICE_UNAVAILABLE",503);}
}

/** CSRF-protected, authenticated, short-lived beta admission policy. */
export async function playAdmissionRequest(request,options={}){
 const cfg=adminSettings();
 if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  const body=await parseSmallJson(request,128);
  if(!own(body,["integrityRequired"])||typeof body.integrityRequired!=="boolean")
   return error("INVALID_REQUEST",400);
  return api({playAdmission:await setAdmissionPolicy(redis,body.integrityRequired)},200,
   {"Cache-Control":"private, no-store"});
 }catch(e){
  if(e?.message==="BETA_LOCKED")return error("BETA_LOCKED",409);
  return error("SERVICE_UNAVAILABLE",503);
 }
}

/** Fixed-provider availability: CSRF protected, authenticated, never writes credentials. */
export async function catalogEditionRequest(request,options={}){
 const cfg=adminSettings();if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  const body=await parseSmallJson(request,128);
  if(!own(body,["displayVersion"])||!Number.isSafeInteger(body.displayVersion)||body.displayVersion<1)return error("INVALID_REQUEST",400);
  const providerControls=await updateDisplayVersion(body.displayVersion,process.env,{prepare:chunksEnabled()?async next=>currentSnapshot(request,{...await providerOverview(),catalogVersion:next.version,displayVersion:String(next.displayVersion)}):null});
  return api({providerControls},200,{"Cache-Control":"private, no-store"});
 }catch(cause){if(["DISPLAY_VERSION_ROLLBACK","MAINTENANCE_LOCKED","PROVIDER_BUSY"].includes(cause?.message))return error(cause.message,409);return error("SERVICE_UNAVAILABLE",503);}
}

export async function providerControlRequest(request,options={}){
 const cfg=adminSettings();
 if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  const body=await parseSmallJson(request,256);
  if(!own(body,["id","enabled"]) || typeof body.enabled!=="boolean" ||
     typeof body.id!=="string" || !PUBLIC_PROVIDER_IDS.includes(body.id))
    return error("INVALID_REQUEST",400);
  const providerControls=await updateProvider(body.id,body.enabled);
  return api({providerControls},200,{"Cache-Control":"private, no-store"});
 }catch(cause){
  if(cause?.message==="PROVIDER_NOT_CONFIGURED")return error("PROVIDER_NOT_CONFIGURED",409);
  if(cause?.message==="MAINTENANCE_LOCKED")return error("MAINTENANCE_LOCKED",409);
  if(cause?.message==="PROVIDER_BUSY")return error("PROVIDER_BUSY",409);
  return error("SERVICE_UNAVAILABLE",503);
 }
}

/** Authenticated method metadata: revision increments and explicit maintenance only.
 * Identifiers are validated against the fixed Server VPN roster by the state store. */
export async function providerMethodRequest(request,options={}){
  const cfg=adminSettings();
  if(!cfg.enabled)return error("ADMIN_DISABLED",503);
  if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
  try{
    const redis=await (options.storeProvider||opsStore)();
    if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
    const body=await parseSmallJson(request,256);
    if(!body || typeof body!=="object" || Array.isArray(body) ||
       typeof body.id!=="string" ||
       !["revision","maintenance"].includes(body.operation) ||
       Object.keys(body).some(k=>!["id","operation","maintenance"].includes(k)) ||
       (body.operation==="maintenance" && typeof body.maintenance!=="boolean") ||
       (body.operation==="revision" && Object.hasOwn(body,"maintenance")))
      return error("INVALID_REQUEST",400);
    const providerControls=await updateMethodState(body.id,body.operation,body.maintenance);
    return api({providerControls},200,{"Cache-Control":"private, no-store"});
  }catch(cause){
    if(cause?.message==="INVALID_METHOD_STATE")return error("INVALID_REQUEST",400);
    if(["MAINTENANCE_LOCKED","PROVIDER_BUSY","METHOD_REVISION_EXHAUSTED"].includes(cause?.message))
      return error(cause.message,409);
    return error("SERVICE_UNAVAILABLE",503);
  }
}

/** Reset per-format error baselines only; success/warnings/usage history remain untouched. */
export async function resetErrorsRequest(request,options={}){
 const cfg=adminSettings();
 if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  const body=await parseSmallJson(request,192);
  if(!own(body,["scope"])&&!own(body,["scope","format"]))return error("INVALID_REQUEST",400);
  if(body.scope!=="all"&&body.scope!=="format")return error("INVALID_REQUEST",400);
  if(body.scope==="all"&&Object.hasOwn(body,"format"))return error("INVALID_REQUEST",400);
  if(body.scope==="format"&&(typeof body.format!=="string"||
      !/^[a-z0-9ɴ][a-z0-9ɴ._-]{0,52}$/.test(body.format)))return error("INVALID_REQUEST",400);
  const reset=await resetErrorBaselines(redis,body);
  return api({reset},200,{"Cache-Control":"private, no-store"});
 }catch(cause){
  if(["INVALID_RESET_SCOPE","INVALID_FORMAT","RESET_TOO_MANY_FORMATS"].includes(cause?.message))
    return error(cause?.message,400);
  return error("SERVICE_UNAVAILABLE",503);
 }
}

/** Private operator-only observability; no endpoint, token, or payload leaves Redis. */
export async function observabilityRequest(request,options={}){
 if(!adminSettings().enabled)return error("ADMIN_DISABLED",503);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request))return error("UNAUTHORIZED",401);
  const url=new URL(request.url),keys=[...url.searchParams.keys()];
  if(keys.length>1||keys.some(k=>k!=="days"))return error("INVALID_REQUEST",400);
  const days=url.searchParams.get("days")||"7";
  if(!["1","7"].includes(days))return error("INVALID_REQUEST",400);
  const [report,observability,health]=await Promise.all([
   usageReport(redis,Number(days)),
   readOpsReport(redis,Number(days)),
   hostHealth(redis,{fetchImpl:options.fetchImpl||fetch}),
  ]);
  return api({report,observability,health},200,{"Cache-Control":"private, no-store"});
 }catch{return error("SERVICE_UNAVAILABLE",503);}
}

/** Destructive operational cleanup: intentionally separate from soft baselines. */
export async function purgeErrorsRequest(request,options={}){
 const cfg=adminSettings();
 if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  const body=await parseSmallJson(request,160);
  if(!own(body,["scope","confirmation"]) || body.scope!=="all" ||
     body.confirmation!=="PURGAR_ERRORES")return error("INVALID_REQUEST",400);
  const purge=await purgeRetainedErrors(redis);
  return api({purge},200,{"Cache-Control":"private, no-store"});
 }catch(e){
  if(e?.message==="REDIS_ATOMIC_PURGE_UNSUPPORTED")return error("REDIS_UNSUPPORTED",503);
  return error("SERVICE_UNAVAILABLE",503);
 }
}
export async function clearAlertsRequest(request,options={}){
 const cfg=adminSettings();
 if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  const body=await parseSmallJson(request,128);
  if(!own(body,["confirmation"])||body.confirmation!=="VACIAR_ALERTAS")
   return error("INVALID_REQUEST",400);
  const cleared=await clearOperationalAlerts(redis);
  return api({cleared},200,{"Cache-Control":"private, no-store"});
 }catch{return error("SERVICE_UNAVAILABLE",503);}
}

export async function pauseAlertsRequest(request,options={}){
 const cfg=adminSettings();
 if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  const body=await parseSmallJson(request,128);
  if(!own(body,["paused"])||typeof body.paused!=="boolean")return error("INVALID_REQUEST",400);
  const alerts=await setAlertPause(redis,body.paused);
  return api({alerts},200,{"Cache-Control":"private, no-store"});
 }catch{return error("SERVICE_UNAVAILABLE",503);}
}
