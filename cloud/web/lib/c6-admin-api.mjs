import { adminSettings, adminLogin, authenticateAdmin, validMutation,
  cookieHeader, deleteCookie, revokeAdmin } from "./c6-admin-auth.mjs";
import { opsStore, maintenanceEnabled, setMaintenance, aggregateMetrics, usageReport,
  SERVICE_IDS,serviceMaintenanceStates,setServiceMaintenance,resetErrorBaselines } from "./c6-ops-store.mjs";
import { settings } from "./c3-config.mjs";
import {admissionPolicy,setAdmissionPolicy} from "./c11-play-admission.mjs";
import {v1ProtectionStatus,setV1Protection} from "./v1-protection-policy.mjs";
import {providerOverview,updateProvider,PUBLIC_PROVIDER_IDS} from "./c12-provider-controls.mjs";
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
    const [maintenance,legacyMetrics,ping,serviceMaintenance,playAdmission,providerControls,v1Protection]=await Promise.all([
      maintenanceEnabled(redis),aggregateMetrics(redis),redis.ping(),serviceMaintenanceStates(redis),
      admissionPolicy(redis),providerOverview(),v1ProtectionStatus(),
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
    return api({
      services:{apiConfigured:cfg.configured,redisConnected:ping==="PONG",
        workerReady,ehiImportConfigured:ehiConfigured(),
        nurCatalogImportConfigured:nurConfigured()},
      maintenance,serviceMaintenance,playAdmission,providerControls,v1Protection,
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
/** Admin-only reversible V1 bearer policy; V2 remains enforced independently. */
export async function v1ProtectionRequest(request,options={}){
 const cfg=adminSettings();
 if(!cfg.enabled)return error("ADMIN_DISABLED",503);
 if(!validMutation(request,cfg))return error("CSRF_REJECTED",403);
 try{
  const redis=await (options.storeProvider||opsStore)();
  if(!await authenticateAdmin(redis,request,cfg))return error("UNAUTHORIZED",401);
  const body=await parseSmallJson(request,192);
  if(!own(body,["enabled","confirmation"])||typeof body.enabled!=="boolean"||
    body.confirmation!==(body.enabled?"ACTIVAR_V1_PROTECCION":"DESACTIVAR_V1_PROTECCION"))
    return error("INVALID_REQUEST",400);
  const v1Protection=await setV1Protection(body.enabled);
  // Best-effort bounded audit without credentials or device metadata.
  try{
   await redis.lPush("spc6:v1-protection:audit",JSON.stringify({at:Date.now(),enabled:v1Protection.enabled}));
   await redis.lTrim("spc6:v1-protection:audit",0,99);
   await redis.expire("spc6:v1-protection:audit",8*86400);
  }catch{}
  return api({v1Protection},200,{"Cache-Control":"private, no-store"});
 }catch(e){
  if(e?.message==="V1_POLICY_LOCKED")return error("V1_POLICY_LOCKED",409);
  if(e?.message==="V1_POLICY_BUSY")return error("V1_POLICY_BUSY",409);
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
