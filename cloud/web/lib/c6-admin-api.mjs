import { adminSettings, adminLogin, authenticateAdmin, validMutation,
  cookieHeader, deleteCookie, revokeAdmin } from "./c6-admin-auth.mjs";
import { opsStore, maintenanceEnabled, setMaintenance, aggregateMetrics, usageReport,
  SERVICE_IDS,serviceMaintenanceStates,setServiceMaintenance } from "./c6-ops-store.mjs";
import { settings } from "./c3-config.mjs";
import {admissionPolicy,setAdmissionPolicy} from "./c11-play-admission.mjs";
import { ehiConfigured,nurConfigured } from "./c35-provider.mjs";
import { jsonReply } from "./responses.mjs";

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
    const [maintenance,metrics,ping,serviceMaintenance,playAdmission]=await Promise.all([
      maintenanceEnabled(redis),aggregateMetrics(redis),redis.ping(),serviceMaintenanceStates(redis),admissionPolicy(redis),
    ]);
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
      maintenance,serviceMaintenance,playAdmission,
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
