import { adminSettings } from "./c6-admin-auth.mjs";
import {recordAutomaticIncident} from "./c9-diagnostics.mjs";
import {recordOpsTelemetry,recordAdminAudit} from "./c14-ops-observability.mjs";
let cache;
export async function opsStore() {
  if(!adminSettings().enabled)throw Error("ADMIN_DISABLED");
  if(!cache){
    cache=import("redis").then(async({createClient})=>{
      const client=createClient({
        url:process.env.CLOUD_REDIS_URL,
        socket:{connectTimeout:3000,reconnectStrategy:false},
      });
      client.on("error",()=>{}); // No URLs, credentials or payloads in logs.
      await client.connect();
      return client;
    }).catch(e=>{cache=undefined;throw e;});
  }
  return cache;
}
export const MAINTENANCE_KEY="spc6:maintenance";
export async function maintenanceEnabled(redis,env=process.env) {
  if(env.CLOUD_FORCE_MAINTENANCE==="true")return true;
  return await redis.get(MAINTENANCE_KEY)==="1";
}
export async function setMaintenance(redis,enabled,env=process.env) {
  if(!enabled && env.CLOUD_FORCE_MAINTENANCE==="true")throw Error("MAINTENANCE_LOCKED");
  if(enabled)await redis.set(MAINTENANCE_KEY,"1");
  else await redis.del(MAINTENANCE_KEY);
}
/** Fixed allowlist: no arbitrary Redis keys may come from an admin request. */
export const SERVICE_IDS=Object.freeze(["files","httpInjector","serverVpn"]);
const serviceKey=id=>{
  if(!SERVICE_IDS.includes(id))throw Error("INVALID_SERVICE");
  return "spc6:maintenance:service:"+id;
};
export async function serviceMaintenanceStates(redis) {
  const entries=await Promise.all(SERVICE_IDS.map(async id=>[id,(await redis.get(serviceKey(id)))==="1"]));
  return Object.fromEntries(entries);
}
export async function serviceMaintenanceEnabled(redis,id,env=process.env){
  // VPS lock and general maintenance always override per-service switches.
  if(await maintenanceEnabled(redis,env))return true;
  return (await redis.get(serviceKey(id)))==="1";
}
export async function setServiceMaintenance(redis,id,enabled,env=process.env){
  const key=serviceKey(id);
  if(env.CLOUD_FORCE_MAINTENANCE==="true")throw Error("MAINTENANCE_LOCKED");
  if(enabled)await redis.set(key,"1");
  else await redis.del(key);
}
export async function recordWorkerResult(redis,outcome,meta=null) {
  // No filenames, payloads, IPs, tokens, or decoded data are retained.
  const classification=classifyWorkerOutcome(outcome,meta||{});
  if(classification==="ignored")return;
  outcome=classification;
  const day=new Date().toISOString().slice(0,10);
  const key="spc6:metrics:"+day+":"+outcome;
  const pipeline=redis.multi();
  pipeline.incr(key);
  pipeline.expire(key,8*86400);
  await pipeline.exec();
  // Keep legacy totals unchanged. New telemetry begins from deployment;
  // nothing is backfilled or inferred from historical file contents.
  if(meta){
    await recordAnonymousUsage(redis,outcome,meta);
    // Best-effort diagnostics: a Redis failure must never change decode outcomes.
    try{await recordAutomaticIncident(redis,outcome,meta);}catch{}
    try{
      const service=meta.kind==="ehi"?"httpInjector":
        ["catalog","server-vpn"].includes(meta.kind)?"serverVpn":"files";
      await recordOpsTelemetry(redis,{...meta,outcome,service,
        format:safeFormat(meta.kind,meta.format,meta.errorCode)});
    }catch{} // Observability can never change the user's decode result.
  }
}
export async function aggregateMetrics(redis) {
  const day=new Date().toISOString().slice(0,10);
  const [success,failed]=await redis.mGet([
    "spc6:metrics:"+day+":success",
    "spc6:metrics:"+day+":failed",
  ]);
  return {window:"utc_today",successfulDecodes:Number(success)||0,failedDecodes:Number(failed)||0};
}

/**
 * Bounded operational counters only: no file names, usernames, IPs, payloads,
 * keys or raw error text. One Redis hash per UTC day expires after 8 days.
 */
const REPORT_PREFIX="spc6:telemetry:";
const REPORT_TTL=8*86400;
const KNOWN_ERRORS=new Set([
  "UNSUPPORTED_FORMAT","DECODE_FAILED","ENGINE_TIMEOUT","ENGINE_UNAVAILABLE",
  "AUTH_FAILED","INVALID_CREDENTIALS","PASSWORD_REQUIRED","HWID_REQUIRED",
  "HWID_PASSWORD_REQUIRED","INVALID_REQUEST","INVALID_INPUT","INVALID_BASE64",
  "INPUT_TOO_LARGE","OUTPUT_TOO_LARGE","SERVICE_UNAVAILABLE",
  "REMOTE_PROVIDER_UNAVAILABLE","REMOTE_CONFIG_UNAVAILABLE","REMOTE_RESPONSE_INVALID","REMOTE_INTEGRITY_FAILED",
  "REMOTE_TOO_LARGE","REMOTE_DECODER_FAILED","SERVICE_MAINTENANCE",
  "UNSUPPORTED_VERSION","UNSUPPORTED_CONFIG_VERSION","PARTIAL_SOURCE_FAILURE",
]);
const dayUTC=(offset=0)=>new Date(Date.now()-offset*86400000).toISOString().slice(0,10);
export function safeFormat(kind,format,errorCode="") {
  // Remote catalog contents and private provider URLs must never be stored.
  if(kind==="server-vpn")
    return typeof format==="string" && /^[a-z0-9-]{1,48}$/.test(format)
      ? "vpn-"+format : "vpn-other";
  if(kind==="text")return "text";
  if(kind==="catalog")return "nur-catalog";
  if(kind==="ehi")return "ehi";
  if(kind!=="file" || (errorCode==="UNSUPPORTED_FORMAT" && format!=="npvs"))return "other";
  if(format==="fɴ")return format;
  if(typeof format!=="string" || format.length>32 ||
    !/^[a-z0-9][a-z0-9._-]{0,31}$/.test(format))return "other";
  return format;
}
export function safeErrorCode(code) {
  return KNOWN_ERRORS.has(code) ? code : "OTHER_ERROR";
}
const REQUIRED_INPUT=new Set(["PASSWORD_REQUIRED","HWID_REQUIRED","HWID_PASSWORD_REQUIRED",
  "USER_CANCELLED","CANCELLED","USER_CONSENT_REQUIRED"]);
const INCOMPATIBLE=new Set(["UNSUPPORTED_FORMAT","UNSUPPORTED_VERSION","UNSUPPORTED_CONFIG_VERSION"]);
export function classifyWorkerOutcome(outcome,{kind,format,errorCode}={}){
  if(outcome==="success")return "success";
  if(outcome!=="failed"&&outcome!=="warning")return "ignored";
  if(REQUIRED_INPUT.has(errorCode))return "ignored"; // No decode; cancelling never yields an event.
  if(outcome==="warning"||INCOMPATIBLE.has(errorCode)||
      (kind==="file" && format==="npvs" && errorCode==="DECODE_FAILED"))return "warning";
  return "failed";
}
const BASELINE_KEY="spc6:error-baselines";
export async function errorBaselines(redis){
  const raw=await redis.hGetAll(BASELINE_KEY),result={};
  for(const [format,value] of Object.entries(raw||{})){
    try{
      const parsed=JSON.parse(value);
      if(parsed&&typeof parsed.at==="string"&&parsed.days&&typeof parsed.days==="object")
        result[format]=parsed;
    }catch{}
  }
  return result;
}
const parseCount=value=>Math.max(0,Number.parseInt(value||"0",10)||0);
function errorSnapshot(data,format){
  const failed=parseCount(data["format:"+format+":failed"]);
  const codes={};
  for(const [field,value] of Object.entries(data)){
    const match=/^formatError:([^:]+):([A-Z_]+)$/.exec(field);
    if(match&&match[1]===format)codes[match[2]]=parseCount(value);
  }
  return {failed,codes,attempts:parseCount(data["format:"+format+":attempts"]),
    success:parseCount(data["format:"+format+":success"])};
}
/** Reset *only* currently displayed errors, keeping successes, warnings, bytes
 * and historical attempts. New errors become visible immediately after reset.
 * Old errors remain in bounded raw Redis hashes for audit/retention, but are
 * subtracted by saved per-format/day baselines from current admin diagnostics. */
export async function resetErrorBaselines(redis,{scope,format}){
  if(scope!=="all"&&scope!=="format")throw Error("INVALID_RESET_SCOPE");
  const dates=Array.from({length:7},(_,i)=>dayUTC(i));
  const hashes=await Promise.all(dates.map(d=>redis.hGetAll(REPORT_PREFIX+d)));
  const known=[...new Set(hashes.flatMap(data=>Object.keys(data||{})
    .map(key=>/^format:([^:]+):(success|failed|warning)$/.exec(key)?.[1]).filter(Boolean)))];
  const targets=scope==="all"?known:[format];
  if(targets.length>512)throw Error("RESET_TOO_MANY_FORMATS");
  if(scope==="format"&&(!known.includes(format)||!/^[a-z0-9ɴ][a-z0-9ɴ._-]{0,52}$/.test(format)))
    throw Error("INVALID_FORMAT");
  const at=new Date().toISOString();
  const tx=redis.multi();
  for(const id of targets){
    const days=Object.fromEntries(dates.map((date,i)=>[date,errorSnapshot(hashes[i]||{},id)]));
    tx.hSet(BASELINE_KEY,id,JSON.stringify({at,days}));
  }
  // Manual incidents may have no matching worker-format counter. A global
  // reset must still hide old manual error reports, never warnings.
  if(scope==="all")tx.hSet(BASELINE_KEY,"@all",JSON.stringify({at,days:{}}));
  tx.expire(BASELINE_KEY,8*86400);
  await tx.exec();
  await recordAdminAudit(redis,{scope,format,at,formatsReset:targets.length});
  return {scope,formatsReset:targets.length,at};
}
export async function recordAnonymousUsage(redis,outcome,{kind,format,bytes=0,errorCode=""}={}) {
  if(!["success","failed","warning"].includes(outcome))return;
  const extension=safeFormat(kind,format,errorCode);
  const code=outcome!=="success"?safeErrorCode(errorCode):null;
  const inputBytes=Number.isSafeInteger(bytes)&&bytes>=0&&bytes<=12*1024*1024?bytes:0;
  const p=redis.multi();
  const key=REPORT_PREFIX+dayUTC();
  p.hIncrBy(key,"attempts",1);
  p.hIncrBy(key,outcome,1);
  p.hIncrBy(key,"bytes",inputBytes);
  const service=kind==="ehi"?"httpInjector":
    kind==="catalog"||kind==="server-vpn"?"serverVpn":"files";
  const hour=new Date().toISOString().slice(11,13);
  p.hIncrBy(key,"service:"+service+":"+outcome,1);
  p.hIncrBy(key,"hour:"+hour+":"+outcome,1);
  if(code)p.hIncrBy(key,(outcome==="warning"?"serviceWarning:":"serviceError:")+service+":"+code,1);
  p.hIncrBy(key,"format:"+extension+":attempts",1);
  p.hIncrBy(key,"format:"+extension+":"+outcome,1);
  if(code){
    p.hIncrBy(key,(outcome==="warning"?"warning:":"error:")+code,1);
    p.hIncrBy(key,(outcome==="warning"?"formatWarning:":"formatError:")+extension+":"+code,1);
  }
  p.expire(key,REPORT_TTL);
  await p.exec();
}
export async function usageReport(redis,days=7) {
  if(![1,7].includes(days))throw Error("INVALID_REPORT_WINDOW");
  const dates=Array.from({length:days},(_,i)=>dayUTC(days-1-i));
  const hashes=await Promise.all(dates.map(day=>redis.hGetAll(REPORT_PREFIX+day)));
  // Also read yesterday's bounded hourly counters for the rolling 48 h chart.
  const extraDates=[dayUTC(1),dayUTC(2)].filter(date=>!dates.includes(date));
  const extraHashes=await Promise.all(extraDates.map(date=>redis.hGetAll(REPORT_PREFIX+date)));
  const hourlyHashes=new Map(dates.map((date,i)=>[date,hashes[i]||{}]));
  extraDates.forEach((date,i)=>hourlyHashes.set(date,extraHashes[i]||{}));
  const formats=new Map(),errors=new Map(),byFormatError=new Map(),warnings=new Map();
  const baselines=await errorBaselines(redis);
  const services=Object.fromEntries(SERVICE_IDS.map(id=>[id,{service:id,successfulDecodes:0,failedDecodes:0,attempts:0}]));
  const rawServiceAttempts=Object.fromEntries(SERVICE_IDS.map(id=>[id,0]));

  const daily=[];
  let success=0,failed=0,warningTotal=0,bytes=0,historicalAttempts=0;
  const parse=v=>Math.max(0,Number.parseInt(v||"0",10)||0);
  for(let i=0;i<dates.length;i++){
    const data=hashes[i]||{};
    const dSuccess=parse(data.success),dBytes=parse(data.bytes);
    let dFailed=0,dWarnings=0;
    for(const [field,val] of Object.entries(data)){
      const m=/^format:([^:]+):(failed|warning)$/.exec(field);
      if(!m)continue;
      if(m[2]==="warning")dWarnings+=parse(val);
      else dFailed+=Math.max(0,parse(val)-parse(baselines[m[1]]?.days?.[dates[i]]?.failed));
    }
    success+=dSuccess;failed+=dFailed;warningTotal+=dWarnings;bytes+=dBytes;
    historicalAttempts+=parse(data.attempts);
    daily.push({date:dates[i],successfulDecodes:dSuccess,failedDecodes:dFailed,
      warnings:dWarnings,inputBytes:dBytes});
    for(const service of SERVICE_IDS){
      services[service].successfulDecodes+=parse(data["service:"+service+":success"]);
      rawServiceAttempts[service]+=parse(data["service:"+service+":success"])+
        parse(data["service:"+service+":failed"])+parse(data["service:"+service+":warning"]);
      // Effective failed counts are calculated from per-format counters below.
    }
    for(const [field,value] of Object.entries(data)){
      const count=parse(value);
      if(!count)continue;
      const attemptMatch=/^format:([^:]+):attempts$/.exec(field);
      if(attemptMatch){
        const extension=attemptMatch[1];
        const item=formats.get(extension)||{extension,successfulDecodes:0,failedDecodes:0,warnings:0,attempts:0};
        item.attempts=(item.attempts||0)+count;
        formats.set(extension,item);
      }
      const formatMatch=/^format:([^:]+):(success|failed|warning)$/.exec(field);
      if(formatMatch){
        const [_,extension,result]=formatMatch;
        const item=formats.get(extension)||{extension,successfulDecodes:0,failedDecodes:0,warnings:0};
        const effective=result==="failed"
          ?Math.max(0,count-parse(baselines[extension]?.days?.[dates[i]]?.failed)):count;
        item[result==="success"?"successfulDecodes":result==="warning"?"warnings":"failedDecodes"]+=effective;
        formats.set(extension,item);
      }
      const warningMatch=/^warning:([A-Z_]+)$/.exec(field);
      if(warningMatch)warnings.set(warningMatch[1],(warnings.get(warningMatch[1])||0)+count);
      const formatErrorMatch=/^formatError:([^:]+):([A-Z_]+)$/.exec(field);
      if(formatErrorMatch){
        const label=formatErrorMatch[1],code=formatErrorMatch[2],key=label+":"+code;
        const item=byFormatError.get(key)||{extension:label,code,count:0};
        item.count+=Math.max(0,count-parse(baselines[label]?.days?.[dates[i]]?.codes?.[code]));
        byFormatError.set(key,item);
      }
    }
  }
  const breakdown=[...formats.values()].map(f=>{
    const item={...f,attempts:f.attempts??(f.successfulDecodes+f.failedDecodes+f.warnings)};
    if(!item.warnings)delete item.warnings; // preserve legacy shape for supported files
    return item;
  })
    .sort((a,b)=>b.attempts-a.attempts||a.extension.localeCompare(b.extension));
  // Reconstruct current errors from scope-filtered per-format counters; this
  // avoids old resets reappearing under other error/service rollups.
  const formatService=label=>label.startsWith("vpn-")||label==="nur-catalog"?"serverVpn":
    label==="ehi"?"httpInjector":"files";
  const serviceCounts=new Map();
  for(const issue of byFormatError.values()){
    errors.set(issue.code,(errors.get(issue.code)||0)+issue.count);
    const k=formatService(issue.extension)+":"+issue.code;
    serviceCounts.set(k,(serviceCounts.get(k)||0)+issue.count);
  }
  for(const item of formats.values())services[formatService(item.extension)].failedDecodes+=item.failedDecodes;
  const comparisons=Object.entries(baselines).filter(([format])=>format!=="@all")
    .map(([extension,baseline])=>{
      const previous=Object.values(baseline.days||{});
      const beforeErrors=previous.reduce((sum,x)=>sum+parse(x.failed),0);
      const hasAttempts=previous.length>0&&previous.every(x=>Object.hasOwn(x,"attempts"));
      const beforeAttempts=hasAttempts?previous.reduce((sum,x)=>sum+parse(x.attempts),0):null;
      const current=breakdown.find(x=>x.extension===extension);
      const sinceAttempts=beforeAttempts===null?null:
        Math.max(0,(current?.attempts||0)-beforeAttempts);
      const afterErrors=current?.failedDecodes||0;
      return {extension,resetAt:baseline.at,beforeErrors,
        beforeAttempts,
        beforeErrorPercent:beforeAttempts?Math.round(beforeErrors/beforeAttempts*1000)/10:null,
        afterErrors,afterAttempts:sinceAttempts,
        afterErrorPercent:sinceAttempts?Math.round(afterErrors/sinceAttempts*1000)/10:null,
        note:"UTC 7-day bounded baseline; historical attempts may include earlier operations"};
    }).sort((a,b)=>b.resetAt.localeCompare(a.resetAt)).slice(0,100);
  const failures=[...errors].map(([code,count])=>({code,count})).filter(x=>x.count>0)
    .sort((a,b)=>b.count-a.count||a.code.localeCompare(b.code));
  const incidents=[...byFormatError.values()].sort((a,b)=>b.count-a.count).slice(0,100);
  const now=new Date();
  const hourly=Array.from({length:48},(_,i)=>{
    const hour=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate(),now.getUTCHours()-47+i));
    const date=hour.toISOString().slice(0,10),hourKey=hour.toISOString().slice(11,13);
    const bucket=hourlyHashes.get(date)||{};
    return {hour:date+"T"+hourKey+":00Z",successfulDecodes:parse(bucket["hour:"+hourKey+":success"]),
      failedDecodes:parse(bucket["hour:"+hourKey+":failed"])};
  });
  const breakdownServices=SERVICE_IDS.map(id=>({
    ...services[id],attempts:rawServiceAttempts[id],
  }));
  const errorServices=[...serviceCounts].map(([key,count])=>{
    const [service,code]=key.split(":");return {service,code,count};
  }).sort((a,b)=>b.count-a.count);
  return {window:days===1?"utc_today":"last_7_utc_days",days,successfulDecodes:success,
    failedDecodes:failed,warnings:warningTotal,totalDecodes:historicalAttempts,inputBytes:bytes,daily,
    extensions:breakdown,errors:failures,
    warningCodes:[...warnings].map(([code,count])=>({code,count})).sort((a,b)=>b.count-a.count),
    comparisons,incidents:incidents.filter(x=>x.count>0),resets:Object.entries(baselines).filter(([label])=>label!=="@all").map(([extension,v])=>({extension,at:v.at})),
    serviceBreakdown:breakdownServices,serviceErrors:errorServices,hourlyLast48:hourly,
    retentionDays:8,hourlyFailuresAreHistorical:true,historyAvailableFrom:"first_deployment_of_telemetry",
    includes:"worker_results_only",privacy:"anonymous_aggregate_counters"};
}
