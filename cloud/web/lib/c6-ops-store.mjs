import { adminSettings } from "./c6-admin-auth.mjs";
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
export async function recordWorkerResult(redis,outcome,meta=null) {
  // No filenames, payloads, IPs, tokens, or decoded data are retained.
  if(!["success","failed"].includes(outcome))return;
  const day=new Date().toISOString().slice(0,10);
  const key="spc6:metrics:"+day+":"+outcome;
  const pipeline=redis.multi();
  pipeline.incr(key);
  pipeline.expire(key,8*86400);
  await pipeline.exec();
  // Keep legacy totals unchanged. New telemetry begins from deployment;
  // nothing is backfilled or inferred from historical file contents.
  if(meta) await recordAnonymousUsage(redis,outcome,meta);
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
  "REMOTE_PROVIDER_UNAVAILABLE","REMOTE_RESPONSE_INVALID","REMOTE_INTEGRITY_FAILED",
  "REMOTE_TOO_LARGE","REMOTE_DECODER_FAILED",
]);
const dayUTC=(offset=0)=>new Date(Date.now()-offset*86400000).toISOString().slice(0,10);
export function safeFormat(kind,format,errorCode="") {
  if(kind==="text")return "text";
  if(kind==="catalog")return "nur-catalog";
  if(kind==="ehi")return "ehi";
  if(kind!=="file" || errorCode==="UNSUPPORTED_FORMAT")return "other";
  if(format==="fɴ")return format;
  if(typeof format!=="string" || format.length>32 ||
    !/^[a-z0-9][a-z0-9._-]{0,31}$/.test(format))return "other";
  return format;
}
export function safeErrorCode(code) {
  return KNOWN_ERRORS.has(code) ? code : "OTHER_ERROR";
}
export async function recordAnonymousUsage(redis,outcome,{kind,format,bytes=0,errorCode=""}={}) {
  if(!["success","failed"].includes(outcome))return;
  const extension=safeFormat(kind,format,errorCode);
  const code=outcome==="failed"?safeErrorCode(errorCode):null;
  const inputBytes=Number.isSafeInteger(bytes)&&bytes>=0&&bytes<=12*1024*1024?bytes:0;
  const p=redis.multi();
  const key=REPORT_PREFIX+dayUTC();
  p.hIncrBy(key,"attempts",1);
  p.hIncrBy(key,outcome,1);
  p.hIncrBy(key,"bytes",inputBytes);
  p.hIncrBy(key,"format:"+extension+":attempts",1);
  p.hIncrBy(key,"format:"+extension+":"+outcome,1);
  if(code){
    p.hIncrBy(key,"error:"+code,1);
    p.hIncrBy(key,"formatError:"+extension+":"+code,1);
  }
  p.expire(key,REPORT_TTL);
  await p.exec();
}
export async function usageReport(redis,days=7) {
  if(![1,7].includes(days))throw Error("INVALID_REPORT_WINDOW");
  const dates=Array.from({length:days},(_,i)=>dayUTC(days-1-i));
  const hashes=await Promise.all(dates.map(day=>redis.hGetAll(REPORT_PREFIX+day)));
  const formats=new Map(),errors=new Map(),byFormatError=new Map();
  const daily=[];
  let success=0,failed=0,bytes=0;
  const parse=v=>Math.max(0,Number.parseInt(v||"0",10)||0);
  for(let i=0;i<dates.length;i++){
    const data=hashes[i]||{};
    const dSuccess=parse(data.success),dFailed=parse(data.failed),dBytes=parse(data.bytes);
    success+=dSuccess;failed+=dFailed;bytes+=dBytes;
    daily.push({date:dates[i],successfulDecodes:dSuccess,failedDecodes:dFailed,inputBytes:dBytes});
    for(const [field,value] of Object.entries(data)){
      const count=parse(value);
      if(!count)continue;
      const formatMatch=/^format:([^:]+):(success|failed)$/.exec(field);
      if(formatMatch){
        const [_,extension,result]=formatMatch;
        const item=formats.get(extension)||{extension,successfulDecodes:0,failedDecodes:0};
        item[result==="success"?"successfulDecodes":"failedDecodes"]+=count;
        formats.set(extension,item);
      }
      const errMatch=/^error:([A-Z_]+)$/.exec(field);
      if(errMatch)errors.set(errMatch[1],(errors.get(errMatch[1])||0)+count);
      const formatErrorMatch=/^formatError:([^:]+):([A-Z_]+)$/.exec(field);
      if(formatErrorMatch){
        const label=formatErrorMatch[1],code=formatErrorMatch[2],key=label+":"+code;
        const item=byFormatError.get(key)||{extension:label,code,count:0};
        item.count+=count;
        byFormatError.set(key,item);
      }
    }
  }
  const breakdown=[...formats.values()].map(f=>({...f,attempts:f.successfulDecodes+f.failedDecodes}))
    .sort((a,b)=>b.attempts-a.attempts||a.extension.localeCompare(b.extension));
  const failures=[...errors].map(([code,count])=>({code,count})).sort((a,b)=>b.count-a.count||a.code.localeCompare(b.code));
  const incidents=[...byFormatError.values()].sort((a,b)=>b.count-a.count).slice(0,100);
  return {window:days===1?"utc_today":"last_7_utc_days",days,successfulDecodes:success,
    failedDecodes:failed,totalDecodes:success+failed,inputBytes:bytes,daily,
    extensions:breakdown,errors:failures,incidents,
    retentionDays:8,historyAvailableFrom:"first_deployment_of_telemetry",
    includes:"worker_results_only",privacy:"anonymous_aggregate_counters"};
}
