/** C14 bounded, privacy-minimised operations telemetry. Never store payloads,
 * paths, IPs, users, credentials, URLs, raw exceptions, or decoded JSON.
 * Only known service/format codes from c6-ops-store enter this module. */
import {readFile} from "node:fs/promises";
const TTL=8*86400, PREFIX="spc14:obs:", ALERTS="spc14:alerts", AUDIT="spc14:admin-actions";
export const ALERT_PAUSE_KEY="spc14:alerts:pause-until";
const SAMPLE_LIMIT=20, LIMITS=[100,250,500,1000,2000,5000,10000,20000,45000,120000,300000];
const CATEGORIES={
 ENGINE_TIMEOUT:"timeout",REMOTE_PROVIDER_UNAVAILABLE:"network",
 REMOTE_NETWORK_DENIED:"network",SERVICE_UNAVAILABLE:"network",
 ENGINE_UNAVAILABLE:"engine",REMOTE_DECODER_FAILED:"engine",
 DECODE_FAILED:"engine",REMOTE_RESPONSE_INVALID:"response",
 REMOTE_INTEGRITY_FAILED:"response",OUTPUT_INVALID:"response",
 OUTPUT_INVALID_UTF8:"response",OUTPUT_TOO_LARGE:"response",
 INVALID_WORKER_RESULT:"response",UNSUPPORTED_FORMAT:"compatibility",
 UNSUPPORTED_VERSION:"compatibility",UNSUPPORTED_CONFIG_VERSION:"compatibility",
};
const n=v=>Math.max(0,Number.parseInt(v||"0",10)||0);
const day=(offset=0)=>new Date(Date.now()-offset*86400000).toISOString().slice(0,10);
const appVersion=v=>typeof v==="string"&&/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)?v:"not-provided";
const exporterVersion=v=>typeof v==="string"&&/^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/.test(v)?v:"not-provided";
const category=code=>CATEGORIES[code]||"other";
const bins=Array.from({length:LIMITS.length+1},(_,i)=>i);
export function latencyBucket(value){
 if(!Number.isFinite(value)||value<0)return null;
 return LIMITS.findIndex(limit=>value<=limit)===-1?LIMITS.length:LIMITS.findIndex(limit=>value<=limit);
}
function quantile(hist,percent){
 const count=hist.reduce((total,x)=>total+x,0);
 if(!count)return null;
 let index=0;
 for(let i=0;i<hist.length;i++){index+=hist[i];if(index>=Math.ceil(count*percent))return LIMITS[i]??300000;}
 return 300000;
}
export function latencySummary(stats){
 const count=n(stats.count),sum=n(stats.sum);
 const histogram=bins.map(i=>n(stats["b"+i]));
 return {count,meanMs:count?Math.round(sum/count):null,p95UpperBoundMs:quantile(histogram,.95),
  granularity:"histogram_upper_bound_ms"};
}
export async function recordOpsTelemetry(redis,{format,service,outcome,errorCode="",latencyMs=null,
  appVersion:clientVersion,formatVersion:formatVersionRaw}={}){
 if(!/^[a-z0-9ɴ][a-z0-9ɴ._-]{0,52}$/.test(format||"") ||
    !["files","httpInjector","serverVpn"].includes(service) ||
    !["success","failed","warning"].includes(outcome))return;
 const code=typeof errorCode==="string"&&/^[A-Z_]{3,48}$/.test(errorCode)?errorCode:"OTHER_ERROR";
 const p=redis.multi(),key=PREFIX+day();
 const bucket=latencyBucket(latencyMs),group=[format,service];
 for(const scope of group){
  const prefix=(scope===service?"service:":"format:")+scope+":";
  p.hIncrBy(key,prefix+"events",1);
  if(bucket!==null){
   const value=Math.min(300000,Math.round(latencyMs));
   p.hIncrBy(key,prefix+"lat:count",1);
   p.hIncrBy(key,prefix+"lat:sum",value);
   p.hIncrBy(key,prefix+"lat:b"+bucket,1);
  }
  if(outcome!=="success")p.hIncrBy(key,prefix+"category:"+category(code),1);
 }
 p.hIncrBy(key,"clientVersion:"+appVersion(clientVersion),1);
 p.hIncrBy(key,"exporterVersion:"+format+":"+exporterVersion(formatVersionRaw),1);
 p.expire(key,TTL);
 await p.exec();
 if(service!=="serverVpn")return;
 const historyKey="spc14:provider:"+format;
 const recentKind=outcome==="success"?"ok":outcome==="warning"?"compat":"error:"+category(code);
 await redis.lPush(historyKey,recentKind);
 await redis.lTrim(historyKey,0,SAMPLE_LIMIT-1);
 await redis.expire(historyKey,TTL);
 const recent=await redis.lRange(historyKey,0,9);
 const failures=recent.filter(x=>x.startsWith("error:")).length;
 const noResponse=recent.slice(0,3).length===3&&recent.slice(0,3)
   .every(x=>x==="error:network"||x==="error:timeout");
 const highRate=recent.length===10&&failures>=5;
 const alertType=noResponse?"unresponsive":highRate?"failure_ratio":null;
 if(!alertType)return;
 if(await redis.get(ALERT_PAUSE_KEY))return; // Suppress alerts only; all metrics remain intact.
 const cooldown="spc14:alert-cooldown:"+format+":"+alertType;
 if(await redis.set(cooldown,"1",{EX:3600,NX:true})!=="OK")return;
 await redis.lPush(ALERTS,JSON.stringify({
   at:new Date().toISOString(),format,type:alertType,
   failures,recent:recent.length,window:"last_10_operations",source:"api",
 }));
 await redis.lTrim(ALERTS,0,99);await redis.expire(ALERTS,TTL);
}
export async function readOpsReport(redis,days=7){
 const dates=Array.from({length:days},(_,i)=>day(days-1-i));
 const pages=await Promise.all(dates.map(x=>redis.hGetAll(PREFIX+x)));
 const groups=new Map(),versions=new Map(),exporters=new Map();
 for(const page of pages){
  for(const [field,value] of Object.entries(page||{})){
   const amount=n(value);
   if(!amount)continue;
   const vm=/^clientVersion:([^:]+)$/.exec(field);
   if(vm){versions.set(vm[1],(versions.get(vm[1])||0)+amount);continue;}
   const ev=/^exporterVersion:([^:]+):([^:]+)$/.exec(field);
   if(ev){const k=ev[1]+"|"+ev[2];exporters.set(k,(exporters.get(k)||0)+amount);continue;}
   const hit=/^(format|service):([^:]+):(.*)$/.exec(field);
   if(!hit)continue;
   const id=hit[1]+":"+hit[2],stats=groups.get(id)||{};
   stats[hit[3]]=n(stats[hit[3]])+amount;groups.set(id,stats);
  }
 }
 const performance=[...groups].map(([id,s])=>({
  scope:id.startsWith("format:")?"format":"service",label:id.split(":").slice(1).join(":"),
  ...latencySummary({count:s["lat:count"],sum:s["lat:sum"],
    ...Object.fromEntries(bins.map(i=>["b"+i,s["lat:b"+i]]))}),
  events:n(s.events),
  categories:Object.fromEntries(["network","timeout","engine","response","compatibility","other"]
    .map(k=>[k,n(s["category:"+k])])),
 })).filter(x=>x.events>0).sort((a,b)=>b.events-a.events||a.label.localeCompare(b.label)).slice(0,200);
 const alerts=[];
 for(const raw of await redis.lRange(ALERTS,0,99)){
  try{const alert=JSON.parse(raw);if(typeof alert.at==="string"&&
    dates.some(d=>alert.at.startsWith(d))&&/^[a-z0-9ɴ][a-z0-9ɴ._-]{0,52}$/.test(alert.format))
    alerts.push(alert);}catch{}
 }
 const alertPauseRaw=await redis.get(ALERT_PAUSE_KEY);
 const alertsPausedUntil=alertPauseRaw&&/^\d{13}$/.test(alertPauseRaw)?new Date(Number(alertPauseRaw)).toISOString():null;
 const latest=await redis.lRange(AUDIT,0,49),actions=[];
 for(const raw of latest){
  try{const v=JSON.parse(raw);if(["reset_errors","purge_errors","clear_alerts","pause_alerts","resume_alerts"].includes(v.action)&&typeof v.at==="string")actions.push(v);}catch{}
 }
 return {performance,alerts,versions:[...versions].map(([version,count])=>({version,count}))
   .sort((a,b)=>b.count-a.count).slice(0,30),
  formatVersions:[...exporters].map(([k,count])=>{const [format,version]=k.split("|");return {format,version,count};})
   .sort((a,b)=>b.count-a.count).slice(0,80),
  actions,alertsPausedUntil,latencyMethod:"bounded_histogram",retentionDays:8,
  thresholds:{unresponsive:"3 consecutive network/timeout failures",highFailureRatio:"5 of last 10 operations",cooldownMinutes:60}};
}
export async function recordAdminAudit(redis,{scope,format,at,formatsReset,mode="reset",
  removedFailures=0,removedIncidents=0,removedAlerts=0}={}){
 const action=mode==="purge"?"purge_errors":mode==="clear_alerts"?"clear_alerts":
  mode==="pause_alerts"?"pause_alerts":mode==="resume_alerts"?"resume_alerts":"reset_errors";
 const event={at,action,scope,format:scope==="format"?format:null,formatsReset};
 if(action==="purge_errors")Object.assign(event,{removedFailures,removedIncidents,removedAlerts});
 if(action==="clear_alerts")event.removedAlerts=removedAlerts;
 await redis.lPush(AUDIT,JSON.stringify(event));
 await redis.lTrim(AUDIT,0,99);await redis.expire(AUDIT,TTL);
}
const sys=async path=>{
 try{return (await readFile(path,"utf8")).trim();}
 catch{return null;}
};
export async function hostHealth(redis,{fetchImpl=fetch}={}){
 // This service runs in Docker. cgroup metrics describe only the WEB CONTAINER
 // and must never be misrepresented as host-wide VPS utilisation.
 const memoryCurrentText=await sys("/sys/fs/cgroup/memory.current");
 const memCurrent=memoryCurrentText===null?null:Number(memoryCurrentText);
 const memoryMaxText=await sys("/sys/fs/cgroup/memory.max");
 const memoryLimit=memoryMaxText&&memoryMaxText!=="max"?Number(memoryMaxText):null;
 const cpu=await sys("/sys/fs/cgroup/cpu.stat");
 const cpuUsageMatch=/^usage_usec\s+(\d+)/m.exec(cpu||"");
 const usage=cpuUsageMatch?Number(cpuUsageMatch[1]):null;
 const now=Date.now();
 let cpuPercent=null;
 if(usage!==null&&Number.isFinite(usage)){
  const previous=await redis.get("spc14:health:cpu:last");
  await redis.set("spc14:health:cpu:last",JSON.stringify({now,usage}),{EX:300});
  try{
   const last=JSON.parse(previous);
   const elapsed=now-last.now;
   if(elapsed>=1000 && elapsed<=300000 && usage>=last.usage)
    cpuPercent=Math.round((usage-last.usage)/(elapsed*1000)*1000)/10;
  }catch{}
 }
 let redisReady=false,workerReady=false;
 try{redisReady=(await redis.ping())==="PONG";}catch{}
 if(process.env.WORKER_INTERNAL_URL==="http://decoder-worker:8787"){
  try{
   const r=await fetchImpl("http://decoder-worker:8787/ready",{
    signal:AbortSignal.timeout(3000),cache:"no-store",redirect:"error"
   });workerReady=r.ok;
  }catch{}
 }
 return {scope:"web_container_only",vpsHostMetricsAvailable:false,
  cpuPercent:cpuPercent===null?null:Math.max(0,cpuPercent),
  memoryUsedBytes:memCurrent!==null&&Number.isFinite(memCurrent)&&memCurrent>=0?memCurrent:null,
  memoryLimitBytes:Number.isFinite(memoryLimit)&&memoryLimit>0?memoryLimit:null,
  redisReady,workerReady,
  pendingQueue:null,queuePolicy:"no_persistent_queue; excess requests are rate-limited",
  sampledAt:new Date(now).toISOString()};
}
