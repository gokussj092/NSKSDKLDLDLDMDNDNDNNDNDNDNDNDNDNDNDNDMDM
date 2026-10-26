/** Bounded, authenticated operator operations; no content or arbitrary Redis keys. */
import {recordAdminAudit,ALERT_PAUSE_KEY} from "./c14-ops-observability.mjs";
const dayUTC=offset=>new Date(Date.now()-offset*86400000).toISOString().slice(0,10);
export function errorPurgeKeys(){
 const keys=[];
 for(let offset=0;offset<8;offset++){
  const day=dayUTC(offset);
  keys.push("spc6:telemetry:"+day,"spc6:metrics:"+day+":failed",
   "spc9:incidents:"+day,"spc14:obs:"+day);
 }
 keys.push("spc6:error-baselines","spc14:alerts");
 return keys;
}
// One atomic Redis script prevents concurrent decoding requests from being lost.
// Warning incidents, successes, app-version metrics and installed-device estimates survive.
const PURGE_SCRIPT="\nlocal removedFailures,removedIncidents,removedAlerts,removedCategories=0,0,0,0\nlocal providers={}\nfor i=0,7 do\n local index=i*4+1\n local telemetry=KEYS[index]\n local legacy=KEYS[index+1]\n local incidents=KEYS[index+2]\n local obs=KEYS[index+3]\n local fields=redis.call('HGETALL',telemetry)\n local success=tonumber(redis.call('HGET',telemetry,'success') or '0') or 0\n local warning=tonumber(redis.call('HGET',telemetry,'warning') or '0') or 0\n local formats={}\n for j=1,#fields,2 do\n  local field=fields[j]\n  local value=tonumber(fields[j+1]) or 0\n  local fmt=string.match(field,'^format:([^:]+):failed$')\n  if fmt then\n   formats[fmt]=true\n   if string.sub(fmt,1,4)=='vpn-' then providers[fmt]=true end\n  end\n  local existing=string.match(field,'^format:([^:]+):attempts$')\n  if existing then formats[existing]=true end\n  if field=='failed' then removedFailures=removedFailures+value end\n  if field=='failed' or\n     string.match(field,'^format:[^:]+:failed$') or\n     string.match(field,'^service:[^:]+:failed$') or\n     string.match(field,'^hour:%d%d:failed$') or\n     string.match(field,'^error:[A-Z_]+$') or\n     string.match(field,'^serviceError:[^:]+:[A-Z_]+$') or\n     string.match(field,'^formatError:[^:]+:[A-Z_]+$') then\n   redis.call('HDEL',telemetry,field)\n  end\n end\n if #fields>0 then\n  redis.call('HSET',telemetry,'attempts',success+warning)\n  for fmt,_ in pairs(formats) do\n   local attempts=(tonumber(redis.call('HGET',telemetry,'format:'..fmt..':success') or '0') or 0)+\n    (tonumber(redis.call('HGET',telemetry,'format:'..fmt..':warning') or '0') or 0)\n   redis.call('HSET',telemetry,'format:'..fmt..':attempts',attempts)\n  end\n end\n redis.call('DEL',legacy)\n if redis.call('EXISTS',incidents)==1 then\n  local old=redis.call('LRANGE',incidents,0,-1)\n  local ttl=redis.call('TTL',incidents)\n  local kept={}\n  for _,raw in ipairs(old) do\n   local ok,item=pcall(cjson.decode,raw)\n   if ok and type(item)=='table' and item.severity=='warning' then\n    kept[#kept+1]=raw\n   else\n    removedIncidents=removedIncidents+1\n   end\n  end\n  redis.call('DEL',incidents)\n  if #kept>0 then\n   redis.call('RPUSH',incidents,unpack(kept))\n   if ttl>0 then redis.call('EXPIRE',incidents,ttl) end\n  end\n end\n local operational=redis.call('HGETALL',obs)\n for j=1,#operational,2 do\n  local field=operational[j]\n  if string.match(field,'^format:[^:]+:category:') or\n    string.match(field,'^service:[^:]+:category:') then\n   removedCategories=removedCategories+(tonumber(operational[j+1]) or 0)\n   redis.call('HDEL',obs,field)\n  end\n end\nend\nremovedAlerts=redis.call('LLEN',KEYS[34])\nredis.call('DEL',KEYS[34],KEYS[33])\nfor fmt,_ in pairs(providers) do\n redis.call('DEL','spc14:provider:'..fmt,\n   'spc14:alert-cooldown:'..fmt..':unresponsive',\n   'spc14:alert-cooldown:'..fmt..':failure_ratio')\nend\nreturn {removedFailures,removedIncidents,removedAlerts,removedCategories}\n";
export async function purgeRetainedErrors(redis){
 if(typeof redis.eval!=="function")throw Error("REDIS_ATOMIC_PURGE_UNSUPPORTED");
 const result=await redis.eval(PURGE_SCRIPT,{keys:errorPurgeKeys(),arguments:[]});
 if(!Array.isArray(result)||result.length!==4||result.some(v=>!Number.isSafeInteger(Number(v))||Number(v)<0))
  throw Error("PURGE_RESULT_INVALID");
 const [removedFailures,removedIncidents,removedAlerts,removedCategories]=result.map(Number);
 const at=new Date().toISOString();
 try{await recordAdminAudit(redis,{scope:"all",at,formatsReset:0,mode:"purge",removedFailures,removedIncidents,removedAlerts});}catch{} // Cleanup must report success even when audit storage fails.
 return {scope:"all",mode:"purge",at,removedFailures,removedIncidents,removedAlerts,
  removedCategories,retentionDays:8,
  note:"Successful decodes and compatibility warnings are preserved. New failures are recorded normally."};
}
const ALERT_SCRIPT="local removed=redis.call('LLEN',KEYS[1])\nredis.call('DEL',KEYS[1])\nreturn removed";
export async function clearOperationalAlerts(redis){
 const result=await redis.eval(ALERT_SCRIPT,{keys:["spc14:alerts"],arguments:[]});
 const removed=Number(result);
 if(!Number.isSafeInteger(removed)||removed<0)throw Error("INVALID_ALERT_COUNT");
 const at=new Date().toISOString();
 try{await recordAdminAudit(redis,{scope:"all",at,formatsReset:0,mode:"clear_alerts",removedAlerts:removed});}catch{} // Redis data was already mutated.
 return {at,removedAlerts:removed};
}

export async function setAlertPause(redis,paused){
 if(typeof paused!=="boolean")throw Error("INVALID_PAUSE");
 const at=new Date().toISOString();
 const until=paused?Date.now()+3600000:null;
 if(paused)await redis.set(ALERT_PAUSE_KEY,String(until),{EX:3600});
 else await redis.del(ALERT_PAUSE_KEY);
 try{await recordAdminAudit(redis,{scope:"all",at,formatsReset:0,
  mode:paused?"pause_alerts":"resume_alerts"});}catch{}
 return {paused,until:until?new Date(until).toISOString():null,at};
}
