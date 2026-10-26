import {test} from "node:test";
import assert from "node:assert/strict";
import {randomBytes,scryptSync} from "node:crypto";
import {errorPurgeKeys,purgeRetainedErrors,clearOperationalAlerts,setAlertPause} from "../lib/c15-admin-operations.mjs";
import {purgeErrorsRequest,clearAlertsRequest,pauseAlertsRequest} from "../lib/c6-admin-api.mjs";
import {adminLogin} from "../lib/c6-admin-auth.mjs";

class ActionRedis {
 constructor(){this.calls=[];this.strings=new Map();this.events=[];}
 async get(key){return this.strings.get(key)||null;}
 async del(key){return this.strings.delete(key)?1:0;}
 async set(key,value,opts={}){if(opts.NX&&this.strings.has(key))return null;this.strings.set(key,value);return "OK";}
 async expire(){return 1;}
 async lPush(key,value){this.events.push({key,value:JSON.parse(value)});return this.events.length;}
 async lTrim(){return 1;}
 async eval(script,options){
  this.calls.push({script,options});
  if(options.keys.length===34)return [4,3,2,6];
  if(options.keys.length===1)return 2;
  throw Error("UNEXPECTED_KEYS");
 }
}
test("purge is bounded to eight UTC days and fixed owned Redis key families",()=>{
 const keys=errorPurgeKeys();
 assert.equal(keys.length,34);
 assert.equal(new Set(keys).size,34);
 assert.deepEqual(keys.slice(-2),["spc6:error-baselines","spc14:alerts"]);
 for(let i=0;i<32;i+=4){
  assert.match(keys[i],/^spc6:telemetry:\d{4}-\d\d-\d\d$/);
  assert.match(keys[i+1],/^spc6:metrics:\d{4}-\d\d-\d\d:failed$/);
  assert.match(keys[i+2],/^spc9:incidents:\d{4}-\d\d-\d\d$/);
  assert.match(keys[i+3],/^spc14:obs:\d{4}-\d\d-\d\d$/);
 }
 assert.doesNotMatch(keys.join(" "),/session|install|provider-controls|password|secret/);
});
test("atomic purge targets failure counters while preserving success and warning fields",async()=>{
 const redis=new ActionRedis();
 const result=await purgeRetainedErrors(redis);
 assert.equal(result.removedFailures,4);
 assert.equal(result.removedIncidents,3);
 assert.equal(result.removedAlerts,2);
 assert.equal(result.removedCategories,6);
 assert.equal(result.retentionDays,8);
 assert.equal(redis.calls.length,1);
 const lua=redis.calls[0].script;
 for(const requirement of [
  "HGETALL","HDEL","redis.call('DEL',legacy)",
  "success+warning","'warning'","spc14:provider:",
  "spc14:alert-cooldown:","removedFailures","KEYS[34]","KEYS[33]"
 ])assert.ok(lua.includes(requirement),requirement);
 assert.ok(!lua.includes("spc9:install:"),"install stats must survive");
 assert.ok(!lua.includes("spc6:maintenance"),"maintenance must survive");
 assert.equal(redis.events[0].value.action,"purge_errors");
});
test("clear-alert action does not change other data families",async()=>{
 const redis=new ActionRedis();
 const result=await clearOperationalAlerts(redis);
 assert.equal(result.removedAlerts,2);
 assert.deepEqual(redis.calls[0].options.keys,["spc14:alerts"]);
 assert.equal(redis.events[0].value.action,"clear_alerts");
});
test("alert pause changes Redis state but not decoder counters, with an automatic TTL",async()=>{
 const redis=new ActionRedis();
 const on=await setAlertPause(redis,true);
 assert.equal(on.paused,true);
 assert.ok(on.until);
 assert.ok(redis.strings.get("spc14:alerts:pause-until"));
 const off=await setAlertPause(redis,false);
 assert.equal(off.paused,false);
 assert.equal(redis.strings.has("spc14:alerts:pause-until"),false);
 assert.deepEqual(redis.events.map(e=>e.value.action),["pause_alerts","resume_alerts"]);
});
test("destructive routes enforce session, CSRF and exact typed confirmation",async()=>{
 const salt=randomBytes(16),password="operator-safety-strong-password";
 Object.assign(process.env,{
  CLOUD_ADMIN_ENABLED:"true",CLOUD_TRUST_PROXY:"true",
  CLOUD_ADMIN_USERNAME:"operator",
  CLOUD_ADMIN_PASSWORD_SCRYPT:"scrypt$16384$8$1$"+salt.toString("hex")+"$"+
   scryptSync(password,salt,64,{N:16384,r:8,p:1,maxmem:32*1024*1024}).toString("hex"),
  CLOUD_ADMIN_SESSION_KEY:"h".repeat(64),
  CLOUD_ADMIN_PUBLIC_ORIGIN:"https://panel.example.test",
  CLOUD_REDIS_URL:"redis://redis:6379",
 });
 const redis=new ActionRedis(),options={storeProvider:async()=>redis};
 const origin="https://panel.example.test";
 const login=await adminLogin(redis,new Request(origin+"/api/admin/login",{
  method:"POST",headers:{Origin:origin,"X-SPDecode-Admin-Action":"1","Content-Type":"application/json"}
 }),"operator",password);
 assert.ok(login.token);
 const cookie="spdecode_admin_session="+login.token;
 const make=(url,body,authenticated=true,csrf=true,requestOrigin=origin)=>new Request(origin+url,{
  method:"POST",
  headers:{
   Origin:requestOrigin,"X-SPDecode-Admin-Action":csrf?"1":"0",
   "Content-Type":"application/json",...(authenticated?{Cookie:cookie}:{})
  },body:JSON.stringify(body)
 });
 const purge="/api/admin/errors/purge",clear="/api/admin/alerts/clear";
 const body={scope:"all",confirmation:"PURGAR_ERRORES"};
 assert.equal((await purgeErrorsRequest(make(purge,body,false),options)).status,401);
 assert.equal((await purgeErrorsRequest(make(purge,body,true,false),options)).status,403);
 assert.equal((await purgeErrorsRequest(make(purge,body,true,true,"https://evil.invalid"),options)).status,403);
 assert.equal((await purgeErrorsRequest(make(purge,{scope:"all",confirmation:"BORRAR"}),options)).status,400);
 assert.equal((await purgeErrorsRequest(make(purge,{scope:"format",format:"hc",confirmation:"PURGAR_ERRORES"}),options)).status,400);
 const ok=await purgeErrorsRequest(make(purge,body),options);
 assert.equal(ok.status,200);
 assert.equal((await ok.json()).purge.removedFailures,4);
 assert.equal((await clearAlertsRequest(make(clear,{confirmation:"NO"}),options)).status,400);
 assert.equal((await clearAlertsRequest(make(clear,{confirmation:"VACIAR_ALERTAS"},false),options)).status,401);
 const cleared=await clearAlertsRequest(make(clear,{confirmation:"VACIAR_ALERTAS"}),options);
 assert.equal(cleared.status,200);
 assert.equal((await cleared.json()).cleared.removedAlerts,2);
 assert.equal((await pauseAlertsRequest(make("/api/admin/alerts/pause",{paused:"true"}),options)).status,400);
 assert.equal((await pauseAlertsRequest(make("/api/admin/alerts/pause",{paused:true},false),options)).status,401);
 const paused=await pauseAlertsRequest(make("/api/admin/alerts/pause",{paused:true}),options);
 assert.equal(paused.status,200);
 assert.equal((await paused.json()).alerts.paused,true);
 assert.equal(redis.calls.length,2);
});
