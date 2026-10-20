import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {recordIncident,readIncidents,sanitizeDiagnostic,recordOptInInstallation,installationStats} from "../lib/c9-diagnostics.mjs";
class MemoryRedis {
 constructor(){this.records=new Map();this.hll=new Map();}
 async lPush(k,v){this.records.set(k,[v,...(this.records.get(k)||[])]);return this.records.get(k).length;}
 async lTrim(k,start,stop){this.records.set(k,(this.records.get(k)||[]).slice(start,stop+1));}
 async lRange(k,start,stop){return (this.records.get(k)||[]).slice(start,stop+1);}
 async expire(){return true;}
 async pfAdd(k,v){if(!this.hll.has(k))this.hll.set(k,new Set());this.hll.get(k).add(v);return 1;}
 async pfCount(keys){const keysArray=Array.isArray(keys)?keys:[keys];const ids=new Set();
   for(const k of keysArray)for(const value of this.hll.get(k)||[])ids.add(value);
   return ids.size;}
}
test("manual report stores only allowlisted metadata, never uploaded file content",async()=>{
 const redis=new MemoryRedis();
 const id=await recordIncident(redis,{service:"files",format:"hc",code:"DECODE_FAILED",
  appVersion:"1.1.4",source:"user",password:"secret",filename:"private.hc",
  dataBase64:"U0VDUkVU",rawText:"secret"});
 assert.match(id,/^[0-9a-f-]{36}$/);
 const rows=await readIncidents(redis,7);
 assert.equal(rows.length,1);
 assert.equal(rows[0].source,"user");
 assert.equal(rows[0].format,"hc");
 const stored=JSON.stringify([...redis.records]);
 for(const value of ["private.hc","U0VDUkVU","password","rawText","secret"])assert.ok(!stored.includes(value),value);
 assert.equal(sanitizeDiagnostic({service:"bad"}),null);
 const raw=sanitizeDiagnostic({service:"serverVpn",format:"../../internal",code:"bad",bytes:800000});
 assert.equal(raw.format,"other");assert.equal(raw.code,"OTHER_ERROR");
});
test("install counting is opt-in, aggregated and does not persist the raw random ID",async()=>{
 const redis=new MemoryRedis(),key="s".repeat(48),id="ab".repeat(16);
 await recordOptInInstallation(redis,id,key);
 await recordOptInInstallation(redis,id,key);
 await recordOptInInstallation(redis,"cd".repeat(16),key);
 const result=await installationStats(redis);
 assert.equal(result.activeToday,2);
 assert.equal(result.activeLast30Days,2);
 assert.equal(JSON.stringify([...redis.hll]).includes(id),false);
 await assert.rejects(()=>recordOptInInstallation(redis,"android-hwid",key),/INVALID_INSTALL_ID/);
});
test("native JNI, settings and UI require explicit user action and support opt-out",()=>{
 const read=path=>readFileSync(new URL("../../"+path,import.meta.url),"utf8");
 const kotlin=read("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDiagnosticsPrivacy.kt");
 const client=read("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt");
 const native=read("android/app/src/main/cpp/spdecode_transport.cpp");
 const main=read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt");
 const app=read("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt");
 assert.match(kotlin,/if\(allowed\)/);assert.match(kotlin,/delete\(INSTALL_ID\)/);
 assert.match(client,/reportFailure/);assert.match(client,/registerOptInActivity/);
 assert.match(native,/\/api\/v1\/telemetry/);
 assert.match(main,/syncOptInUsage/);assert.match(main,/sendCurrentFailureReport/);
 assert.match(app,/canReportError/);assert.match(app,/onReportError/);
 const legal=read("cloud/web/app/public/legal.jsx");
 assert.match(legal,/HyperLogLog/);
});
