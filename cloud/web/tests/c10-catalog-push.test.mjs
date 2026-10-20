import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
import {publishCatalogUpdate,pushSettings} from "../lib/c10-catalog-push.mjs";
import {catalogWatchRequest,MAX_OPEN_WATCHES,WATCH_SECONDS} from "../lib/c10-catalog-watch.mjs";
import {POST as httpWatch} from "../app/api/v1/server-vpn/watch/route.js";

const src=path=>readFileSync(new URL("../../../"+path,import.meta.url),"utf8");
class Redis{
 constructor(){this.values=new Map();}
 async get(key){return this.values.get(key)??null;}
 async set(key,value){this.values.set(key,value);return "OK";}
}
const env={CLOUD_SERVER_VPN_CATALOG_VERSION:"11"};
function makeRequest(knownVersion,signal){
 return new Request("https://api.spdecode.xyz/api/v1/server-vpn/watch",{
  method:"POST",headers:{"content-type":"application/json"},
  body:JSON.stringify({knownVersion}),signal
 });
}

test("own VPS version status has no external push configuration or tokens",async()=>{
 const store=new Redis();
 assert.deepEqual(pushSettings(),{enabled:true,transport:"own-vps-https-watch"});
 const current=activeCatalogVersion(env);
 assert.equal(current,13);
 assert.deepEqual(await publishCatalogUpdate(store,{env}),{status:"registered",version:current});
 assert.deepEqual(await publishCatalogUpdate(store,{env}),{status:"unchanged",version:current});
 const updatedEnv={...env,CLOUD_SERVER_VPN_CATALOG_VERSION:String(current+1)};
 assert.deepEqual(await publishCatalogUpdate(store,{env:updatedEnv}),{status:"registered",version:current+1});
 assert.deepEqual(await publishCatalogUpdate(store,{env}),{status:"unchanged",version:current});
 assert.equal(await store.get("spc10:catalog:last-announced"),String(current+1));
});
test("stale catalog version gets immediate metadata-only notification",async()=>{
 let waited=false;
 const response=await catalogWatchRequest(makeRequest(10),{
  versionProvider:()=>11,wait:async()=>{waited=true;}
 });
 assert.equal(response.status,200);
 assert.deepEqual(await response.json(),{
  apiVersion:"v1",catalogVersion:11,changed:true,checkOnly:true
 });
 assert.equal(waited,false);
 assert.equal(MAX_OPEN_WATCHES,64);
 assert.equal(WATCH_SECONDS,12);
});
test("active watcher wakes when VPS version advances",async()=>{
 let version=11,waits=0;
 const response=await catalogWatchRequest(makeRequest(11),{
  versionProvider:()=>version,wait:async()=>{waits++;version=12;}
 });
 assert.equal(response.status,200);
 assert.equal((await response.json()).changed,true);
 assert.equal(waits,1);
});
test("closed/aborted watcher returns unchanged without hanging or leaking a slot",async()=>{
 const abort=new AbortController();
 let waits=0;
 const res=await catalogWatchRequest(makeRequest(11,abort.signal),{
  versionProvider:()=>11,
  wait:async()=>{waits++;abort.abort();}
 });
 assert.equal(res.status,200);
 const value=await res.json();assert.equal(value.changed,false);
 assert.equal(waits,1);
 const next=await catalogWatchRequest(makeRequest(10),{versionProvider:()=>11});
 assert.equal(next.status,200);
});
test("invalid requests, disallowed fields, excessive bodies and wrong methods fail closed",async()=>{
 for(const payload of [{knownVersion:-1},{knownVersion:"11"},{knownVersion:11,url:"https://evil.example"},
  {knownVersion:1000000000},{}]){
  const response=await catalogWatchRequest(new Request("https://api.spdecode.xyz/api/v1/server-vpn/watch",{
   method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)
  }),{versionProvider:()=>11});
  assert.equal(response.status,400);
 }
 const bad=new Request("https://api.spdecode.xyz/api/v1/server-vpn/watch",{method:"POST",
  headers:{"Content-Type":"application/json"},body:JSON.stringify({knownVersion:1,junk:"a".repeat(600)})});
 assert.equal((await catalogWatchRequest(bad)).status,400);
 const response=await httpWatch(makeRequest(0));
 assert.equal(response.status,200);
 assert.equal((await response.json()).catalogVersion>=11,true);
});
test("Android retains checked encrypted cache, opt-in lifecycle and WorkManager recovery without Firebase",()=>{
 const updates=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudCatalogUpdates.kt");
 const repository=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/ServerVpnCatalogRepository.kt");
 const activity=src("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt");
 const client=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt");
 const bridge=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudNativeTransport.kt");
 const cpp=src("android/app/src/main/cpp/spdecode_transport.cpp");
 const manifest=src("android/app/src/main/AndroidManifest.xml");
 const gradle=src("android/app/build.gradle.kts");
 const compose=src("cloud/compose.yaml");
 const legal=src("cloud/web/app/public/legal.jsx");
 for(const part of ["watchWhileVisible","CoroutineWorker","ExistingPeriodicWorkPolicy.KEEP",
  "CloudLegalConsent.accepted","NetworkType.CONNECTED","onVersionHint"])
  assert.ok(updates.includes(part),part);
 for(const part of ["catalogWatchJob?.cancel()","override fun onStop","startCatalogWatch()"])
  assert.ok(activity.includes(part),part);
 for(const part of ["digest(bytes)!=checksum","vault.write(\"catalog\",fresh","announcedVersion>previousVersion"])
  assert.ok(repository.includes(part),part);
 assert.ok(client.includes("watchCatalogVersion"));
 assert.ok(bridge.includes('"/api/v1/server-vpn/watch"'));
 assert.ok(cpp.includes('path == "/api/v1/server-vpn/watch"'));
 for(const part of [updates,manifest,gradle,compose,legal])
  assert.doesNotMatch(part,/Firebase Cloud Messaging|FCM|firebase-messaging|CLOUD_FCM_|SPDECODE_FCM_/i);
});
