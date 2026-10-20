import {test} from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync} from "node:crypto";
import {readFileSync} from "node:fs";
import {publishCatalogUpdate,pushSettings,catalogTopic} from "../lib/c10-catalog-push.mjs";
import {activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
const keyPair=generateKeyPairSync("rsa",{modulusLength:2048});
const key=keyPair.privateKey.export({type:"pkcs8",format:"pem"});
const env={
 CLOUD_FCM_ENABLED:"true",
 CLOUD_FCM_PROJECT_ID:"spdecode-test-push",
 CLOUD_FCM_SERVICE_ACCOUNT_JSON:JSON.stringify({
  type:"service_account",project_id:"spdecode-test-push",
  client_email:"spdecode@spdecode-test-push.iam.gserviceaccount.com",
  private_key:key
 }),
 CLOUD_SERVER_VPN_CATALOG_VERSION:"11"
};
class Redis{
 constructor(){this.map=new Map();}
 async get(k){return this.map.get(k)??null;}
 async set(k,v,{NX}={}){if(NX&&this.map.has(k))return null;this.map.set(k,v);return "OK";}
 async del(k){this.map.delete(k);return 1;}
}
test("FCM transport is strictly disabled by default and never uses a public secret",()=>{
 assert.equal(pushSettings({}).enabled,false);
 assert.equal(pushSettings({...env,CLOUD_FCM_ENABLED:"false"}).enabled,false);
 assert.equal(pushSettings({...env,CLOUD_FCM_PROJECT_ID:"../../local"}).enabled,false);
 assert.equal(catalogTopic,"spdecode-vpn-catalog");
 assert.equal(activeCatalogVersion(env),11);
});
test("new catalog version results in one strictly bounded topic message, not one message per user",async()=>{
 const redis=new Redis(),calls=[];
 const fetchImpl=async(url,args)=>{
  calls.push({url,body:args.body});
  if(url.endsWith("/token"))return {ok:true,json:async()=>({access_token:"a".repeat(48)})};
  return {ok:true,json:async()=>({name:"projects/test/messages/x"})};
 };
 const a=await publishCatalogUpdate(redis,{env,fetchImpl});
 assert.deepEqual(a,{status:"published",version:11});
 const last=calls[1];
 assert.match(last.url,/^https:\/\/fcm.googleapis.com\/v1\/projects\/spdecode-test-push\/messages:send$/);
 const msg=JSON.parse(last.body);
 assert.equal(msg.message.topic,catalogTopic);
 assert.deepEqual(msg.message.data,{type:"catalog_update",catalogVersion:"11"});
 assert.equal(JSON.stringify(msg).includes("private_key"),false);
 assert.equal(JSON.stringify(msg).includes("password"),false);
 assert.deepEqual(await publishCatalogUpdate(redis,{env,fetchImpl}),{status:"unchanged",version:11});
 assert.equal(calls.length,2);
 assert.deepEqual(await publishCatalogUpdate(redis,{env:{...env,CLOUD_SERVER_VPN_CATALOG_VERSION:"12"},fetchImpl}),
  {status:"published",version:12});
 assert.equal(calls.length,4);
 assert.deepEqual(await publishCatalogUpdate(redis,{env,fetchImpl}),{status:"unchanged",version:11});
});
test("failed FCM delivery does not advance watermark; next attempt retries",async()=>{
 const redis=new Redis();let tries=0;
 const fetchImpl=async(url)=>url.endsWith("/token")?
  {ok:true,json:async()=>({access_token:"a".repeat(48)})}:
  (++tries===1?{ok:false}:{ok:true});
 await assert.rejects(()=>publishCatalogUpdate(redis,{env,fetchImpl}),/FCM_SEND_FAILED/);
 assert.equal(await redis.get("spc10:catalog:last-announced"),null);
 assert.equal(await redis.get("spc10:catalog:notify-lock"),null);
 assert.equal((await publishCatalogUpdate(redis,{env,fetchImpl})).status,"published");
 assert.equal(tries,2);
});
test("busy lock deduplicates competing publishers",async()=>{
 const redis=new Redis();
 await redis.set("spc10:catalog:notify-lock","other",{NX:true});
 const result=await publishCatalogUpdate(redis,{env,fetchImpl:()=>{throw Error("must not call");}});
 assert.equal(result.status,"busy");
 assert.equal(await redis.get("spc10:catalog:notify-lock"),"other");
});
test("Android background push is opt-in and always revalidates via HTTPS and digest before activation",()=>{
 const src=file=>readFileSync(new URL("../../../"+file,import.meta.url),"utf8");
 const android=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudCatalogUpdates.kt");
 const repo=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/ServerVpnCatalogRepository.kt");
 const app=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudNativeTransport.kt");
 const manifest=src("android/app/src/main/AndroidManifest.xml");
 for(const phrase of ["FirebaseMessagingService","CoroutineWorker","ExistingPeriodicWorkPolicy.KEEP",
  "ExistingWorkPolicy.REPLACE","CloudLegalConsent.accepted","deleteToken","catalogVersion",
  "NetworkType.CONNECTED"])assert.ok(android.includes(phrase),phrase);
 assert.match(repo,/announcedVersion>previousVersion/);
 assert.match(repo,/digest\(bytes\)!=checksum/);
 assert.match(repo,/vault\.write\("catalog",fresh/);
 assert.match(app,/\/api\/v1\/server-vpn\/catalog/);
 assert.match(manifest,/firebase_messaging_auto_init_enabled/);
 assert.match(manifest,/android:value="false"/);
 assert.doesNotMatch(android,/http:\/\//);
});
