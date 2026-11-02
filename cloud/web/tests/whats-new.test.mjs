import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {loadNews,loadV1News,validateNews,localizeNews,whatsNewRequest} from "../lib/whats-new.mjs";
import {bindVerifiedRequest} from "../lib/v2-bound-request.mjs";
import {POST as route} from "../app/api/v1/whats-new/route.js";
const fixture=JSON.parse(readFileSync(new URL("../content/whats-new.json",import.meta.url),"utf8"));
const v1Fixture=JSON.parse(readFileSync(new URL("../content/whats-new-v1.json",import.meta.url),"utf8"));
const query=(knownVersion=0,locale="en")=>new Request("https://api.spdecode.xyz/api/v1/whats-new",{
 method:"POST",headers:{"content-type":"application/json"},
 body:JSON.stringify({knownVersion,locale})
});
const src=path=>readFileSync(new URL("../../../"+path,import.meta.url),"utf8");

const locales=["en","es","ar","fa","fr","id","ru","de","pt-BR","tr","vi","hi","ja","it"];
test("V2 v8 news excludes Speicers while preserving other updates in 14 locales",()=>{
 const news=validateNews(fixture);
 assert.equal(news.version,8);
 assert.equal(news.publishedAt,"2026-11-01");
 assert.deepEqual(news.items.map(x=>x.id),[
  "new-server-vpn-apps-v7","ha-tunnel-plus-v7","mm-tunnel-v7"]);
 assert.deepEqual(news.items.map(x=>x.type),["feature","improvement","fix"]);
 assert(Buffer.byteLength(readFileSync(new URL("../content/whats-new.json",import.meta.url)))<=16384);
 assert.deepEqual(Object.keys(news.subtitle).sort(),[...locales].sort());
 for(const locale of locales){
  const translated=localizeNews(news,locale);
  assert.equal(translated.locale,locale);
  assert.equal(translated.title,news.title[locale]);
  assert.equal(translated.subtitle,news.subtitle[locale]);
  assert.equal(translated.items.length,3);
  translated.items.forEach((item,i)=>{
   assert.equal(item.title,news.items[i].title[locale]);
   assert.equal(item.description,news.items[i].description[locale]);
  });
  assert(translated.items[0].description.includes(".enaa"),locale);
  assert(translated.items[1].description.includes(".hat"),locale);
  assert(!translated.subtitle.includes("Speicers"),locale);
  assert(!JSON.stringify(translated).includes("Speicers"),locale);
 }
 assert.equal(localizeNews(news,"unknown").title,news.title.en);
 assert(!JSON.stringify(news).includes("update-1125-v1"));
 assert(!JSON.stringify(news).includes("<a "));
});

test("V1-only v6 notice covers all 14 locales, update, Play status and tester contact",async()=>{
 const catalog=validateNews(v1Fixture);
 assert.equal(catalog.version,6);
 assert.equal(catalog.publishedAt,"2026-10-31");
 assert.deepEqual(catalog.items.map(x=>x.id),
  ["update-1125-v1","google-play-1125-pending-v1","join-play-testers-v1"]);
 assert.deepEqual(catalog.items.map(x=>x.type),["support","support","support"]);
 assert(Buffer.byteLength(readFileSync(new URL("../content/whats-new-v1.json",import.meta.url)))<=16384);
 assert.deepEqual(Object.keys(catalog.title).sort(),[...locales].sort());
 for(const locale of locales){
  assert(catalog.subtitle[locale].includes("1.1.25"),locale);
  assert(catalog.items[0].title[locale].includes("1.1.25"),locale);
  assert(catalog.items[0].description[locale].includes("https://t.me/GhostDeve"),locale);
  assert(catalog.items[1].description[locale].includes("Google Play"),locale);
  assert(catalog.items[2].description[locale].includes("Ghost Developer"),locale);
  assert(catalog.items[2].description[locale].includes("https://t.me/Gh0stDeveloper"),locale);
  const response=await route(query(5,locale));
  assert.equal(response.status,200);
  assert.equal(response.headers.get("Cache-Control"),"no-store");
  const data=await response.json();
  assert.equal(data.unchanged,false);
  assert.equal(data.version,6);
  assert.equal(data.locale,locale);
  assert.equal(data.title,catalog.title[locale]);
  assert.equal(data.items.length,3);
  assert.equal(data.items[0].description,catalog.items[0].description[locale]);
 }
 const unchanged=await (await route(query(6,"es"))).json();
 assert.deepEqual(unchanged,{apiVersion:"v1",version:6,recheckAfterSeconds:1800,unchanged:true});
 assert.equal((await (await route(query(4,"es"))).json()).version,6);
});
test("authenticated V2 operation 14 never receives the V1 mandatory update",async()=>{
 const direct=query(0,"es");
 const userSpoof=new Request(direct,{headers:{
  "content-type":"application/json","x-spdecode-api-version":"v2",
  "x-spdecode-v2-authenticated":"true"
 }});
 const directBody=await (await whatsNewRequest(userSpoof)).json();
 assert.equal(directBody.version,6);
 assert(directBody.items.some(x=>x.id==="update-1125-v1"));
 const signed=query(0,"es");
 bindVerifiedRequest(signed,{aud:"spdecode-android-v2",versionCode:40});
 const signedBody=await (await whatsNewRequest(signed)).json();
 assert.equal(signedBody.version,8);
 assert.deepEqual(signedBody.items.map(x=>x.id),fixture.items.map(x=>x.id));
 assert(!JSON.stringify(signedBody).includes("update-1125-v1"));
 assert(!JSON.stringify(signedBody).includes("join-play-testers-v1"));
 const v2Unchanged=query(8,"es");
 bindVerifiedRequest(v2Unchanged,{aud:"spdecode-android-v2",versionCode:40});
 const oldBody=await (await whatsNewRequest(v2Unchanged)).json();
 assert.deepEqual(oldBody,{apiVersion:"v1",version:8,recheckAfterSeconds:1800,unchanged:true});
});
test("V1 and V2 editorial override environments are independently scoped",()=>{
 assert.equal(loadV1News().version,6);
 assert.equal(loadNews().version,8);
 assert.equal(loadV1News({CLOUD_WHATS_NEW_JSON:JSON.stringify(fixture)}).version,6);
 assert.equal(loadNews({CLOUD_WHATS_NEW_V1_JSON:JSON.stringify(v1Fixture)}).version,8);
 assert.equal(loadV1News({CLOUD_WHATS_NEW_V1_JSON:JSON.stringify(fixture)}).version,8);
 assert.equal(loadNews({CLOUD_WHATS_NEW_JSON:JSON.stringify(v1Fixture)}).version,6);
});
test("server publication is independent of Android versionCode",async()=>{
 const next=structuredClone(fixture);
 next.version=fixture.version+1;
 next.items=[{id:"fix-api",type:"fix",title:{en:"Cloud processing improvements"},
 description:{en:"Updated error handling in the cloud service."}}];
 const response=await whatsNewRequest(query(fixture.version,"fr"),{source:()=>validateNews(next)});
 assert.equal(response.status,200);
 const body=await response.json();
 assert.equal(body.version,next.version);
 assert.equal(body.locale,"fr");
 assert.equal(body.items[0].title,"Cloud processing improvements");
 assert.equal(loadNews({CLOUD_WHATS_NEW_JSON:JSON.stringify(next)}).version,next.version);
});
test("invalid controls, unsafe HTML and oversized data fail closed; list newlines are safe",async()=>{
 for(const invalid of [{knownVersion:-1,locale:"en"},{knownVersion:"0",locale:"en"},
  {knownVersion:0,locale:"en",host:"https://unknown.invalid"},[]]){
  const response=await whatsNewRequest(new Request("https://api.spdecode.xyz/api/v1/whats-new",{
   method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(invalid)}));
  assert.equal(response.status,400);
 }
 for(const bad of ["<b>fake</b>","\u0001bad","invalid\rinput"]){
  const changed=structuredClone(fixture);
  changed.items[0].description.en=bad;
  assert.throws(()=>validateNews(changed),/INVALID_RELEASE_NOTES/);
 }
 const unsafeTitle=structuredClone(fixture);
 unsafeTitle.title.en="Header\nnew line";
 assert.throws(()=>validateNews(unsafeTitle),/INVALID_RELEASE_NOTES/);
 const oversized=structuredClone(fixture);
 oversized.items[0].description.en="a".repeat(321);
 assert.throws(()=>validateNews(oversized),/INVALID_RELEASE_NOTES/);
 assert.throws(()=>loadNews({CLOUD_WHATS_NEW_JSON:"x".repeat(20000)}));
});
test("Android caches, localizes 14 supported languages and records seen news separately from APK version",()=>{
 const client=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt");
 const kotlin=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudWhatsNewRepository.kt");
 const activity=src("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt");
 const ui=src("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt");
 const native=src("android/app/src/main/cpp/spdecode_transport.cpp");
 assert.match(client,/suspend fun whatsNew\(/);
 assert.match(kotlin,/ServerVpnSecureCache/);
 assert.match(kotlin,/lastSeen/);
 assert.match(kotlin,/locale/);
 const supported=kotlin.match(/private val supported=setOf\(([^)]*)\)/s)?.[1];
 assert(supported);
 for(const locale of locales) assert(supported.includes('"'+locale+'"'),locale);
 assert.match(activity,/last_seen_cloud_news_version/);
 assert.match(activity,/refreshCloudWhatsNew/);
 assert.match(activity,/cloudWhatsNew=cloudWhatsNew/);
 assert.match(ui,/cloudWhatsNew\.items\.forEach/);
 assert.match(ui,/verticalScroll\(rememberScrollState\(\)\)/);
 assert.match(client,/CloudOperation\.WHATS_NEW/);
 assert.match(native,/safeOperation/);
 assert.doesNotMatch(JSON.stringify(fixture),/http:\/\//);
});
