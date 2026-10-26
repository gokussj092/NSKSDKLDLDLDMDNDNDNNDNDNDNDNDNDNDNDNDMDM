import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {loadNews,validateNews,localizeNews,whatsNewRequest} from "../lib/whats-new.mjs";
import {POST as route} from "../app/api/v1/whats-new/route.js";
const fixture=JSON.parse(readFileSync(new URL("../content/whats-new.json",import.meta.url),"utf8"));
const query=(knownVersion=0,locale="en")=>new Request("https://api.spdecode.xyz/api/v1/whats-new",{
 method:"POST",headers:{"content-type":"application/json"},
 body:JSON.stringify({knownVersion,locale})
});
const src=path=>readFileSync(new URL("../../../"+path,import.meta.url),"utf8");

const locales=["en","es","ar","fa","fr","id","ru","de","pt-BR","tr","vi","hi","ja","it"];
test("v5 notes cover HA, HC Cloud and the 1.1.20 release in all 14 locales",()=>{
 const news=validateNews(fixture);
 assert.equal(news.version,5);
 assert.equal(news.publishedAt,"2026-10-26");
 assert.deepEqual(news.items.map(x=>x.id),[
   "ha-tunnel-plus-v5","http-custom-online-v5","app-update-1120-v5"]);
 assert.deepEqual(news.items.map(x=>x.type),["improvement","feature","support"]);
 assert(readFileSync(new URL("../content/whats-new.json",import.meta.url)).length<=16384);
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
   assert(translated.subtitle.includes("1.1.20"),locale);
   assert(translated.items[0].description.includes(".hat"),locale);
   assert(translated.items[1].description.includes("hccloud://"),locale);
   assert(translated.items[2].description.includes("1.1.20"),locale);
   assert(translated.items[2].description.includes("https://t.me/GhostDeve/377"),locale);
   assert(translated.items[2].description.includes("Google Play Store"),locale);
 }
 assert.equal(localizeNews(news,"unknown").title,news.title.en);
 assert(!JSON.stringify(news).includes("Password:"));
 assert(!JSON.stringify(news).includes("<a "));
});

test("v4 readers receive v5 once and v5 snapshots remain unchanged",async()=>{
 const response=await route(query(4,"es"));
 assert.equal(response.status,200);
 assert.equal(response.headers.get("Cache-Control"),"no-store");
 const body=await response.json();
 assert.equal(body.unchanged,false);
 assert.equal(body.version,5);
 assert.equal(body.locale,"es");
 assert.equal(body.items.length,3);
 const same=await (await route(query(5,"es"))).json();
 assert.deepEqual(same,{apiVersion:"v1",version:5,recheckAfterSeconds:1800,unchanged:true});
 for(const locale of locales){
   const response=await route(query(4,locale));
   assert.equal(response.status,200);
   const doc=await response.json();
   assert.equal(doc.locale,locale);
   assert.equal(doc.title,fixture.title[locale]);
 }
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
 assert.match(native,/path == "\/api\/v1\/whats-new"/);
 assert.doesNotMatch(JSON.stringify(fixture),/http:\/\//);
});
