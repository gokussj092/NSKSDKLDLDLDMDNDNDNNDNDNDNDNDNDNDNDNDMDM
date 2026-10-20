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

test("public release notes are versioned, localized in every supported language and safe",()=>{
 const config=validateNews(fixture);
 assert.equal(config.version,2);
 assert.equal(config.items.length,3);
 assert.deepEqual(config.items.map(x=>x.id),["ksh-vpn-provider","dtunnel-mod-entry","mkk-hyper-sources"]);
 assert.deepEqual(config.items.map(x=>x.type),["feature","feature","fix"]);
 assert.equal(new Set(config.items.map(x=>x.id)).size,config.items.length);
 const english=localizeNews(config,"en");
 const spanish=localizeNews(config,"es");
 assert.equal(english.items.length,spanish.items.length);
 assert.match(english.title,/SP-DECODE/);
 assert.match(spanish.title,/SP-DECODE/);
 for(const language of ["en","es","ar","fa","fr","id","ru","de","pt-BR"]){
  const translated=localizeNews(config,language);
  assert.equal(translated.locale,language);
  assert.equal(translated.version,2);
  assert.equal(translated.items.length,config.items.length);
  assert.equal(translated.title,config.title[language]);
  assert.equal(translated.subtitle,config.subtitle[language]);
  for(let i=0;i<translated.items.length;i++){
    assert.equal(translated.items[i].title,config.items[i].title[language]);
    assert.equal(translated.items[i].description,config.items[i].description[language]);
  }
 }
 assert.equal(localizeNews(config,"unknown").title,english.title);
 assert(english.items.some(x=>x.title.includes("KSH VPN")));
 assert(english.items.some(x=>x.title.includes("DTunnel Mod")));
 assert(english.items.some(x=>x.title.includes("MKK Hyper VPN")));
 assert(english.items.every(x=>x.title.includes("✅")||x.title.includes("🛠️")));
 assert(!JSON.stringify(english).includes("HTTP Custom"));
 assert(!JSON.stringify(english).includes("HA Tunnel"));
 assert(!JSON.stringify(english).includes("Google Play"));
 assert(!JSON.stringify(english).includes("NUR download URL"));
});
test("one HTTPS version check returns complete text only for new releases",async()=>{
 const first=await route(query());
 assert.equal(first.status,200);
 assert.equal(first.headers.get("Cache-Control"),"no-store");
 const value=await first.json();
 assert.equal(value.version,2);
 assert.equal(value.unchanged,false);
 assert.equal(value.locale,"en");
 assert(Array.isArray(value.items)&&value.items.length===3);
 const same=await (await route(query(2,"es"))).json();
 assert.deepEqual(same,{apiVersion:"v1",version:2,recheckAfterSeconds:1800,unchanged:true});
 const es=(await (await route(query(0,"es"))).json());
 assert.equal(es.locale,"es");
 assert.notEqual(es.title,value.title);
});
test("new server publication does not need an Android versionCode update",async()=>{
 const updated=structuredClone(fixture);
 updated.version=fixture.version+1;
 updated.items=[{id:"fix-api",type:"fix",title:{en:"Cloud processing improvements"},
 description:{en:"Updated error handling in the cloud service."}}];
 const response=await whatsNewRequest(query(fixture.version,"fr"),{source:()=>validateNews(updated)});
 assert.equal(response.status,200);
 const body=await response.json();
 assert.equal(body.version,3);
 assert.equal(body.locale,"fr");
 assert.equal(body.items[0].title,"Cloud processing improvements");
 const envCatalog=loadNews({CLOUD_WHATS_NEW_JSON:JSON.stringify(updated)});
 assert.equal(envCatalog.version,3);
});
test("invalid, oversized and unsafe catalog data fails closed",async()=>{
 for(const invalid of [{knownVersion:-1,locale:"en"},{knownVersion:"0",locale:"en"},
  {knownVersion:0,locale:"en",host:"https://unknown.invalid"},[]]){
  const response=await whatsNewRequest(new Request("https://api.spdecode.xyz/api/v1/whats-new",{
   method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(invalid)}));
  assert.equal(response.status,400);
 }
 for(const text of ["<b>fake</b>","\u0001bad"]){
  const changed=structuredClone(fixture);
  changed.title.en=text;
  assert.throws(()=>validateNews(changed),/INVALID_RELEASE_NOTES/);
 }
 assert.throws(()=>loadNews({CLOUD_WHATS_NEW_JSON:"x".repeat(20000)}));
});
test("Android fetches, caches encrypted, localizes and remembers server news separately from APK version",()=>{
 const client=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt");
 const kotlin=src("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudWhatsNewRepository.kt");
 const activity=src("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt");
 const ui=src("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt");
 const native=src("android/app/src/main/cpp/spdecode_transport.cpp");
 assert.match(client,/suspend fun whatsNew\(/);
 assert.match(kotlin,/ServerVpnSecureCache/);
 assert.match(kotlin,/lastSeen/);
 assert.match(kotlin,/locale/);
 assert.match(activity,/last_seen_cloud_news_version/);
 assert.match(activity,/refreshCloudWhatsNew/);
 assert.match(activity,/cloudWhatsNew=cloudWhatsNew/);
 assert.match(ui,/cloudWhatsNew\.items\.forEach/);
 assert.match(native,/path == "\/api\/v1\/whats-new"/);
 assert.doesNotMatch(JSON.stringify(fixture),/http:\/\//);
});
