import test from "node:test";
import assert from "node:assert/strict";
import {publicTextFormats,validatePublicTextFormats}
 from "../lib/text-format-catalog.mjs";
import {catalog,CATALOG_VERSION} from "../lib/server-vpn-catalog.mjs";
import {androidUpdateHint} from "../lib/whats-new.mjs";

test("Cloud catalog advertises bounded file, text and online reference formats",()=>{
 const formats=publicTextFormats();
 const published=catalog();
 assert.equal(CATALOG_VERSION,67); // Current file-format catalog floor includes .hexcm
 assert.equal(published.textSchemaVersion,1);
 assert.equal(published.textCount,formats.length);
 assert.deepEqual(published.textFormats,formats);
 assert(formats.length>=40);
 assert(formats.some(x=>x.prefix==="mnrtunneludp://" && x.kind==="cloud"));
 assert(formats.some(x=>x.prefix==="bdnet://"));
 assert(formats.some(x=>x.prefix==="hccloud://" && x.suffix==="hc" && x.kind==="cloud"));
 for(const prefix of ["xhypher://","xhyphertunnelpro://"])
   assert(formats.some(x=>x.prefix===prefix && x.suffix==="xhypher" && x.kind==="text"));
 assert(formats.some(x=>x.prefix==="npvt-vless://"));
 for(const prefix of ["dark://","darktunnel://","dtunnel://","dt://"])
   assert(formats.some(x=>x.prefix===prefix && x.suffix==="dark" &&
     x.name==="Dark Tunnel" && x.kind==="text"));
 assert(formats.every(x=>!("url" in x)&&!("route" in x)&&!("key" in x)));
 assert.equal(new Set(formats.map(x=>x.prefix.toLowerCase())).size,formats.length);
 assert.equal(published.formats.length,256);
});

test("Untrusted catalog cannot select worker modules, URLs, scripts or duplicate prefixes",()=>{
 const safe=publicTextFormats().slice(0,3).map(x=>({...x}));
 for(const malicious of [
  {prefix:"https://attacker.invalid/",name:"Evil",suffix:"evil",kind:"cloud"},
  {prefix:"../evil",name:"Evil",suffix:"evil",kind:"cloud"},
  {prefix:"../evil/",name:"Evil",suffix:"evil",kind:"text"},
  {prefix:"evil://../secret",name:"Evil",suffix:"evil",kind:"text"},
  {prefix:"evil.com",name:"Evil",suffix:"evil",kind:"text"},
  {prefix:"evil://a.b",name:"Evil",suffix:"evil",kind:"cloud"},
  {...safe[0],worker:"../secrets.py"},
  {...safe[0],prefix:safe[1].prefix},
  {...safe[0],kind:"network"},
 ]) {
  assert.throws(()=>validatePublicTextFormats({schemaVersion:1,formats:[...safe,malicious]}));
 }
});

test("App-update hint has no arbitrary link or release when not configured",()=>{
 assert.equal(androidUpdateHint({}),null);
 assert.deepEqual(androidUpdateHint({
  CLOUD_ANDROID_LATEST_VERSION_CODE:"31",
  CLOUD_ANDROID_LATEST_VERSION_NAME:"1.1.20",
 }),{versionCode:31,versionName:"1.1.20"});
 for(const code of ["-1","31.0","00031","1000000000"])assert.throws(()=>
  androidUpdateHint({CLOUD_ANDROID_LATEST_VERSION_CODE:code,
   CLOUD_ANDROID_LATEST_VERSION_NAME:"1.1.20"}));
 assert.throws(()=>androidUpdateHint({
  CLOUD_ANDROID_LATEST_VERSION_CODE:"31",
  CLOUD_ANDROID_LATEST_VERSION_NAME:"https://example.com"}));
});
