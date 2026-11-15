import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {createHash} from "node:crypto";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {catalog,iconFor,CATALOG_VERSION} from "../lib/server-vpn-catalog.mjs";
import {providerIds,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
const fixture=JSON.parse(readFileSync(new URL("../../../analysis/com.litron.udp/11/tests/fixtures/vectors.json",import.meta.url),"utf8"));
const bytes=Buffer.from(fixture.catalog);
function enabled(t){const prior=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";t.after(()=>{if(prior===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=prior;});}
test("Litron Pro has a distinct identity and the supplied APK's exact original icon",t=>{
 enabled(t);const list=catalog().apps,app=list.find(x=>x.id==="litron-pro-vpn"),base=list.find(x=>x.id==="litron-vpn");
 assert(app);assert(base);assert.notEqual(app.name,base.name);assert.equal(app.decodeEnabled,true);assert.ok(list.length>=69);
 assert.ok(CATALOG_VERSION>=77);assert(providerIds().includes(app.id));assert(PUBLIC_PROVIDER_IDS.includes(app.id));
 const icon=iconFor(app.id);assert.equal(icon.bytes.length,165852);assert.equal(icon.bytes.readUInt32BE(16),500);assert.equal(icon.bytes.readUInt32BE(20),500);
 assert.equal(createHash("sha256").update(icon.bytes).digest("hex"),"625e93856e82f750a0a4590537aac184d8c9110a13877c446d2dcff9a043a887");
 assert(!JSON.stringify(app).includes("godtech"));
});
test("Pro broker pins its own fixed source with TLS, DNS and redirect guards",async t=>{
 enabled(t);let address="93.184.216.34",redirect=null,calls=0;
 t.mock.method(dns,"lookup",async host=>{assert.equal(host,"godtechprime.github.io");return [{address,family:4}];});
 t.mock.method(https,"request",(url,options,callback)=>{
  calls++;assert.equal(url.href,"https://godtechprime.github.io/litroproadfix.txt");assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,"TLSv1.2");
  assert.equal(options.method,"GET");assert.equal(options.headers["Accept-Encoding"],"identity");assert.equal(options.headers["User-Agent"],"SP-DECODE/1.0");
  const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
   const res=new EventEmitter();res.resume=()=>{};res.statusCode=redirect?302:200;res.headers=redirect?{location:redirect}:{};
   callback(res);if(!redirect){res.emit("data",bytes);res.emit("end");}
  });return req;
 });
 assert.deepEqual(await downloadVpnCatalog("litron-pro-vpn"),bytes);
 redirect="https://godtechprime.github.io/latestv2ray.txt";await assert.rejects(()=>downloadVpnCatalog("litron-pro-vpn"),{code:"REMOTE_NETWORK_DENIED"});
 redirect=null;address="127.0.0.1";const before=calls;await assert.rejects(()=>downloadVpnCatalog("litron-pro-vpn"),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls,before);
});
test("Pro operator availability and maintenance do not alter base Litron",t=>{
 enabled(t);for(const doc of [catalog({availability:{"litron-pro-vpn":false}}),catalog({methodStates:{"litron-pro-vpn":{maintenance:true}}})]){
  assert.equal(doc.apps.find(x=>x.id==="litron-pro-vpn").decodeEnabled,false);assert.equal(doc.apps.find(x=>x.id==="litron-vpn").decodeEnabled,true);
 }
});
