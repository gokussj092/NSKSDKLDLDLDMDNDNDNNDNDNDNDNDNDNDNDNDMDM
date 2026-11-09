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
const fixture=JSON.parse(readFileSync(new URL("../../../analysis/com.fleet.vpn/25/tests/fixtures/vectors.json",import.meta.url),"utf8"));
const bytes=Buffer.from(fixture.catalog);
function enabled(t){const prior=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";t.after(()=>{if(prior===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=prior;});}
test("base LITRON is registered once with the owner's exact icon and no Pro alias",t=>{
 enabled(t);const list=catalog().apps,app=list.find(x=>x.id==="litron-vpn");
 assert(app);assert.equal(app.name,"LITRON VPN");assert.equal(app.decodeEnabled,true);assert.ok(list.length>=68);
 assert.ok(CATALOG_VERSION>=76);assert(providerIds().includes(app.id));assert(PUBLIC_PROVIDER_IDS.includes(app.id));
 assert(!providerIds().includes("litron-pro-vpn"));assert(!list.some(x=>/litron.*pro/i.test(x.name)));
 const icon=iconFor(app.id);assert.equal(icon.bytes.length,86055);assert.equal(icon.bytes.readUInt32BE(16),288);assert.equal(icon.bytes.readUInt32BE(20),288);
 assert.equal(createHash("sha256").update(icon.bytes).digest("hex"),"38a931316e6ea65793f377eccd66924790a3ff273d250d8955b6b48a7867aae0");
 assert(!JSON.stringify(app).includes("godtech"));
});
test("real broker pins Litron DNS/TLS and preserves all carrier whitespace bytes",async t=>{
 enabled(t);let address="93.184.216.34",redirect=null,calls=0;
 t.mock.method(dns,"lookup",async host=>{assert.equal(host,"godtechprime.github.io");return [{address,family:4}];});
 t.mock.method(https,"request",(url,options,callback)=>{
  calls++;assert.equal(url.href,"https://godtechprime.github.io/latestv2ray.txt");assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,"TLSv1.2");
  assert.equal(options.method,"GET");assert.equal(options.headers["Accept-Encoding"],"identity");
  const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
   const res=new EventEmitter();res.resume=()=>{};res.statusCode=redirect?302:200;res.headers=redirect?{location:redirect}:{};
   callback(res);if(!redirect){res.emit("data",bytes);res.emit("end");}
  });return req;
 });
 assert(fixture.catalog[0].trim()==="");assert.deepEqual(await downloadVpnCatalog("litron-vpn"),bytes);
 redirect="https://other.invalid/catalog";await assert.rejects(()=>downloadVpnCatalog("litron-vpn"),{code:"REMOTE_NETWORK_DENIED"});
 redirect=null;address="127.0.0.1";const before=calls;await assert.rejects(()=>downloadVpnCatalog("litron-vpn"),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls,before);
});
test("Litron operator switches and maintenance remain effective",t=>{
 enabled(t);assert.equal(catalog({availability:{"litron-vpn":false}}).apps.find(x=>x.id==="litron-vpn").decodeEnabled,false);
 assert.equal(catalog({methodStates:{"litron-vpn":{maintenance:true}}}).apps.find(x=>x.id==="litron-vpn").decodeEnabled,false);
});
