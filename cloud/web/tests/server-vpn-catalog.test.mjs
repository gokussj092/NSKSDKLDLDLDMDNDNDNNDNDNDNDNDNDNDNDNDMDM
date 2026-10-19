import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {catalog,iconFor,CATALOG_VERSION,RECHECK_SECONDS,activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
import {POST as list} from "../app/api/v1/server-vpn/catalog/route.js";
import {POST as getIcon} from "../app/api/v1/server-vpn/icon/route.js";

const body=(content)=>new Request("https://api.spdecode.xyz/api/v1/server-vpn/test",{
  method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(content),
});
test("original provider PNGs match the public digest and never contain secrets",()=>{
 const values=catalog();assert.equal(values.catalogVersion,CATALOG_VERSION);
 assert.equal(RECHECK_SECONDS,86400);assert.equal(values.apps.length,5);
 const ids=new Set();
 for(const app of values.apps) {
   assert(!ids.has(app.id));ids.add(app.id);
   assert(!("url" in app) && !("secret" in app));
   const icon=iconFor(app.id);
   assert(icon.bytes.length>32);
   assert.equal(icon.bytes.subarray(0,8).toString("hex"),"89504e470d0a1a0a");
   assert.equal(createHash("sha256").update(icon.bytes).digest("hex"),app.iconSha256);
 }
 assert.equal(catalog().apps.find(x=>x.id==="hx-tunnel").name,"HX Tunnel VPN");
});
test("version match returns only a cheap unchanged response",async()=>{
 const response=await list(body({knownVersion:CATALOG_VERSION}));
 assert.equal(response.status,200);
 const data=await response.json();assert.equal(data.unchanged,true);
 assert.equal(data.catalogVersion,CATALOG_VERSION);assert(!("apps" in data));
});
test("new version returns catalog and invalid bodies fail closed",async()=>{
 const response=await list(body({knownVersion:0}));
 const data=await response.json();assert.equal(response.status,200);
 assert.equal(data.unchanged,false);assert.equal(data.apps.length,5);
 for(const invalid of [{knownVersion:-1},{url:"http://127.0.0.1/"},{knownVersion:"1"}]) {
   assert.equal((await list(body(invalid))).status,400);
 }
});
test("only registered icon identifiers are served",async()=>{
 const found=await getIcon(body({id:"hx-tunnel"}));
 assert.equal(found.status,200);
 const icon=await found.json();
 assert.equal(icon.id,"hx-tunnel");
 assert.equal(createHash("sha256").update(Buffer.from(icon.contentBase64,"base64")).digest("hex"),icon.sha256);
 assert.equal((await getIcon(body({id:"../secrets"}))).status,400);
 assert.equal((await getIcon(body({id:"missing"}))).status,404);
});

import {providerIds,providerEnabled,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
test("only fixed catalog providers are eligible for remote broker",async()=>{
  assert.deepEqual(providerIds().sort(),["24clan-green","hx-tunnel","mkk-hyper","my-tunnel-proxy"]);
  for(const id of providerIds()) assert.equal(providerEnabled(id,{CLOUD_SERVER_VPN_ENABLED:"false"}),false);
  assert.equal(providerEnabled("https://attacker.invalid/",{CLOUD_SERVER_VPN_ENABLED:"true"}),false);
  await assert.rejects(()=>downloadVpnCatalog("https://attacker.invalid/"),{code:"UNSUPPORTED_FORMAT"});
});

test("deployment version is monotonic and rejects rollback",()=>{
 assert.equal(activeCatalogVersion({}),CATALOG_VERSION);
 assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"3"}),3);
 for(const value of ["-1","0","1","2","abc","3.4","0003","9999999999"]) {
   assert.throws(()=>activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:value}));
 }
});
