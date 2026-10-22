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
 assert.equal(RECHECK_SECONDS,900);assert.equal(values.apps.length,23);
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
 assert.equal(data.unchanged,false);assert.equal(data.apps.length,23);
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
  assert.deepEqual(providerIds().sort(),["24clan-green","4u-tunnel-lite","ac-tunnel-vpn","austroplus-vpn","focus-vpn-cloud","freedom-vpn","http-fenixvpn","http-jireh","http-socketclay","http-wakko","hx-tunnel","ksh-vpn","mkk-hyper","my-tunnel-proxy","robust-tunnel","trv-tunnel","tunneltweak","v2ray-tunnel-plus"]);
  for(const id of providerIds()) assert.equal(providerEnabled(id,{CLOUD_SERVER_VPN_ENABLED:"false"}),false);
  assert.equal(providerEnabled("https://attacker.invalid/",{CLOUD_SERVER_VPN_ENABLED:"true"}),false);
  await assert.rejects(()=>downloadVpnCatalog("https://attacker.invalid/"),{code:"UNSUPPORTED_FORMAT"});
});

test("deployment version is monotonic and rejects rollback",()=>{
 assert.equal(activeCatalogVersion({}),CATALOG_VERSION);
 assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"11"}),CATALOG_VERSION);
 assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"12"}),CATALOG_VERSION);
 for(const value of ["-1","0","1","2","3","4","5","6","7","8","9","10","abc","3.4","0003","9999999999"]) {
   assert.throws(()=>activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:value}));
 }
});

test("DTunnel Mod uses the confirmed green provider icon but never offers unauthenticated remote download",async t=>{
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;
 process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
 const record=catalog().apps.find(app=>app.id==="dtunnel-mod");
 assert(record);
 assert.equal(record.name,"DTunnel Mod");
 assert.equal(record.decodeEnabled,false);
 assert.equal(catalog({availability:{"dtunnel-mod":true}}).apps.find(app=>app.id==="dtunnel-mod").decodeEnabled,false);
 const result=await getIcon(body({id:"dtunnel-mod"}));
 assert.equal(result.status,200);
 const icon=await result.json();
 assert.equal(icon.id,"dtunnel-mod");
 const bytes=Buffer.from(icon.contentBase64,"base64");
 assert.equal(bytes.subarray(0,8).toString("hex"),"89504e470d0a1a0a");
 assert.equal(icon.sha256,createHash("sha256").update(bytes).digest("hex"));
 assert.equal(icon.sha256,"9eefafb521cd0ebd568918798aaeb657ec9989ad96b16347bae0951d8d742d9d");
});

// Original icon bytes must remain available even above the former client cap.
test("Royal retains its large original PNG and stays visible with decoding disabled",async t=>{
 const previous=process.env.CLOUD_SERVER_VPN_ENABLED;
 process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(previous===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=previous;});
 const royal=catalog().apps.find(x=>x.id==="royal-tunnel");
 assert(royal);assert.equal(royal.decodeEnabled,false);
 const response=await getIcon(body({id:"royal-tunnel"}));assert.equal(response.status,200);
 const value=await response.json();const bytes=Buffer.from(value.contentBase64,"base64");
 assert(bytes.length>256*1024);assert(value.contentBase64.length>350000);
 assert.equal(createHash("sha256").update(bytes).digest("hex"),"d5b0acadb3759da52c90cd45a671e264ed98b58e5c838d496e6999b5e1198309");
});


test("SocketClay original icon and verified remote source follow provider availability",t=>{
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;
 process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
 const app=catalog({availability:{"http-socketclay":true}}).apps.find(x=>x.id==="http-socketclay");
 assert(app);assert.equal(app.name,"HTTP SocketClay");assert.equal(app.decodeEnabled,true);
 assert.equal(catalog({availability:{"http-socketclay":false}}).apps.find(x=>x.id==="http-socketclay").decodeEnabled,false);
 assert.equal(app.iconSha256,"8a09f5b74e445f859532809204c3a543b05b6fa89be8844b655191e17690f101");
 assert.equal(providerEnabled("http-socketclay",{CLOUD_SERVER_VPN_ENABLED:"true"}),true);
});

test("Wakko original icon and verified remote source follow provider availability",t=>{
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;
 process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
 const app=catalog({availability:{"http-wakko":true}}).apps.find(x=>x.id==="http-wakko");
 assert(app);assert.equal(app.name,"HTTP Wakko");assert.equal(app.decodeEnabled,true);
 assert.equal(catalog({availability:{"http-wakko":false}}).apps.find(x=>x.id==="http-wakko").decodeEnabled,false);
 assert.equal(app.iconSha256,"77d7f0647746000fea1dee4ae0dff7189214e649944de226fc07d864971f520a");
 assert.equal(providerEnabled("http-wakko",{CLOUD_SERVER_VPN_ENABLED:"true"}),true);
});

test("TunelGuard keeps its original icon while the build-128 updater returns 404",async t=>{
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
 const app=catalog({availability:{"tunelguard-vpn":true}}).apps.find(x=>x.id==="tunelguard-vpn");
 assert(app);assert.equal(app.name,"TunelGuard VPN");assert.equal(app.decodeEnabled,false);
 assert.equal(app.iconSha256,"bdc4bca16e4c9fc0c446e90cf683eef1fe57f7a10de9c451e8c5ec30890f3f6a");
 assert.equal(providerEnabled("tunelguard-vpn",{CLOUD_SERVER_VPN_ENABLED:"true"}),false);
 assert(!providerIds().includes("tunelguard-vpn"));
 await assert.rejects(()=>downloadVpnCatalog("tunelguard-vpn"),{code:"UNSUPPORTED_FORMAT"});
 const response=await getIcon(body({id:"tunelguard-vpn"}));assert.equal(response.status,200);
 assert.equal((await response.json()).sha256,app.iconSha256);
});

test("V2ray Tunnel Plus original icon and verified remote source follow provider availability",t=>{
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;
 process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
 const app=catalog({availability:{"v2ray-tunnel-plus":true}}).apps.find(x=>x.id==="v2ray-tunnel-plus");
 assert(app);assert.equal(app.name,"V2ray Tunnel Plus");assert.equal(app.decodeEnabled,true);
 assert.equal(catalog({availability:{"v2ray-tunnel-plus":false}}).apps.find(x=>x.id==="v2ray-tunnel-plus").decodeEnabled,false);
 assert.equal(app.iconSha256,"b87f9c792ec5271da31e255cf957e02abf8fbafd0f1f2737549f232d47cfb47f");
 assert.equal(providerEnabled("v2ray-tunnel-plus",{CLOUD_SERVER_VPN_ENABLED:"true"}),true);
});

test("EUT VPN retains the original bundled icon while its API requires an accepted session",()=>{
 const app=catalog().apps.find(x=>x.id==="eut-vpn");
 assert(app);assert.equal(app.name,"EUT VPN");assert.equal(app.decodeEnabled,false);
 assert.equal(app.iconSha256,"f037219478e9ab6ec2d6963ffed9e303186fcbeb50ffece2a33d19173ef465cf");
 assert(!providerIds().includes("eut-vpn"));
});

test("Focus original launcher icon and validated source follow provider controls",()=>{
 const app=catalog({availability:{"focus-vpn-cloud":true}}).apps.find(x=>x.id==="focus-vpn-cloud");
 assert.equal(app.name,"Focus VPN Cloud");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"81b351e2ce9b578db175da44c521f72aaaa136b1d40a7a3759a211c3becb9164");
 assert.equal(catalog({availability:{"focus-vpn-cloud":false}}).apps.find(x=>x.id==="focus-vpn-cloud").decodeEnabled,false);
});

test("FreedomVPN original icon and verified source follow provider availability",()=>{
 const app=catalog({availability:{"freedom-vpn":true}}).apps.find(x=>x.id==="freedom-vpn");
 assert.equal(app.name,"FreedomVPN");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"70750ce9d34de700556f0c3db93c1a3677ebbe581c06ba267833e449ded63234");
 assert.equal(catalog({availability:{"freedom-vpn":false}}).apps.find(x=>x.id==="freedom-vpn").decodeEnabled,false);
});
