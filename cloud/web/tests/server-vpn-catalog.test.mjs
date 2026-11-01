import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {catalog,iconFor,CATALOG_VERSION,RECHECK_SECONDS,activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
import {POST as list} from "../app/api/v1/server-vpn/catalog/route.js";
import {POST as getIcon} from "../app/api/v1/server-vpn/icon/route.js";

const body=(content)=>new Request("https://api.spdecode.xyz/api/v1/server-vpn/test",{
  method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(content),
});
test("HA Tunnel original PNG is available while its protected updater remains unverified",()=>{
 const app=catalog({availability:{"ha-tunnel-plus":true}}).apps.find(x=>x.id==="ha-tunnel-plus");
 assert.equal(app.name,"HA Tunnel Plus");assert.equal(app.decodeEnabled,false);
 assert.equal(app.iconSha256,"42aa9743f5d430933257f0023af2182f2dcc6ae41a8930a9ca38e9f397ac3ab8");
 assert.equal(iconFor(app.id).bytes.length,20416);
});
test("original provider PNGs match the public digest and never contain secrets",()=>{
 const values=catalog();assert.equal(values.catalogVersion,CATALOG_VERSION);
 assert.equal(RECHECK_SECONDS,900);assert.equal(values.apps.length,57);
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
test("current catalog still invalidates the release-57 Android catalog cache",async()=>{
 const response=await list(body({knownVersion:57}));
 assert.equal(response.status,200);
 const data=await response.json();
 assert.equal(data.unchanged,false);
 assert.equal(data.catalogVersion,CATALOG_VERSION);
 assert.equal(CATALOG_VERSION,59);
 assert(data.apps.some(x=>x.id==="http-jireh"));
 assert(data.apps.some(x=>x.id==="jyfast-vpn-ultra"));
});
test("new version returns catalog and invalid bodies fail closed",async()=>{
 const response=await list(body({knownVersion:0}));
 const data=await response.json();assert.equal(response.status,200);
 assert.equal(data.unchanged,false);assert.equal(data.apps.length,57);
 for(const invalid of [{knownVersion:-1},{url:"http://127.0.0.1/"},{knownVersion:"1"}]) {
   assert.equal((await list(body(invalid))).status,400);
 }
});
test("Wolf catalog refreshes a release-58 cache with its original icon",async()=>{
 const response=await list(body({knownVersion:58}));
 const data=await response.json();
 assert.equal(response.status,200);assert.equal(data.unchanged,false);
 assert.equal(data.catalogVersion,CATALOG_VERSION);assert(CATALOG_VERSION>58);
 assert.equal(data.apps.find(x=>x.id==="wolf-custom-vpn").iconSha256,
   "4e403e8f44b840eadb67af9062d0b0455ffc88c37706bee4b949ca94513fa1c0");
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
  assert.deepEqual(providerIds().sort(),["24clan-green","4u-tunnel-lite","7net-vpn","abowaged-vpn","ac-tunnel-vpn","alfaisal-tunnel-plus","any-vpn","apna-vpn","aura-net-vpn","austroplus-vpn","bd-net-vpn","enaa-tunnel","focus-vpn-cloud","freedom-vpn","http-fenixvpn","http-internet-infinito","http-jireh","http-socketclay","http-wakko","hx-tunnel","izph-vpn-pro","jyfast-vpn-ultra","ksh-vpn","megatunnel","mkk-hyper","mm-tunnel","mnr-tunnel-plus","mtm-tunnel-lite","mx-tunnel-pro","my-tunnel-proxy","netcol-vpn","onspace-vpn","rjc-tunnel-pro","rmp-tunnel-pro","robust-tunnel","speicers-pro-vpn","superflash-vpn","trv-tunnel","tunneldoom-vpn","tunneltweak","turbomx-vpn","tx-tunnel","v2ray-tunnel-plus","vip-snipher-pro","wolf-custom-vpn","xhypher-tunnel-pro","zig-tunnel"]);
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

test("Internet Infinito original icon and verified source follow provider availability",()=>{
 const app=catalog({availability:{"http-internet-infinito":true}}).apps.find(x=>x.id==="http-internet-infinito");
 assert.equal(app.name,"HTTP Internet Infinito");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"93917c9c260d4d7fe7633d57f64f654f9dd800837bac186517f884dfb04c7efa");
 assert.equal(catalog({availability:{"http-internet-infinito":false}}).apps.find(x=>x.id==="http-internet-infinito").decodeEnabled,false);
});

test("MegaTunnel original icon and real validated source follow provider controls",()=>{
 const app=catalog({availability:{"megatunnel":true}}).apps.find(x=>x.id==="megatunnel");
 assert.equal(app.name,"MegaTunnel");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"aa9a6c221895ee6f525c8cae66acbee10bc1d5ab9d91bcd70e03930fd274a192");
 assert.equal(catalog({availability:{"megatunnel":false}}).apps.find(x=>x.id==="megatunnel").decodeEnabled,false);
});


test("Mx Tunnel PRO exact original icon and real validated catalog follow provider controls",()=>{
 const app=catalog({availability:{"mx-tunnel-pro":true}}).apps.find(x=>x.id==="mx-tunnel-pro");
 assert.equal(app.name,"Mx Tunnel PRO");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"e533df6792db791255152d871904f302674c9f4cba9c118a13abe4bb55bff20d");
 assert.equal(catalog({availability:{"mx-tunnel-pro":false}}).apps.find(x=>x.id==="mx-tunnel-pro").decodeEnabled,false);
});


test("OnSpace VPN lossless original launcher and verified paired sources follow provider controls",()=>{
 const app=catalog({availability:{"onspace-vpn":true}}).apps.find(x=>x.id==="onspace-vpn");
 assert.equal(app.name,"OnSpace VPN");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"59a6de90b34c625913705585ed6e0f2115b661015c656d9a0c43fdd036a5b232");
 assert.equal(catalog({availability:{"onspace-vpn":false}}).apps.find(x=>x.id==="onspace-vpn").decodeEnabled,false);
});


test("ProNeet keeps its original icon visible while both official updater files are empty",async t=>{
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
 const app=catalog({availability:{"proneet-vpn":true}}).apps.find(x=>x.id==="proneet-vpn");
 assert.equal(app.name,"ProNeet VPN");assert.equal(app.decodeEnabled,false);
 assert.equal(app.iconSha256,"3158eca3593b48108561aea234d3015f3e0e3c3c05fe4454bd86e78984aa1693");
 assert(!providerIds().includes("proneet-vpn"));assert.equal(providerEnabled("proneet-vpn",{CLOUD_SERVER_VPN_ENABLED:"true"}),false);
 await assert.rejects(()=>downloadVpnCatalog("proneet-vpn"),{code:"UNSUPPORTED_FORMAT"});
});


test("RJC TUNNEL PRO original PNG and verified live catalog follow provider controls",()=>{
 const app=catalog({availability:{"rjc-tunnel-pro":true}}).apps.find(x=>x.id==="rjc-tunnel-pro");
 assert.equal(app.name,"RJC TUNNEL PRO");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"cbfa6c1555e6c9839c915b0e49b381a551099807c28fe1927bd9b33b79fb0476");
 assert.equal(catalog({availability:{"rjc-tunnel-pro":false}}).apps.find(x=>x.id==="rjc-tunnel-pro").decodeEnabled,false);
});


test("RMP TUNNEL PRO exact original icon and real validated source follow provider controls",()=>{
 const app=catalog({availability:{"rmp-tunnel-pro":true}}).apps.find(x=>x.id==="rmp-tunnel-pro");
 assert.equal(app.name,"RMP TUNNEL PRO");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"c00e5d70987cf08e1b868be5800962569abd16e98f86d9e4bc999f71e1405527");
 assert.equal(catalog({availability:{"rmp-tunnel-pro":false}}).apps.find(x=>x.id==="rmp-tunnel-pro").decodeEnabled,false);
});


test("SuperFlash original PNG and validated paired sources follow provider controls",()=>{
 const app=catalog({availability:{"superflash-vpn":true}}).apps.find(x=>x.id==="superflash-vpn");
 assert.equal(app.name,"SuperFlash VPN");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"69a0efc8ac0e713e705c7935524e340b99f7dd5c6404cdb4162cd60b0deae214");
 assert.equal(catalog({availability:{"superflash-vpn":false}}).apps.find(x=>x.id==="superflash-vpn").decodeEnabled,false);
});


test("TurboMX original PNG and validated paired sources follow provider controls",()=>{
 const app=catalog({availability:{"turbomx-vpn":true}}).apps.find(x=>x.id==="turbomx-vpn");
 assert.equal(app.name,"TurboMX VPN");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"3f9f45bb05d49cb20a84d3fa86c90981a7e52287c13a3acf157d5cc1068b7945");
 assert.equal(catalog({availability:{"turbomx-vpn":false}}).apps.find(x=>x.id==="turbomx-vpn").decodeEnabled,false);
});


test("UT Loop keeps its original icon visible while its official remote response remains unvalidated",async t=>{
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
 const app=catalog({availability:{"ut-loop-pro-vpn":true}}).apps.find(x=>x.id==="ut-loop-pro-vpn");
 assert(app);assert.equal(app.name,"UT Loop Pro VPN");assert.equal(app.decodeEnabled,false);
 assert.equal(app.iconSha256,"8f01bceeb6a4f352e0b5b17ffe43df37ff4c5c78aaaf250696e540ae3f779b17");
 assert(!providerIds().includes("ut-loop-pro-vpn"));
 assert.equal(providerEnabled("ut-loop-pro-vpn",{CLOUD_SERVER_VPN_ENABLED:"true"}),false);
 await assert.rejects(()=>downloadVpnCatalog("ut-loop-pro-vpn"),{code:"UNSUPPORTED_FORMAT"});
 const response=await getIcon(body({id:"ut-loop-pro-vpn"}));assert.equal(response.status,200);
 assert.equal((await response.json()).sha256,app.iconSha256);
});


test("Xhypher original PNG and validated complete catalog follow provider controls",()=>{
 const app=catalog({availability:{"xhypher-tunnel-pro":true}}).apps.find(x=>x.id==="xhypher-tunnel-pro");
 assert.equal(app.name,"Xhypher Tunnel Pro");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"f32f6d6c2044ee507741b4b389f53b9fc03922800deaac66cda1dd094ece9e72");
 assert.equal(catalog({availability:{"xhypher-tunnel-pro":false}}).apps.find(x=>x.id==="xhypher-tunnel-pro").decodeEnabled,false);
});

test("7NET original PNG and validated complete catalog follow provider controls",()=>{
 const app=catalog({availability:{"7net-vpn":true}}).apps.find(x=>x.id==="7net-vpn");
 assert.equal(app.name,"7NET VPN");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"a6eac9703f48f4890f29a093178526e841984f8d5915fbc187a9e895da6a538c");
 assert.equal(catalog({availability:{"7net-vpn":false}}).apps.find(x=>x.id==="7net-vpn").decodeEnabled,false);
});


test("AM retains its original PNG while protected catalog support is pending",async t=>{
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
 const app=catalog({availability:{"am-tunnel-lite-vpn":true}}).apps.find(x=>x.id==="am-tunnel-lite-vpn");
 assert.equal(app.name,"AM TUNNEL LITE VPN");assert.equal(app.decodeEnabled,false);
 assert.equal(app.iconSha256,"ad8aab869a41fd23aa1bff5c976c589ae73738192a8d475c3fcc36edd1da2d7a");
 assert(!providerIds().includes("am-tunnel-lite-vpn"));
 assert.equal(providerEnabled("am-tunnel-lite-vpn",{CLOUD_SERVER_VPN_ENABLED:"true"}),false);
 await assert.rejects(()=>downloadVpnCatalog("am-tunnel-lite-vpn"),{code:"UNSUPPORTED_FORMAT"});
});

// CREEB VPN has a validated offline reader; this card cannot download yet.
test("CREEB VPN remains disabled even with global availability",()=>{
 const app=catalog({availability:{"creeb-vpn":true}}).apps.find(x=>x.id==="creeb-vpn");
 assert.equal(app.name,"CREEB VPN");assert.equal(app.decodeEnabled,false);
 assert.equal(app.iconSha256,createHash("sha256").update(iconFor("creeb-vpn").bytes).digest("hex"));
});

test("MM Tunnel keeps its original PNG and enables the validated hash POST",()=>{
 const app=catalog({availability:{"mm-tunnel":true}}).apps.find(x=>x.id==="mm-tunnel");
 assert.equal(app.name,"MM Tunnel");
 assert.equal(app.iconSha256,"be2bb0a69da20838aaa46c388ab898a33b84cab59ccdad7413b76eac21b7b211");
 assert.equal(iconFor("mm-tunnel").bytes.length,109337);
 assert.equal(app.decodeEnabled,true);
 assert.equal(providerEnabled("mm-tunnel",{CLOUD_SERVER_VPN_ENABLED:"true"}),true);
 assert(providerIds().includes("mm-tunnel"));
});

test("Tx original icon and verified fixed catalog follow individual availability",()=>{
 const app=catalog({availability:{"tx-tunnel":true}}).apps.find(x=>x.id==="tx-tunnel");
 assert.equal(app.name,"Tx Tunnel");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"cc0507ce55fb41623379091f70732a932fb5df7c2f1b1c6e7875b1448f887772");
 assert.equal(iconFor("tx-tunnel").bytes.length,312819);
 assert.equal(catalog({availability:{"tx-tunnel":false}}).apps.find(x=>x.id==="tx-tunnel").decodeEnabled,false);
});
