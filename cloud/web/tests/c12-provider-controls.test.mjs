import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,readFile,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {
  PUBLIC_PROVIDER_IDS,providerPrerequisite,providerEffective,
  loadProviderState,providerOverview,providerAllowed,updateProvider,updateMethodState,
} from "../lib/c12-provider-controls.mjs";
import {catalog,activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";

const env={
  CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_NUR_FETCH_ENABLED:"true",
  CLOUD_NUR_CATALOG_URL:"https://strongteam.co/approved/catalog",
  CLOUD_EHI_IMPORT_ENABLED:"true",
  CLOUD_EHI_SIGN_KEY:"S".repeat(32),CLOUD_EHI_RESPONSE_KEY:"R".repeat(32),
  CLOUD_SERVER_VPN_CATALOG_VERSION:"12",CLOUD_FORCE_MAINTENANCE:"false",
};
async function fixture(t){
  const root=await mkdtemp(join(tmpdir(),"spdecode-provider-test-"));
  t.after(async()=>rm(root,{recursive:true,force:true}));
  return root;
}
test("allowlist is fixed and remote URLs are never stored as provider IDs",()=>{
  assert(PUBLIC_PROVIDER_IDS.includes("ehi-cloud"));
  assert(PUBLIC_PROVIDER_IDS.includes("nur-tunnel"));
  assert(PUBLIC_PROVIDER_IDS.includes("tunneltweak"));
  assert(PUBLIC_PROVIDER_IDS.includes("http-socketclay"));
  assert(PUBLIC_PROVIDER_IDS.includes("http-wakko"));
  assert(!PUBLIC_PROVIDER_IDS.includes("royal-tunnel"));
  assert(!PUBLIC_PROVIDER_IDS.includes("https://evil.example/"));
  assert.throws(()=>providerPrerequisite("https://evil.example/",env));
});
test("provider settings are opt-out, persistent and version-incremented",async t=>{
  const root=await fixture(t);
  const opts={root};
  assert.equal((await providerOverview(env,opts)).catalogVersion,activeCatalogVersion(env));
  assert.equal(await providerAllowed("http-jireh",env,opts),true);
  const disabled=await updateProvider("http-jireh",false,env,opts);
  assert.equal(disabled.providers.find(x=>x.id==="http-jireh").enabled,false);
  assert(disabled.catalogVersion>activeCatalogVersion(env));
  assert.equal(await providerAllowed("http-jireh",env,opts),false);
  const stored=await readFile(join(root,"switches.json"),"utf8");
  assert(!stored.includes("https://") && !stored.includes("S".repeat(32)));
  assert.deepEqual(JSON.parse(stored).disabled,["http-jireh"]);
  const repeat=await updateProvider("http-jireh",false,env,opts);
  assert.equal(repeat.catalogVersion,disabled.catalogVersion);
  const enabled=await updateProvider("http-jireh",true,env,opts);
  assert.equal(enabled.providers.find(x=>x.id==="http-jireh").enabled,true);
  assert(enabled.catalogVersion>disabled.catalogVersion);
  const available=Object.fromEntries(enabled.providers.map(x=>[x.id,x.enabled]));
  assert.equal(catalog({availability:available,version:enabled.catalogVersion})
    .apps.find(x=>x.id==="http-jireh").decodeEnabled,true);
});
test("turning off EHI and NUR is enforced while file decoding remains independent",async t=>{
  const root=await fixture(t),opts={root};
  await updateProvider("nur-tunnel",false,env,opts);
  await updateProvider("ehi-cloud",false,env,opts);
  assert.equal(await providerAllowed("nur-tunnel",env,opts),false);
  assert.equal(await providerAllowed("ehi-cloud",env,opts),false);
  const overview=await providerOverview(env,opts);
  const map=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
  assert.equal(catalog({availability:map,version:overview.catalogVersion})
    .apps.find(x=>x.id==="nur-tunnel").decodeEnabled,false);
  assert.equal(map["http-jireh"],true);
});
test("panel cannot enable missing private EHI keys or disabled VPS integration",async t=>{
  const root=await fixture(t),opts={root};
  const noKeys={...env,CLOUD_EHI_RESPONSE_KEY:""};
  const disabled=await updateProvider("ehi-cloud",false,noKeys,opts);
  assert.equal(disabled.providers.find(x=>x.id==="ehi-cloud").configured,false);
  await assert.rejects(()=>updateProvider("ehi-cloud",true,noKeys,opts),/PROVIDER_NOT_CONFIGURED/);
  await assert.rejects(()=>updateProvider("http-jireh",true,{...env,CLOUD_SERVER_VPN_ENABLED:"false"},opts),
    /PROVIDER_NOT_CONFIGURED/);
  await assert.rejects(()=>updateProvider("http-jireh",true,{...env,CLOUD_FORCE_MAINTENANCE:"true"},opts),
    /MAINTENANCE_LOCKED/);
});
test("invalid and corrupt state is rejected, never replaced silently",async t=>{
  const root=await fixture(t),opts={root};
  await writeFile(join(root,"switches.json"),'{"version":12,"disabled":["../../secret"]}');
  await assert.rejects(()=>loadProviderState(root),/PROVIDER_STATE_INVALID/);
  await assert.rejects(()=>updateProvider("http-jireh",true,env,opts),/PROVIDER_STATE_INVALID/);
  assert.match(await readFile(join(root,"switches.json"),"utf8"),/secret/);
  await assert.rejects(()=>updateProvider("evil",true,env,opts),/INVALID_PROVIDER/);
});
test("concurrent mutations serialize and keep both switches",async t=>{
  const root=await fixture(t),opts={root};
  const [a,b]=await Promise.all([
    updateProvider("http-jireh",false,env,opts),
    updateProvider("hx-tunnel",false,env,opts),
  ]);
  assert(a.catalogVersion!==b.catalogVersion);
  const state=await loadProviderState(root);
  assert.deepEqual(state.disabled,["http-jireh","hx-tunnel"]);
});


test("SocketClay has a named control and can be enabled or disabled without touching other providers",async t=>{
 const root=await fixture(t),opts={root};
 let overview=await providerOverview(env,opts);
 assert.deepEqual(overview.providers.find(x=>x.id==="http-socketclay"),{
   id:"http-socketclay",name:"HTTP SocketClay",configured:true,enabled:true,
 });
 overview=await updateProvider("http-socketclay",false,env,opts);
 let availability=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
 assert.equal(catalog({availability}).apps.find(x=>x.id==="http-socketclay").decodeEnabled,false);
 assert.equal(await providerAllowed("http-jireh",env,opts),true);
 overview=await updateProvider("http-socketclay",true,env,opts);
 availability=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
 assert.equal(catalog({availability}).apps.find(x=>x.id==="http-socketclay").decodeEnabled,true);
});

test("Wakko has a named control and can be enabled or disabled without touching other providers",async t=>{
 const root=await fixture(t),opts={root};
 let overview=await providerOverview(env,opts);
 assert.deepEqual(overview.providers.find(x=>x.id==="http-wakko"),{
   id:"http-wakko",name:"HTTP Wakko",configured:true,enabled:true,
 });
 overview=await updateProvider("http-wakko",false,env,opts);
 let availability=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
 assert.equal(catalog({availability}).apps.find(x=>x.id==="http-wakko").decodeEnabled,false);
 assert.equal(await providerAllowed("http-jireh",env,opts),true);
 overview=await updateProvider("http-wakko",true,env,opts);
 availability=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
 assert.equal(catalog({availability}).apps.find(x=>x.id==="http-wakko").decodeEnabled,true);
});

test("V2ray Tunnel Plus has a named control and can be enabled or disabled without touching other providers",async t=>{
 const root=await fixture(t),opts={root};
 let overview=await providerOverview(env,opts);
 assert.deepEqual(overview.providers.find(x=>x.id==="v2ray-tunnel-plus"),{
   id:"v2ray-tunnel-plus",name:"V2ray Tunnel Plus",configured:true,enabled:true,
 });
 overview=await updateProvider("v2ray-tunnel-plus",false,env,opts);
 let availability=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
 assert.equal(catalog({availability}).apps.find(x=>x.id==="v2ray-tunnel-plus").decodeEnabled,false);
 assert.equal(await providerAllowed("http-jireh",env,opts),true);
 overview=await updateProvider("v2ray-tunnel-plus",true,env,opts);
 availability=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
 assert.equal(catalog({availability}).apps.find(x=>x.id==="v2ray-tunnel-plus").decodeEnabled,true);
});


test("Xhypher Tunnel Pro has a named control and can be enabled or disabled without touching other providers",async t=>{
 const root=await fixture(t),opts={root};
 let overview=await providerOverview(env,opts);
 assert.deepEqual(overview.providers.find(x=>x.id==="xhypher-tunnel-pro"),{
   id:"xhypher-tunnel-pro",name:"Xhypher Tunnel Pro",configured:true,enabled:true,
 });
 overview=await updateProvider("xhypher-tunnel-pro",false,env,opts);
 let availability=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
 assert.equal(catalog({availability}).apps.find(x=>x.id==="xhypher-tunnel-pro").decodeEnabled,false);
 assert.equal(await providerAllowed("http-jireh",env,opts),true);
 overview=await updateProvider("xhypher-tunnel-pro",true,env,opts);
 availability=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
 assert.equal(catalog({availability}).apps.find(x=>x.id==="xhypher-tunnel-pro").decodeEnabled,true);
});

test("7NET VPN has a named control and can be enabled or disabled without touching other providers",async t=>{
 const root=await fixture(t),opts={root};
 let overview=await providerOverview(env,opts);
 assert.deepEqual(overview.providers.find(x=>x.id==="7net-vpn"),{
   id:"7net-vpn",name:"7NET VPN",configured:true,enabled:true,
 });
 overview=await updateProvider("7net-vpn",false,env,opts);
 let availability=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
 assert.equal(catalog({availability}).apps.find(x=>x.id==="7net-vpn").decodeEnabled,false);
 assert.equal(await providerAllowed("http-jireh",env,opts),true);
 overview=await updateProvider("7net-vpn",true,env,opts);
 availability=Object.fromEntries(overview.providers.map(x=>[x.id,x.enabled]));
 assert.equal(catalog({availability}).apps.find(x=>x.id==="7net-vpn").decodeEnabled,true);
});

test("Tx Tunnel has a named persistent provider switch",async t=>{
 const root=await fixture(t),opts={root};
 assert(PUBLIC_PROVIDER_IDS.includes("tx-tunnel"));
 assert.equal(providerPrerequisite("tx-tunnel",env),true);
 assert.equal((await providerOverview(env,opts)).providers.find(x=>x.id==="tx-tunnel").name,"Tx Tunnel");
 const result=await updateProvider("tx-tunnel",false,env,opts);
 assert.equal(result.providers.find(x=>x.id==="tx-tunnel").enabled,false);
 assert.equal(await providerAllowed("tx-tunnel",env,opts),false);
});


test("explicit method revision is separate from catalog and icon version",async t=>{
  const root=await fixture(t),opts={root};
  const initial=await providerOverview(env,opts);
  const method=initial.methodStatuses.find(x=>x.id==="http-jireh");
  assert.deepEqual(
    {revision:method.methodRevision,maintenance:method.maintenance},
    {revision:0,maintenance:false},
  );
  const initialCatalog=catalog({version:initial.catalogVersion});
  assert.equal(initialCatalog.apps.find(x=>x.id==="http-jireh").methodRevision,0);
  assert.equal(initialCatalog.apps.find(x=>x.id==="http-jireh").maintenance,false);
  const updated=await updateMethodState("http-jireh","revision",undefined,env,opts);
  assert(updated.catalogVersion>initial.catalogVersion);
  const revised=updated.methodStatuses.find(x=>x.id==="http-jireh");
  assert.equal(revised.methodRevision,1);
  assert.equal(revised.maintenance,false);
  const metadata=Object.fromEntries(updated.methodStatuses.map(x=>[x.id,x]));
  assert.equal(catalog({methodStates:metadata,version:updated.catalogVersion})
    .apps.find(x=>x.id==="http-jireh").methodRevision,1);
  // Incrementing the global version alone never changes the method revision.
  assert.equal(catalog({methodStates:metadata,version:updated.catalogVersion+1})
    .apps.find(x=>x.id==="http-jireh").methodRevision,1);
  assert.equal((await updateMethodState("http-jireh","revision",undefined,env,opts))
    .methodStatuses.find(x=>x.id==="http-jireh").methodRevision,2);
});

test("maintenance is explicit, persistent and blocks provider admission",async t=>{
  const root=await fixture(t),opts={root};
  assert.equal(await providerAllowed("http-jireh",env,opts),true);
  const blocked=await updateMethodState("http-jireh","maintenance",true,env,opts);
  assert.equal(await providerAllowed("http-jireh",env,opts),false);
  assert.equal(blocked.methodStatuses.find(x=>x.id==="http-jireh").maintenance,true);
  const availability=Object.fromEntries(blocked.providers.map(x=>[x.id,x.enabled]));
  const methods=Object.fromEntries(blocked.methodStatuses.map(x=>[x.id,x]));
  const item=catalog({availability,methodStates:methods,version:blocked.catalogVersion})
    .apps.find(x=>x.id==="http-jireh");
  assert.equal(item.decodeEnabled,false);
  assert.equal(item.maintenance,true);
  const repeat=await updateMethodState("http-jireh","maintenance",true,env,opts);
  assert.equal(repeat.catalogVersion,blocked.catalogVersion);
  assert.deepEqual(JSON.parse(await readFile(join(root,"switches.json"),"utf8")).maintenance,
    ["http-jireh"]);
  const restored=await updateMethodState("http-jireh","maintenance",false,env,opts);
  assert(restored.catalogVersion>blocked.catalogVersion);
  assert.equal(await providerAllowed("http-jireh",env,opts),true);
  assert.equal(restored.methodStatuses.find(x=>x.id==="http-jireh").maintenance,false);
});

test("method updates reject arbitrary IDs and invalid maintenance values",async t=>{
  const root=await fixture(t),opts={root};
  await assert.rejects(()=>updateMethodState("../fake","revision",undefined,env,opts),
    /INVALID_METHOD_STATE/);
  await assert.rejects(()=>updateMethodState("http-jireh","maintenance","yes",env,opts),
    /INVALID_METHOD_STATE/);
  await assert.rejects(()=>updateMethodState("http-jireh","revision",true,env,opts),
    /INVALID_METHOD_STATE/);
  await assert.rejects(()=>updateMethodState("http-jireh","maintenance",true,
    {...env,CLOUD_FORCE_MAINTENANCE:"true"},opts),/MAINTENANCE_LOCKED/);
  await writeFile(join(root,"switches.json"),JSON.stringify({
    version:2,disabled:[],methodRevisions:{"../../bad":4},maintenance:[],
  }));
  await assert.rejects(()=>loadProviderState(root),/PROVIDER_STATE_INVALID/);
});
