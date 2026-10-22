import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,readFile,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {
  PUBLIC_PROVIDER_IDS,providerPrerequisite,providerEffective,
  loadProviderState,providerOverview,providerAllowed,updateProvider,
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
