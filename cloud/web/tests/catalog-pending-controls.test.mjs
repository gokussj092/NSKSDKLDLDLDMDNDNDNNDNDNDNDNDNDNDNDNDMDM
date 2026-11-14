import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,rm,writeFile,readFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {PENDING_CATALOGS} from "../lib/catalog-provider-policy.mjs";
import {catalog} from "../lib/server-vpn-catalog.mjs";
import {providerIds} from "../lib/server-vpn-provider.mjs";
import {loadProviderState,providerOverview,providerAllowed,providerEffective,updateProvider,
  updateMethodState,synchronizeCatalogVersion} from "../lib/c12-provider-controls.mjs";

const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_FORCE_MAINTENANCE:"false"};
const row=(overview,id)=>overview.providers.find(p=>p.id===id);
const available=overview=>Object.fromEntries(overview.providers.map(p=>[p.id,p.enabled]));
async function fixture(t){
  const root=await mkdtemp(join(tmpdir(),"spdecode-pending-catalogs-"));
  t.after(()=>rm(root,{recursive:true,force:true}));return {root};
}
test("all catalog cards have controls; only documented pending sources default off",async t=>{
  const opts=await fixture(t),overview=await providerOverview(env,opts);
  const apps=catalog({availability:available(overview)}).apps;
  for(const card of apps)assert(row(overview,card.id),card.id);
  for(const id of Object.keys(PENDING_CATALOGS)){
    assert.equal(row(overview,id).administrativelyEnabled,false,id);
    assert.equal(row(overview,id).enabled,false,id);
    assert(row(overview,id).pendingReason,id);
    assert.equal(apps.find(p=>p.id===id).decodeEnabled,false,id);
  }
  assert(row(overview,"dtunnel-mod").enabled);
  assert(row(overview,"at-net-vpn").enabled);
  assert(row(overview,"hx-tunnel").enabled);
});
test("default-off catalogs support on/off, fresh-process reload, and deployment sync",async t=>{
  const opts=await fixture(t),brokers=new Set(providerIds());
  for(const id of Object.keys(PENDING_CATALOGS)){
    const on=await updateProvider(id,true,env,opts);
    assert.equal(row(on,id).administrativelyEnabled,true,id);
    assert.equal(row(on,id).enabled,brokers.has(id),id);
    assert.equal((await loadProviderState(opts.root)).enabled.includes(id),true);
    const fresh=await import("../lib/c12-provider-controls.mjs?reload="+id);
    const reloaded=await fresh.providerOverview(env,opts);
    assert.equal(row(reloaded,id).administrativelyEnabled,true,id);
    const state=await synchronizeCatalogVersion(env,opts);
    assert.equal(providerEffective(id,state,env),brokers.has(id),id);
    assert.equal(catalog({availability:available(reloaded)}).apps.find(p=>p.id===id).decodeEnabled,brokers.has(id),id);
    const repeat=await updateProvider(id,true,env,opts);
    const off=await updateProvider(id,false,env,opts);
    assert(off.catalogVersion>repeat.catalogVersion);
    assert.equal(row(off,id).administrativelyEnabled,false,id);
    assert.equal(await providerAllowed(id,env,opts),false,id);
    assert.equal((await loadProviderState(opts.root)).enabled.includes(id),false);
  }
});
test("legacy disabled catalogs can be reenabled even while prerequisites are missing",async t=>{
  const opts=await fixture(t);
  await writeFile(join(opts.root,"switches.json"),JSON.stringify({version:250000000,disabled:["royal-tunnel","jetroi","http-jireh"]}));
  const prior=await synchronizeCatalogVersion(env,opts);
  assert.deepEqual(prior.disabled,["royal-tunnel","jetroi","http-jireh"]);
  const on=await updateProvider("royal-tunnel",true,env,opts);
  assert.equal(row(on,"royal-tunnel").administrativelyEnabled,true);
  assert.equal(row(on,"royal-tunnel").configured,false);
  assert.equal(row(on,"royal-tunnel").enabled,false);
  assert.equal(catalog({availability:available(on)}).apps.find(p=>p.id==="royal-tunnel").decodeEnabled,false);
  const state=await loadProviderState(opts.root);
  // The saved operator choice becomes effective when a legitimate broker is configured.
  assert(state.enabled.includes("royal-tunnel"));
  assert.deepEqual(state.disabled,["http-jireh","jetroi"]);
  assert.equal(await providerAllowed("jetroi",env,opts),false);
  assert.equal(await providerAllowed("http-jireh",env,opts),false);
});
test("maintenance remains independent of explicit activation",async t=>{
  const opts=await fixture(t),id="jetroi";
  await updateProvider(id,true,env,opts);
  await updateMethodState(id,"maintenance",true,env,opts);
  assert.equal(await providerAllowed(id,env,opts),false);
  assert.equal(row(await providerOverview(env,opts),id).administrativelyEnabled,true);
  await updateMethodState(id,"maintenance",false,env,opts);
  assert.equal(await providerAllowed(id,env,opts),true);
  await updateProvider(id,false,env,opts);
  await updateMethodState(id,"maintenance",true,env,opts);
  await updateMethodState(id,"maintenance",false,env,opts);
  assert.equal(await providerAllowed(id,env,opts),false);
});
test("invalid or conflicting explicit overrides fail closed without rewriting state",async t=>{
  const opts=await fixture(t),path=join(opts.root,"switches.json");
  for(const enabled of [["https://evil.invalid/"],["jetroi","jetroi"],["jetroi"]]){
    const content=JSON.stringify({version:1,disabled:["jetroi"],enabled});
    await writeFile(path,content);
    await assert.rejects(()=>loadProviderState(opts.root),/PROVIDER_STATE_INVALID/);
    assert.equal(await readFile(path,"utf8"),content);
  }
});
