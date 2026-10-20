import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,rm,readFile,writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {
 synchronizeCatalogVersion,providerOverview,updateProvider,loadProviderState
} from "../lib/c12-provider-controls.mjs";

const env={
 CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",
 CLOUD_SERVER_VPN_CATALOG_VERSION:"11",CLOUD_FORCE_MAINTENANCE:"false"
};
test("first catalog sync increments above a previous higher persistent version and preserves disabled providers",async t=>{
 const root=await mkdtemp(join(tmpdir(),"spdecode-catalog-sync-"));
 t.after(async()=>rm(root,{recursive:true,force:true}));
 await writeFile(join(root,"switches.json"),JSON.stringify({
   version:250000000,disabled:["mkk-hyper"]
 })+"\n",{mode:0o600});
 const previous=await loadProviderState(root);
 assert.equal(previous.version,250000000);
 const updated=await synchronizeCatalogVersion(env,{root});
 assert.equal(updated.version,250000001);
 assert.deepEqual(updated.disabled,["mkk-hyper"]);
 assert.match(updated.catalogFingerprint,/^[0-9a-f]{64}$/);
 const repeated=await synchronizeCatalogVersion(env,{root});
 assert.deepEqual(repeated,updated);
 const overview=await providerOverview(env,{root,syncCatalog:true});
 assert.equal(overview.catalogVersion,250000001);
 assert.equal(overview.providers.find(p=>p.id==="mkk-hyper").enabled,false);
 const disabled=await updateProvider("ksh-vpn",false,env,{root});
 assert(disabled.catalogVersion>updated.version);
 const finalState=JSON.parse(await readFile(join(root,"switches.json"),"utf8"));
 assert.equal(finalState.catalogFingerprint,updated.catalogFingerprint);
 assert.deepEqual(finalState.disabled,["ksh-vpn","mkk-hyper"]);
 const stable=await synchronizeCatalogVersion(env,{root});
 assert.equal(stable.version,finalState.version);
});

test("simultaneous first sync is atomic and keeps the roster version stable",async t=>{
 const root=await mkdtemp(join(tmpdir(),"spdecode-catalog-sync-"));
 t.after(async()=>rm(root,{recursive:true,force:true}));
 await writeFile(join(root,"switches.json"),'{"version":9999,"disabled":[]}\n',{mode:0o600});
 const [a,b]=await Promise.all([
   synchronizeCatalogVersion(env,{root}),synchronizeCatalogVersion(env,{root})
 ]);
 assert.equal(a.version,b.version);
 assert(a.version>9999);
 const state=await loadProviderState(root);
 assert.equal(state.version,a.version);
});

test("catalog sync handles local development without provider-control volume",async t=>{
 const root=join(await mkdtemp(join(tmpdir(),"spdecode-no-volume-")),"missing");
 t.after(async()=>rm(root.slice(0,root.lastIndexOf("/")),{recursive:true,force:true}));
 const state=await synchronizeCatalogVersion(env,{root});
 assert.equal(state.version,0);
 assert.deepEqual(state.disabled,[]);
});
