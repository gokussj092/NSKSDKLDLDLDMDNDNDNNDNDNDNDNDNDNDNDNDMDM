import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,rm} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {catalog,CATALOG_VERSION,iconFor} from "../lib/server-vpn-catalog.mjs";
import {providerIds,providerEnabled} from "../lib/server-vpn-provider.mjs";
import {PUBLIC_PROVIDER_IDS,updateProvider,providerOverview} from "../lib/c12-provider-controls.mjs";

test("ANY and Speicers are public cards with original icons and operator availability",()=>{
  const doc=catalog({availability:{"any-vpn":true,"speicers-pro-vpn":true}});
  assert.equal(doc.apps.length,47);
  assert.equal(CATALOG_VERSION,50);
  const expected={
    "any-vpn":["ANY VPN",44411,"f111f88d18e14dd0eb934cfdafd0be0a8a74197c66e499be317b7c50fc11b38c"],
    "speicers-pro-vpn":["Speicers Pro VPN",34275,"8c49bc17d883ffee1275b113a12e1d4696b95e1bfba57dd0ebe8346e82be6e91"],
  };
  for(const [id,[name,bytes,hash]] of Object.entries(expected)){
    const card=doc.apps.find(x=>x.id===id);
    assert.equal(card.name,name);assert.equal(card.decodeEnabled,true);
    assert.equal(card.iconSha256,hash);assert.equal(iconFor(id).bytes.length,bytes);
    assert(providerIds().includes(id));assert(PUBLIC_PROVIDER_IDS.includes(id));
    assert.equal(providerEnabled(id,{CLOUD_SERVER_VPN_ENABLED:"true"}),true);
    assert.equal(providerEnabled(id,{CLOUD_SERVER_VPN_ENABLED:"false"}),false);
    assert.equal(catalog({availability:{[id]:false}}).apps.find(x=>x.id===id).decodeEnabled,false);
    assert(!JSON.stringify(card).includes("https://"));
  }
});

test("both new cards use persistent switches without resetting previously disabled providers",async t=>{
  const root=await mkdtemp(join(tmpdir(),"spdecode-any-speicers-"));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
  await updateProvider("mkk-hyper",false,env,{root});
  const first=await updateProvider("any-vpn",false,env,{root});
  const second=await updateProvider("speicers-pro-vpn",false,env,{root});
  assert(second.catalogVersion>first.catalogVersion);
  const overview=await providerOverview(env,{root});
  for(const id of ["any-vpn","speicers-pro-vpn","mkk-hyper"])
    assert.equal(overview.providers.find(x=>x.id===id).enabled,false);
  assert.equal(overview.providers.find(x=>x.id==="any-vpn").name,"ANY VPN");
  assert.equal(overview.providers.find(x=>x.id==="speicers-pro-vpn").name,"Speicers Pro VPN");
});
