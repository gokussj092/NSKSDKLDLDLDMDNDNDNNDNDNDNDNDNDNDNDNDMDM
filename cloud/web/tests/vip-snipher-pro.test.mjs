import test from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import {catalog,CATALOG_VERSION,iconFor} from "../lib/server-vpn-catalog.mjs";
import {providerEnabled,providerIds,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
import {POST as icon} from "../app/api/v1/server-vpn/icon/route.js";

test("VIP Snipher original icon remains visible with remote download disabled",()=>{
  const doc=catalog({availability:{"vip-snipher-pro":true}});
  assert.equal(CATALOG_VERSION,59);assert.equal(doc.apps.length,53);
  const card=doc.apps.find(x=>x.id==="vip-snipher-pro");
  assert.equal(card.name,"VIP Snipher Pro");assert.equal(card.decodeEnabled,false);
  assert.equal(card.iconSha256,"6a2ecaacc5fdf2a20f23cf31a58838854d7573dfb58c738274e150c31978e1e6");
  assert.equal(iconFor(card.id).bytes.length,25374);
  assert(!JSON.stringify(card).includes("https://"));
  assert.equal(doc.formats.length,254);
  assert(!doc.formats.some(x=>x.suffix==="js"||x.suffix==="rj"));
});

test("VIP unavailable updater is never offered as an operational broker",async t=>{
  t.mock.method(https,"request",()=>{throw Error("unexpected provider transport");});
  assert(!providerIds().includes("vip-snipher-pro"));
  assert(!PUBLIC_PROVIDER_IDS.includes("vip-snipher-pro"));
  assert.equal(providerEnabled("vip-snipher-pro",{CLOUD_SERVER_VPN_ENABLED:"true"}),false);
  await assert.rejects(()=>downloadVpnCatalog("vip-snipher-pro"),{code:"UNSUPPORTED_FORMAT"});
  assert(!catalog().apps.some(x=>x.id==="90net-vpn"));
});

test("VIP original icon is downloadable through the existing metadata API",async()=>{
  const response=await icon(new Request("https://api.example.test/api/v1/server-vpn/icon",{
    method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:"vip-snipher-pro"}),
  }));
  assert.equal(response.status,200);
  const result=await response.json();
  assert.deepEqual(Buffer.from(result.contentBase64,"base64"),iconFor("vip-snipher-pro").bytes);
});

const document={Version:"synthetic-29",Servers:[{Name:"test",unknown:true}],Networks:[{Name:"payload",Payload:"test"}]};
const result=()=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"vip-snipher-pro",
  structuredJson:document,rawText:JSON.stringify(document),isPartial:false,warnings:[],exporterCertified:false});
test("VIP internal worker result preserves the complete offline document and rejects partial output",async t=>{
  const previous=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  t.after(()=>{if(previous===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=previous;});
  const input={providerId:"vip-snipher-pro"},settings={workerToken:"w".repeat(48)};
  const response=await fetchWorker("server-vpn",input,settings,{fetchImpl:async()=>Response.json(result())});
  assert.deepEqual((await response.json()).structuredJson,document);
  for(const bad of [
    {...result(),providerId:"other"},{...result(),kind:"file"},
    {...result(),isPartial:true},{...result(),rawText:"not JSON"},
    {...result(),rawText:JSON.stringify({...document,Networks:[]})},
    {...result(),rawText:JSON.stringify({...document,Servers:[]}),structuredJson:{...document,Servers:[]}},
    {...result(),rawText:JSON.stringify({...document,Networks:[1]}),structuredJson:{...document,Networks:[1]}},
  ])await assert.rejects(()=>fetchWorker("server-vpn",input,settings,{fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
});
