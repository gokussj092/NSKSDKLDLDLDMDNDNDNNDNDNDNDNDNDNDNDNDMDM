import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {audit,parseArgs} from "../scripts/catalog-provider-check.mjs";

test("operator flags are explicit; ambiguous selections fail",()=>{
  assert.deepEqual(parseArgs([]),{enableMM:false,probe:false,
    ids:["mm-tunnel","tunneldoom-vpn"]});
  assert.deepEqual(parseArgs(["--enable-mm","--probe","--mm-only"]),
    {enableMM:true,probe:true,ids:["mm-tunnel"]});
  assert.throws(()=>parseArgs(["--url=https://attacker.invalid/"]),/USAGE/);
  assert.throws(()=>parseArgs(["--mm-only","--tunneldoom-only"]),/USAGE/);
});

function fake(overrides={}){
  const calls=[];
  const api={
    calls,
    providerPrerequisite:id=>{calls.push("prerequisite:"+id);return true;},
    updateProvider:async id=>{calls.push("enable:"+id);},
    updateMethodState:async (id,operation,value)=>{calls.push("method:"+id+":"+operation+":"+value);},
    providerOverview:async()=>({
      catalogVersion:73,
      providers:[{id:"mm-tunnel",enabled:true,configured:true},
        {id:"tunneldoom-vpn",enabled:false,configured:true}],
      methodStatuses:[{id:"mm-tunnel",maintenance:false},
        {id:"tunneldoom-vpn",maintenance:true}],
    }),
    downloadVpnCatalog:async id=>{calls.push("download:"+id);return Buffer.from("synthetic ciphertext");},
    ...overrides,
  };
  return api;
}

test("default status inspection never downloads or changes provider state",async()=>{
  const api=fake(),result=await audit({},api);
  assert.deepEqual(api.calls,[]);
  assert.equal(result.mmStateChanged,false);
  assert(result.providers.every(x=>x.download.state==="not_requested"));
});

test("explicit MM activation only touches MM and respects maintenance",async()=>{
  const api=fake();
  const result=await audit({enableMM:true,ids:["mm-tunnel"]},api);
  assert.equal(result.mmStateChanged,true);
  assert.deepEqual(api.calls,["prerequisite:mm-tunnel",
    "enable:mm-tunnel","method:mm-tunnel:maintenance:false"]);
  assert.equal(result.providers[0].enabled,true);
});

test("disabled prerequisites prevent any state mutation",async()=>{
  const api=fake({providerPrerequisite:()=>false});
  await assert.rejects(()=>audit({enableMM:true},api),/MM_PREREQUISITES_DISABLED/);
  assert.deepEqual(api.calls,[]);
});

test("network is opt-in, ciphertext is never printed; failures are sanitized",async()=>{
  const api=fake({downloadVpnCatalog:async id=>{
    api.calls.push("download:"+id);
    if(id==="tunneldoom-vpn")throw Object.assign(new Error("token=private"),{code:"REMOTE_PROVIDER_UNAVAILABLE"});
    return Buffer.from("synthetic ciphertext");
  },providerOverview:async()=>({
    catalogVersion:73,providers:[
      {id:"mm-tunnel",enabled:true,configured:true},
      {id:"tunneldoom-vpn",enabled:true,configured:true}],
    methodStatuses:[],
  })});
  const result=await audit({probe:true},api);
  assert.deepEqual(api.calls,["download:mm-tunnel","download:tunneldoom-vpn"]);
  assert.equal(result.providers[0].download.sha256,
    createHash("sha256").update("synthetic ciphertext").digest("hex"));
  assert.equal(result.providers[0].download.state,"received_not_decoded");
  assert.deepEqual(result.providers[1].download,
    {state:"failed",code:"REMOTE_PROVIDER_UNAVAILABLE"});
  assert(!JSON.stringify(result).includes("synthetic ciphertext"));
  assert(!JSON.stringify(result).includes("token=private"));
});

test("disabled providers never trigger vendor requests",async()=>{
  const api=fake(),result=await audit({probe:true},api);
  assert.equal(result.providers[1].download.state,"skipped_provider_disabled");
  assert.deepEqual(api.calls,["download:mm-tunnel"]);
});
