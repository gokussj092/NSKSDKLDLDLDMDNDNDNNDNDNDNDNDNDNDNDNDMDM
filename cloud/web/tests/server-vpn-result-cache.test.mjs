import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,readFile,writeFile,rm,utimes,readdir} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {sharedCatalog,renewDemandedCatalog,TTL_MS,REFRESH_AHEAD_MS,cacheable} from "../lib/server-vpn-result-cache.mjs";

class RedisFixture {
 constructor(){this.data=new Map();this.active=0;}
 async get(k){const v=this.data.get(k);if(v&&v.until<=Date.now()){this.data.delete(k);return null;}return v?.value??null;}
 async set(k,value,{NX=false,PX,EX}={}){
  if(NX&&await this.get(k)!==null)return null;
  // No await between ownership test and assignment in this fixture.
  if(NX&&this.data.has(k))return null;
  this.data.set(k,{value,until:Date.now()+(PX??(EX??86400)*1000)});return "OK";
 }
 async eval(script,{keys,arguments:args}){if(await this.get(keys[0])!==args[0])return 0;this.data.delete(keys[0]);return 1;}
 async zCard(){return this.active;}
 async zRemRangeByScore(){return 0;}
}
const result=(text,extra={})=>Response.json({status:"success",rawText:text,isPartial:false,requestId:"original-private-id",...extra});
async function fixture(t,extra={}){
 const root=await mkdtemp(join(tmpdir(),"catalog-cache-"));t.after(()=>rm(root,{recursive:true,force:true}));
 const r=new RedisFixture(),clock={value:Date.now()},calls={value:0};
 const cfg={id:"sample-vpn",revision:"test-v1",secret:"cache-test-secret".repeat(3),root,enabled:true,
  now:()=>clock.value,sleep:()=>new Promise(r=>setTimeout(r,15)),waitMs:5000,
  load:async()=>result("fixture-"+(++calls.value)),...extra};
 return {r,cfg,clock,calls,path:join(root,"catalog-sample-vpn.bin")};
}
test("shared result: worker called once; disk encrypted; new requestId and no-store",async t=>{
 const {r,cfg,calls,path}=await fixture(t);
 const x=await (await sharedCatalog(r,cfg)).json();
 const second=await sharedCatalog(r,cfg),y=await second.json();
 const third=await (await sharedCatalog(r,cfg)).json();
 assert.equal(calls.value,1);assert.equal(x.rawText,y.rawText);assert.equal(third.rawText,y.rawText);
 assert.notEqual(y.requestId,x.requestId);assert.notEqual(y.requestId,third.requestId);
 assert.match(second.headers.get("cache-control"),/no-store/);
 const disk=await readFile(path);assert.equal(disk.includes(Buffer.from("fixture-1")),false);
 assert.equal(disk.includes(Buffer.from("original-private-id")),false);
});
test("concurrent misses use just one load",async t=>{
 const {r,cfg,calls}=await fixture(t);
 cfg.load=async()=>{calls.value++;await new Promise(r=>setTimeout(r,50));return result("one-result");};
 const all=await Promise.all(Array.from({length:12},()=>sharedCatalog(r,cfg)));
 assert.equal(calls.value,1);
 assert.deepEqual(await Promise.all(all.map(async r=>(await r.json()).rawText)),Array(12).fill("one-result"));
});
test("refresh ahead uses active demand; serves fresh copy while renewal runs",async t=>{
 const {r,cfg,clock,calls,path}=await fixture(t);
 await sharedCatalog(r,cfg);
 clock.value+=TTL_MS-REFRESH_AHEAD_MS+1000;
 const oldMtime=new Date(Date.now()-(TTL_MS-REFRESH_AHEAD_MS+1000));await utimes(path,oldMtime,oldMtime);
 r.active=1;assert.equal(await renewDemandedCatalog(r,[cfg]),false);r.active=0;
 let unblock;const completion=new Promise(resolve=>{unblock=resolve;});
 let entered;const loading=new Promise(resolve=>{entered=resolve;});
 const renewal=renewDemandedCatalog(r,[{...cfg,load:async()=>{calls.value++;entered();await completion;return result("renewed");}}]);
 await loading;assert.equal((await (await sharedCatalog(r,cfg)).json()).rawText,"fixture-1");
 unblock();assert.equal(await renewal,true);
 assert.equal((await (await sharedCatalog(r,cfg)).json()).rawText,"renewed");
 assert.equal(calls.value,2);
 assert.equal(await renewDemandedCatalog(r,[cfg]),false);
});
test("failed refresh keeps still-valid result; expiration fails closed",async t=>{
 const {r,cfg,clock,path}=await fixture(t);
 await sharedCatalog(r,cfg);
 clock.value+=TTL_MS-REFRESH_AHEAD_MS+1000;
 const oldMtime=new Date(Date.now()-TTL_MS+REFRESH_AHEAD_MS-1000);await utimes(path,oldMtime,oldMtime);
 assert.equal(await renewDemandedCatalog(r,[{...cfg,load:async()=>Response.json({error:{code:"REMOTE_PROVIDER_UNAVAILABLE"}},{status:502})}]),true);
 assert.equal((await (await sharedCatalog(r,cfg)).json()).rawText,"fixture-1");
 clock.value+=REFRESH_AHEAD_MS;
 await assert.rejects(()=>sharedCatalog(r,cfg),/SERVICE_UNAVAILABLE/);
});
test("cache misses after revision change, tampering or signing secret rotation",async t=>{
 const {r,cfg,calls,path}=await fixture(t);
 await sharedCatalog(r,cfg);
 const newCfg={...cfg,revision:"test-v2"};
 assert.equal((await (await sharedCatalog(r,newCfg)).json()).rawText,"fixture-2");
 const buf=await readFile(path);buf[buf.length-1]^=1;await writeFile(path,buf);
 assert.equal((await (await sharedCatalog(r,newCfg)).json()).rawText,"fixture-3");
 const rotated={...newCfg,secret:"new-test-secret".repeat(4)};
 assert.equal((await (await sharedCatalog(r,rotated)).json()).rawText,"fixture-4");assert.equal(calls.value,4);
});
test("expired result cannot be served; eligible provider is downloaded again",async t=>{
 const {r,cfg,clock,calls}=await fixture(t);
 await sharedCatalog(r,cfg);clock.value+=TTL_MS;
 assert.equal((await (await sharedCatalog(r,cfg)).json()).rawText,"fixture-2");assert.equal(calls.value,2);
});
test("partial, failure, disabled and excluded providers cannot publish",async t=>{
 const {r,cfg,calls}=await fixture(t);
 assert.equal(cacheable("opentunnel-ssh"),false);
 assert.equal(cacheable("speigo-vpn-ssh"),false);
 assert.equal(cacheable("mkk-hyper"),false);
 assert.equal(cacheable("../escape"),false);
 const partial=await sharedCatalog(r,{...cfg,load:async()=>result("partial",{isPartial:true})});
 assert.equal((await partial.json()).isPartial,true);
 assert.deepEqual(await readdir(cfg.root),[]);
 await sharedCatalog(r,{...cfg,id:"disabled",enabled:false});
 await sharedCatalog(r,{...cfg,id:"mkk-hyper"});
 assert.deepEqual(await readdir(cfg.root),[]);
 assert.equal(calls.value,2);
});
test("maintenance or provider revocation prevents use and publication",async t=>{
 const {r,cfg}=await fixture(t);await sharedCatalog(r,cfg);
 await assert.rejects(()=>sharedCatalog(r,{...cfg,isCurrent:async()=>false}),/SERVICE_UNAVAILABLE/);
 assert.equal(await renewDemandedCatalog(r,[{...cfg,isCurrent:async()=>false}]),false);
});
test("scheduler never warms catalog without user demand",async t=>{
 const {r,cfg,calls}=await fixture(t);assert.equal(await renewDemandedCatalog(r,[cfg]),false);assert.equal(calls.value,0);
});
