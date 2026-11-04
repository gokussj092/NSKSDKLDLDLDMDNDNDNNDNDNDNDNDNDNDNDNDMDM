import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {syncBuiltinESMExports} from "node:module";
import https from "node:https";
import dns from "node:dns/promises";
import {EventEmitter} from "node:events";
import {createHash} from "node:crypto";
import {mkdtemp,rm,readFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {HALCON_SOURCE,halconConfigured,halconRequest} from "../lib/halcon-protocol.mjs";
import {providerEnabled,providerIds,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {catalog,CATALOG_VERSION,iconFor} from "../lib/server-vpn-catalog.mjs";
import {PUBLIC_PROVIDER_IDS,updateProvider,providerAllowed} from "../lib/c12-provider-controls.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";

const synthetic={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",SPDECODE_HALCON_REQUEST_SECRET:"synthetic-request-key!",
  SPDECODE_HALCON_CATALOG_PASSWORD:"S".repeat(65)+"A".repeat(64)};
const expected=JSON.parse(fs.readFileSync(new URL("../../../analysis/com.halcon.connect/1391/tests/fixtures/catalog.expected.json",import.meta.url)));
function env(t){
  for(const [key,value] of Object.entries(synthetic)){
    const old=process.env[key];process.env[key]=value;
    t.after(()=>{if(old===undefined)delete process.env[key];else process.env[key]=old;});
  }
}
function network(t,{data=Buffer.from("synthetic encrypted envelope"),status=200,location,check=()=>{}}={}){
  t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
  t.mock.method(https,"request",(url,options,callback)=>{
    const req=new EventEmitter();req.destroy=()=>{};
    req.end=body=>queueMicrotask(()=>{
      check(url,options,body);
      const res=new EventEmitter();res.resume=()=>{};res.statusCode=status;
      res.headers=location?{location}:{};callback(res);
      if(!location&&status===200){res.emit("data",data);res.emit("end");}
    });return req;
  });
}
function iconFixture(t){
  // Independent icon files are outside this focused test's scope. Use the real
  // Halcon raster as a harmless stand-in while catalog() enumerates other IDs.
  const read=fs.readFileSync;
  const png=read(new URL("../public/server-vpn-icons/halcon-r-net.png",import.meta.url));
  t.mock.method(fs,"readFileSync",(path,...args)=>String(path).includes("server-vpn-icons")?png:read(path,...args));
  syncBuiltinESMExports();
  t.after(()=>{t.mock.restoreAll();syncBuiltinESMExports();});
  return png;
}
test("Halcon signing matches the original timestamp+secret protocol",()=>{
  const timestamp=1793692575;
  assert(halconConfigured(synthetic));
  const signed=halconRequest(synthetic,timestamp);
  const hash=createHash("sha256").update(String(timestamp)+synthetic.SPDECODE_HALCON_REQUEST_SECRET).digest("hex");
  assert.equal(signed.headers["X-Auth-Hash"],hash);
  assert.equal(signed.headers["X-Timestamp"],String(timestamp));
  assert.equal(signed.headers["X-App-ID"],"HalconRNet_2026");
  assert.equal(signed.body.toString(),`hash=${hash}&timestamp=${timestamp}`);
  assert(!signed.body.includes(Buffer.from(synthetic.SPDECODE_HALCON_CATALOG_PASSWORD)));
  assert.throws(()=>halconRequest(synthetic,-1));
});
test("Halcon requires both secrets before DNS or download",async t=>{
  env(t);
  assert(providerIds().includes("halcon-r-net"));assert(PUBLIC_PROVIDER_IDS.includes("halcon-r-net"));
  t.mock.method(dns,"lookup",()=>{throw Error("unexpected DNS");});
  for(const key of ["SPDECODE_HALCON_REQUEST_SECRET","SPDECODE_HALCON_CATALOG_PASSWORD"]){
    const old=process.env[key];process.env[key]="";
    assert.equal(providerEnabled("halcon-r-net"),false);
    await assert.rejects(()=>downloadVpnCatalog("halcon-r-net"),{code:"REMOTE_NOT_CONFIGURED"});
    process.env[key]=old;
    assert.equal(halconConfigured({...synthetic,[key]:"bad\r\nInjected: value"}),false);
    assert.equal(halconConfigured({...synthetic,[key]:synthetic[key]+"\n"}),false);
  }
});
test("Halcon sends one signed POST only to the fixed original TLS destination",async t=>{
  env(t);let calls=0;
  network(t,{check:(url,options,body)=>{
    calls++;assert.equal(url.href,HALCON_SOURCE);assert.equal(options.method,"POST");
    assert.equal(options.rejectUnauthorized,true);assert.equal(options.headers["User-Agent"],"Dalvik/2.1.0");
    assert.equal(options.headers["Accept-Encoding"],"identity");
    const stamp=options.headers["X-Timestamp"];
    const hash=createHash("sha256").update(stamp+synthetic.SPDECODE_HALCON_REQUEST_SECRET).digest("hex");
    assert.equal(options.headers["X-Auth-Hash"],hash);
    assert.equal(body.toString(),`hash=${hash}&timestamp=${stamp}`);
    assert(!JSON.stringify(options).includes(synthetic.SPDECODE_HALCON_CATALOG_PASSWORD));
  }});
  assert.equal((await downloadVpnCatalog("halcon-r-net")).toString(),"synthetic encrypted envelope");
  await assert.rejects(()=>downloadVpnCatalog("halcon-r-net","https://example.org/"),{code:"UNSUPPORTED_FORMAT"});
  assert.equal(calls,1);
});
test("Halcon rejects private DNS, redirects, HTML and does not retry signed POSTs",async t=>{
  env(t);let calls=0;
  network(t,{status:503,check:()=>{calls++;}});
  await assert.rejects(()=>downloadVpnCatalog("halcon-r-net"),{code:"REMOTE_PROVIDER_UNAVAILABLE"});
  assert.equal(calls,1);
  network(t,{location:"https://example.org/",status:302,check:()=>{calls++;}});
  await assert.rejects(()=>downloadVpnCatalog("halcon-r-net"),{code:"REMOTE_NETWORK_DENIED"});
  assert.equal(calls,2);
  network(t,{data:Buffer.from("<html>error</html>")});
  await assert.rejects(()=>downloadVpnCatalog("halcon-r-net"),{code:"REMOTE_RESPONSE_INVALID"});
  t.mock.method(dns,"lookup",async()=>[{address:"127.0.0.1",family:4}]);
  await assert.rejects(()=>downloadVpnCatalog("halcon-r-net"),{code:"REMOTE_NETWORK_DENIED"});
});
test("Halcon original raster, public card and configured availability",t=>{
  env(t);const png=iconFixture(t);
  assert.equal(CATALOG_VERSION,69);
  assert.equal(createHash("sha256").update(png).digest("hex"),"859825df9e151d9b77039cc7f4a42b75feb3b9ea823999fa567ec823a173f143");
  const doc=catalog(),card=doc.apps.find(x=>x.id==="halcon-r-net");
  assert.equal(doc.apps.length,65);assert.equal(card.name,"HALCON RAMOS Conectividad");
  assert.equal(card.decodeEnabled,true);assert.equal(iconFor(card.id).bytes.length,71433);
  assert.equal(catalog({availability:{"halcon-r-net":false}}).apps.find(x=>x.id===card.id).decodeEnabled,false);
  assert.equal(catalog({methodStates:{"halcon-r-net":{maintenance:true}}}).apps.find(x=>x.id===card.id).decodeEnabled,false);
  delete process.env.SPDECODE_HALCON_REQUEST_SECRET;
  assert.equal(catalog().apps.find(x=>x.id===card.id).decodeEnabled,false);
  assert(!JSON.stringify(doc).includes(synthetic.SPDECODE_HALCON_CATALOG_PASSWORD));
});
test("Halcon persistent switch preserves other operators' choices",async t=>{
  env(t);iconFixture(t);
  const root=await mkdtemp(join(tmpdir(),"halcon-switch-"));t.after(()=>rm(root,{recursive:true,force:true}));
  await updateProvider("netcol-vpn",false,synthetic,{root});
  await updateProvider("halcon-r-net",false,synthetic,{root});
  assert.equal(await providerAllowed("halcon-r-net",synthetic,{root}),false);
  await updateProvider("halcon-r-net",true,synthetic,{root});
  assert.equal(await providerAllowed("halcon-r-net",synthetic,{root}),true);
  assert.equal(await providerAllowed("netcol-vpn",synthetic,{root}),false);
  const stored=await readFile(join(root,"switches.json"),"utf8");
  assert(!stored.includes(synthetic.SPDECODE_HALCON_REQUEST_SECRET));
});
test("Halcon worker contract accepts the full document and rejects partial or malformed results",async t=>{
  const prev=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  t.after(()=>{if(prev===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=prev;});
  const good={apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"halcon-r-net",
    structuredJson:expected,rawText:JSON.stringify(expected),isPartial:false,warnings:[],exporterCertified:false};
  const call=body=>fetchWorker("server-vpn",{providerId:"halcon-r-net"},{workerToken:"w".repeat(48)},
    {fetchImpl:async()=>Response.json(body)});
  assert.deepEqual((await (await call(good)).json()).structuredJson,expected);
  for(const bad of [{...good,isPartial:true},{...good,providerId:"other"},
      {...good,structuredJson:{...expected,servers:[]},rawText:JSON.stringify({...expected,servers:[]})},
      {...good,rawText:JSON.stringify({...expected,version:"changed"})}]){
    await assert.rejects(()=>call(bad),/INVALID_WORKER_RESULT/);
  }
  const invalid=structuredClone(expected);delete invalid.servers[0].password;
  await assert.rejects(()=>call({...good,structuredJson:invalid,rawText:JSON.stringify(invalid)}),/INVALID_WORKER_RESULT/);
});
