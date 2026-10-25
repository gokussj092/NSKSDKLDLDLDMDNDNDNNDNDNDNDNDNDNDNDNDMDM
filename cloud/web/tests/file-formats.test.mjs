import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {catalog,CATALOG_VERSION} from "../lib/server-vpn-catalog.mjs";
import {validatePublicFormats,publicFormats} from "../lib/file-format-catalog.mjs";
import {POST as endpoint} from "../app/api/v1/server-vpn/catalog/route.js";

const project=(name)=>readFileSync(new URL("../../../"+name,import.meta.url),"utf8");
const request=(knownVersion)=>new Request("https://api.spdecode.xyz/api/v1/server-vpn/catalog",{
  method:"POST",headers:{"content-type":"application/json"},
  body:JSON.stringify({knownVersion}),
});

test("all C0 and C8 file routes are published once, without decoder implementation details",()=>{
  const matrix=project("docs/cloud/C0_FORMAT_MATRIX.csv").trimEnd().split("\n").slice(1).map(s=>s.split(",")[0]);
  const engine=project("cloud/workers/python/engine.py");
  const block=engine.split("_C8_FILE_ENGINES = {")[1]?.split("\ndef load_runtime_file_engines")[0];
  assert(block);
  const additional=[...block.matchAll(/^\s*"([^"]+)": \("([^"]+)", "([^"]+)"\),/gm)].map(m=>m[1]);
  assert.equal(matrix.length,240);
  assert(additional.length>=18);
  const known=new Set([...matrix,...additional]);
  assert(known.size>=250);
  const current=publicFormats();
  assert.equal(current.length,known.size);
  assert.deepEqual(new Set(current.map(f=>f.suffix)),known);
  const native=new Set(JSON.parse(project("android/app/src/main/assets/decoder_catalog.json")).entries.map(x=>x.suffix));
  native.add("solid");
  assert.equal(native.size,240);
  for(const entry of current){
    assert.deepEqual(Object.keys(entry),[
      "suffix","name","kind","offlineSupported","cloudSupported","credentialFields",
    ]);
    assert.equal(entry.offlineSupported,native.has(entry.suffix));
    assert.equal(entry.cloudSupported,true);
    assert.equal(entry.kind,"file");
    assert(!("script" in entry) && !("originalRuntime" in entry) && !("key" in entry));
  }
  assert.equal(current.filter(x=>!x.offlineSupported).length,known.size-native.size);
});

test("extension precedence, native/cloud overlap and credential metadata",()=>{
  const formats=publicFormats();
  const candidates=filename=>formats.filter(x=>filename.toLowerCase().endsWith("."+x.suffix));
  assert.equal(candidates("backup.sksrv.png")[0].suffix,"sksrv.png");
  assert.equal(formats.find(x=>x.suffix==="npvs").credentialFields.join(","),"password,publicKey");
  assert.equal(formats.find(x=>x.suffix==="hc").credentialFields.join(","),"password,hwid");
  assert.equal(formats.find(x=>x.suffix==="mmt").name,"MM Tunnel v1.10.11.1");
  assert.deepEqual(formats.find(x=>x.suffix==="mmt").credentialFields,[]);
  assert.equal(formats.find(x=>x.suffix==="1ftnl").offlineSupported,false);
  assert.equal(formats.find(x=>x.suffix==="1ftnl").cloudSupported,true);
  assert.equal(formats.find(x=>x.suffix==="fɴ").offlineSupported,true);
});

test("HTTP Door publishes its file route and refreshes cached v44 metadata without adding a server provider",async()=>{
  const format=publicFormats().find(x=>x.suffix==="kyz");
  assert.deepEqual(format,{suffix:"kyz",name:"HTTP Door 5.0",kind:"file",
    offlineSupported:false,cloudSupported:true,credentialFields:[]});
  assert.equal(CATALOG_VERSION,47);
  const response=await endpoint(request(44));
  assert.equal(response.status,200);
  const body=await response.json();
  assert.equal(body.unchanged,false);
  assert.equal(body.apps.length,47);
  assert(!body.apps.some(x=>x.id==="http-door"));
  assert(body.formats.some(x=>x.suffix==="kyz"));
});

test("catalog response is backwards-compatible and uses the existing version contract",async()=>{
  const result=catalog();
  assert.equal(result.catalogVersion,CATALOG_VERSION);
  assert.equal(result.formatsSchemaVersion,1);
  assert.deepEqual(result.formatDetection,{
    rule:"longest-filename-suffix",caseInsensitive:true,separator:".",
  });
  assert.equal(result.formatCount,publicFormats().length);
  assert.equal(result.formats.length,publicFormats().length);
  assert.equal(result.apps.length,47);
  const payload=JSON.stringify(result);
  for(const forbidden of [
    "decoders/Python/",'"script":',"source_script","originalRuntime",
    "migrationPhase","androidPortStatus","__proto__","privateKey",
  ]) assert(!payload.includes(forbidden),forbidden);
  const response=await endpoint(request(0));
  assert.equal(response.status,200);
  const body=await response.json();
  assert.equal(body.unchanged,false);
  assert.equal(body.formats.length,publicFormats().length);
  assert.equal(body.apps.length,47);
  const unchanged=await endpoint(request(body.catalogVersion));
  assert.equal(unchanged.status,200);
  const hint=await unchanged.json();
  assert.equal(hint.unchanged,true);
  assert.equal(hint.catalogVersion,body.catalogVersion);
  assert(!("formats" in hint) && !("apps" in hint));
});

test("Cloud catalog v38 refreshes AWG and password-protected UA without an APK update",async()=>{
  // The catalog is metadata only; decoding remains on the allowlisted VPS worker.
  assert(CATALOG_VERSION>=38);
  const formats=publicFormats();
  const awg=formats.find(f=>f.suffix==="awg");
  const ua=formats.find(f=>f.suffix==="ua");
  assert.deepEqual(awg,{
    suffix:"awg",name:"AboWaged VPN 1.0",kind:"file",
    offlineSupported:false,cloudSupported:true,credentialFields:[],
  });
  assert.deepEqual(ua,{
    suffix:"ua",name:"Ultra Custom",kind:"file",
    offlineSupported:false,cloudSupported:true,credentialFields:["password"],
  });
  const worker=project("cloud/workers/python/engine.py");
  assert(worker.includes('"awg": ("decoders/Python/apps/AboWaged_VPN/file_decoder.py"'));
  assert(worker.includes('"ua": ("decoders/Python/apps/Ultra_Custom/ultra_custom_52.py"'));
  const response=await endpoint(request(37));
  assert.equal(response.status,200);
  const body=await response.json();
  assert.equal(body.unchanged,false);
  assert(body.catalogVersion>37);
  assert.deepEqual(body.formats.find(f=>f.suffix==="awg"),awg);
  assert.deepEqual(body.formats.find(f=>f.suffix==="ua"),ua);
});

test("schema rejects duplicate, invented or executable fields",()=>{
  const clean=JSON.parse(project("cloud/web/content/file-formats.json"));
  const clone=()=>JSON.parse(JSON.stringify(clean));
  assert.equal(validatePublicFormats(clean).length,publicFormats().length);
  const duplicate=clone();duplicate.formats[1].suffix=duplicate.formats[0].suffix;
  assert.throws(()=>validatePublicFormats(duplicate));
  const script=clone();script.formats[0].script="custom.py";
  assert.throws(()=>validatePublicFormats(script));
  const invalid=clone();invalid.formats[0].suffix="../etc/passwd";
  assert.throws(()=>validatePublicFormats(invalid));
  const order=clone();order.formats.reverse();
  assert.throws(()=>validatePublicFormats(order));
  const unknown=clone();unknown.formats[0].credentialFields=["arbitraryCode"];
  assert.throws(()=>validatePublicFormats(unknown));
});
