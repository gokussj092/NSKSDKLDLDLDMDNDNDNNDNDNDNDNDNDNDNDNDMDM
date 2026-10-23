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
  assert.equal(additional.length,18);
  const known=new Set([...matrix,...additional]);
  assert.equal(known.size,250);
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
  assert.equal(current.filter(x=>!x.offlineSupported).length,10);
});

test("extension precedence, native/cloud overlap and credential metadata",()=>{
  const formats=publicFormats();
  const candidates=filename=>formats.filter(x=>filename.toLowerCase().endsWith("."+x.suffix));
  assert.equal(candidates("backup.sksrv.png")[0].suffix,"sksrv.png");
  assert.equal(formats.find(x=>x.suffix==="npvs").credentialFields.join(","),"password,publicKey");
  assert.equal(formats.find(x=>x.suffix==="hc").credentialFields.join(","),"password,hwid");
  assert.equal(formats.find(x=>x.suffix==="1ftnl").offlineSupported,false);
  assert.equal(formats.find(x=>x.suffix==="1ftnl").cloudSupported,true);
  assert.equal(formats.find(x=>x.suffix==="fɴ").offlineSupported,true);
});

test("catalog response is backwards-compatible and uses the existing version contract",async()=>{
  const result=catalog();
  assert.equal(result.catalogVersion,CATALOG_VERSION);
  assert.equal(result.formatsSchemaVersion,1);
  assert.equal(result.formatCount,250);
  assert.equal(result.formats.length,250);
  assert.equal(result.apps.length,38);
  const payload=JSON.stringify(result);
  for(const forbidden of [
    "decoders/Python/","\\\"script\\\":","source_script","originalRuntime",
    "migrationPhase","androidPortStatus","__proto__","privateKey",
  ]) assert(!payload.includes(forbidden),forbidden);
  const response=await endpoint(request(0));
  assert.equal(response.status,200);
  const body=await response.json();
  assert.equal(body.unchanged,false);
  assert.equal(body.formats.length,250);
  assert.equal(body.apps.length,38);
  const unchanged=await endpoint(request(body.catalogVersion));
  assert.equal(unchanged.status,200);
  const hint=await unchanged.json();
  assert.equal(hint.unchanged,true);
  assert.equal(hint.catalogVersion,body.catalogVersion);
  assert(!("formats" in hint) && !("apps" in hint));
});

test("schema rejects duplicate, invented or executable fields",()=>{
  const clean=JSON.parse(project("cloud/web/content/file-formats.json"));
  const clone=()=>JSON.parse(JSON.stringify(clean));
  assert.equal(validatePublicFormats(clean).length,250);
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
