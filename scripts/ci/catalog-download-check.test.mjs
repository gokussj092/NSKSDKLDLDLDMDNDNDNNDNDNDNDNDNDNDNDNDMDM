import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {createHash} from "node:crypto";
import {EventEmitter} from "node:events";
import dns from "node:dns/promises";
import https from "node:https";
import {SERVER_VPN_METHODS} from "../../cloud/web/lib/server-vpn-catalog.mjs";
import {providerIds} from "../../cloud/web/lib/server-vpn-provider.mjs";
import {
  sourceMap,buildPlan,inspectPayload,validateBaseline,compareResult,
  observeDownload,probeInWorker,runChecks,markdown,
} from "./catalog-download-check.mjs";

const source=await readFile(new URL("../../cloud/web/lib/server-vpn-provider.mjs",import.meta.url),"utf8");
const baseline=()=>({schemaVersion:1,scope:"TRANSPORT_ONLY_NO_DECRYPTION",entries:{}});
const good=()=>inspectPayload(Buffer.from('{"version":1,"servers":[{"name":"Owned fixture"}]}'));
const reference=value=>Object.fromEntries(["payloadKind","bodySha256","shapeSha256"].map(k=>[k,value[k]]));

test("every roster entry and every current broker provider is included",()=>{
  const plan=buildPlan(source),ids=new Set(plan.map(p=>p.id));
  assert.deepEqual(ids,new Set(SERVER_VPN_METHODS.map(p=>p.id)));
  for(const id of providerIds())assert.ok(ids.has(id),id);
  assert.equal(new Set(plan.map(p=>p.id+"/"+p.source)).size,plan.length);
  assert.equal(plan.find(p=>p.id==="nur-tunnel").route,"nur");
  assert.equal(plan.find(p=>p.id==="ut-loop-pro-vpn").route,"unconfigured");
});
test("paired sources, both subscription variants and all MKK sources are covered",()=>{
  const map=sourceMap(source);
  for(const id of ["speicers-turbo-vpn","turbomx-vpn","http-wakko","http-socketclay"])
    assert.deepEqual(map.get(id),["servers","users"]);
  assert.deepEqual(map.get("jyfast-vpn-ultra"),["free","premium"]);
  assert.deepEqual(map.get("abowaged-vpn"),["servers","udp"]);
  assert.deepEqual(map.get("v2ray-tunnel-plus"),["base64","raw"]);
  assert.deepEqual(map.get("mkk-hyper"),["servers","static","subscriptions","legacy-subscriptions"]);
  assert.doesNotMatch(JSON.stringify([...map]),/https?:/);
});
test("a new registered provider is picked up without maintaining another provider list",()=>{
  const ids=[...providerIds(),"owned-new-provider"];
  const roster=[...SERVER_VPN_METHODS,{id:"owned-new-provider",name:"Owned new provider"}];
  assert.deepEqual(buildPlan(source,roster,ids).at(-1),
    {id:"owned-new-provider",name:"Owned new provider",source:"servers",route:"broker"});
});
test("inventory grammar changes and missing roster entries fail visibly",()=>{
  assert.throws(()=>sourceMap(source.replace("const PAIRED_SOURCES","const RENAMED")),/INVENTORY/);
  assert.throws(()=>buildPlan(source,SERVER_VPN_METHODS.filter(x=>x.id!=="mm-tunnel")),/ROSTER/);
  assert.throws(()=>sourceMap(source.replace('"speicers-turbo-vpn":SPEICERS_TURBO_SOURCES',
    '"owned-missing":SPEICERS_TURBO_SOURCES')),/UNKNOWN_PAIRED_PROVIDER/);
});
test("empty, whitespace and BOM-only downloads are warnings",()=>{
  for(const text of [""," \n\t","\uFEFF \n"])
    assert.equal(inspectPayload(Buffer.from(text)).code,"EMPTY_RESPONSE");
});
test("HTML, XML and explicit JSON error documents are not reported as catalogs",()=>{
  for(const text of ["<!doctype html><html>login</html>","<?xml version='1.0'?><Error/>"])
    assert.equal(inspectPayload(Buffer.from(text)).code,"HTML_OR_XML_RESPONSE");
  for(const text of ['{"success":false,"message":"blocked"}','{"error":"expired"}','{"status":"error"}',"Site Unavailable"])
    assert.equal(inspectPayload(Buffer.from(text)).code,"REMOTE_ERROR_DOCUMENT");
});
test("opaque encrypted bytes and carriers are observed without decrypting",()=>{
  for(const [data,kind] of [[Buffer.from([255,0,128,222]),"BINARY"],
    [Buffer.from("ab".repeat(40)),"HEX_TEXT"],
    [Buffer.from("+/".repeat(40)),"BASE64_TEXT"]]){
    const report=inspectPayload(data);
    assert.equal(report.status,"OK");
    assert.equal(report.payloadKind,kind);
    assert.equal(report.decryptionPerformed,false);
    assert.equal(report.bodySha256,createHash("sha256").update(data).digest("hex"));
  }
});
test("oversized responses remain bounded warnings",()=>{
  assert.equal(inspectPayload(Buffer.alloc(16*1024*1024+1)).code,"REMOTE_TOO_LARGE");
});
test("metadata never exports response values or raw JSON schema keys",()=>{
  const secret="PRIVATE_OWNED_FIXTURE_VALUE";
  const report=inspectPayload(Buffer.from(JSON.stringify({[secret]:secret,servers:[]})));
  assert.doesNotMatch(JSON.stringify(report),new RegExp(secret));
  assert.match(report.shapeSha256,/^[a-f0-9]{64}$/);
});
test("HTTP Conexion unwraps only transport packing and never hashes its password",()=>{
  const catalog=Buffer.from("Owned encrypted carrier");
  function packed(password){
    return Buffer.from(JSON.stringify({kind:"spdecode-http-conexion-config-v1",
      passwordBase64:Buffer.from(password).toString("base64"),catalogBase64:catalog.toString("base64")}));
  }
  const first=inspectPayload(packed("OWNED_PRIVATE_PASSWORD"),"http-conexion");
  const second=inspectPayload(packed("CHANGED_PRIVATE_PASSWORD"),"http-conexion");
  assert.deepEqual(first,second);
  assert.equal(first.bodySha256,createHash("sha256").update(catalog).digest("hex"));
  assert.equal(first.bytes,catalog.length);
  assert.doesNotMatch(JSON.stringify(first),/PASSWORD|passwordBase64|catalogBase64/);
  assert.equal(inspectPayload(Buffer.from("{}"),"http-conexion").status,"WARN");
});
test("normal catalog value, record count and version changes are informational",()=>{
  const old=good();
  const updated=inspectPayload(Buffer.from('{"version":2,"servers":[]}'));
  const result=compareResult(updated,reference(old));
  assert.equal(result.status,"OK");
  assert.equal(result.code,"CATALOG_CONTENT_CHANGED");
  assert.equal(result.formatChanged,false);
  assert.equal(result.contentChanged,true);
});
test("format and root structure changes warn and never certify decoder failure",()=>{
  const old=good();
  const changed=compareResult(inspectPayload(Buffer.from('{"encrypted":"Owned"}')),reference(old));
  assert.equal(changed.status,"WARN");
  assert.equal(changed.code,"PAYLOAD_FORMAT_CHANGED");
  assert.equal(changed.decryptionPerformed,false);
  assert.equal(compareResult(old,reference(old)).code,"DOWNLOAD_OK");
});
test("missing baseline does not turn a successful download into a provider failure",()=>{
  assert.equal(compareResult(good(),undefined).baselineAvailable,false);
  assert.equal(compareResult(good(),undefined).status,"OK");
  assert.equal(compareResult({status:"WARN",code:"EMPTY_RESPONSE"},reference(good())).status,"WARN");
});
test("reference file accepts only safe fingerprints and known carrier kinds",()=>{
  const valid=baseline();valid.entries["owned/servers"]=reference(good());
  assert.deepEqual(validateBaseline(valid),valid);
  for(const change of [{scope:"VERIFIED_DECODER"},{entries:{"https://private.invalid":reference(good())}},
    {entries:{"owned/servers":{...reference(good()),token:"private"}}}]){
    assert.throws(()=>validateBaseline({...baseline(),...change}),/INVALID_DOWNLOAD_BASELINE/);
  }
});
test("all providers run despite warnings and concurrency is bounded",async()=>{
  const plan=[0,1,2,3,4].map(n=>({id:"owned-"+n,name:"Owned "+n,source:"servers",route:"broker"}));
  let active=0,peak=0,calls=0;
  const report=await runChecks(plan,baseline(),{concurrency:2,probe:async item=>{
    active++;peak=Math.max(peak,active);calls++;
    await new Promise(resolve=>setTimeout(resolve,2));
    active--;
    return item.id==="owned-1"?{status:"WARN",code:"REMOTE_PROVIDER_UNAVAILABLE",httpStatuses:[404]}:
      {...good(),httpStatuses:[200]};
  }});
  assert.equal(calls,5);assert.equal(peak,2);
  assert.equal(report.ok,4);assert.equal(report.warnings,1);assert.equal(report.internalErrors,0);
  assert.equal(report.decoderCompatibility,"NOT_TESTED");
  const summary=markdown(report);
  assert.match(summary,/Owned 1/);assert.match(summary,/Advertencia/);assert.match(summary,/404/);
});
test("broken probe code is distinguished from an external provider warning",async()=>{
  const report=await runChecks([{id:"owned",name:"Owned",source:"servers"}],baseline(),{
    probe:async()=>({status:"ERROR",code:"INTERNAL_PROBE_FAILURE",httpStatuses:[]})});
  assert.equal(report.internalErrors,1);assert.equal(report.warnings,0);
});
test("unconfigured routes produce explicit warnings without a network request",async()=>{
  const result=await observeDownload({id:"ut-loop-pro-vpn",source:"unavailable",route:"unconfigured"});
  assert.equal(result.code,"REMOTE_ROUTE_NOT_CONFIGURED");assert.deepEqual(result.httpStatuses,[]);
});
test("missing credentials are reported by the real isolated worker without a network request",async()=>{
  const old=process.env.SPDECODE_VIP_SNIPHER_AUTHORIZATION,flag=process.env.CLOUD_SERVER_VPN_ENABLED;
  process.env.SPDECODE_VIP_SNIPHER_AUTHORIZATION="";process.env.CLOUD_SERVER_VPN_ENABLED="true";
  try{
    const result=await probeInWorker({id:"vip-snipher-pro",source:"servers",route:"broker"},{timeoutMs:10000});
    assert.equal(result.code,"REMOTE_NOT_CONFIGURED");assert.deepEqual(result.httpStatuses,[]);
  }finally{
    if(old===undefined)delete process.env.SPDECODE_VIP_SNIPHER_AUTHORIZATION;else process.env.SPDECODE_VIP_SNIPHER_AUTHORIZATION=old;
    if(flag===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=flag;
  }
});
test("worker hard deadline terminates the isolated task",async()=>{
  const result=await probeInWorker({id:"owned",source:"servers",route:"broker"},{timeoutMs:1});
  assert.equal(result.code,"REMOTE_TIMEOUT");
});
test("the real downloader preserves MM POST and status observation without decryption",async t=>{
  t.mock.method(dns,"lookup",async()=>[{address:"8.8.8.8",family:4}]);
  const captured=[];
  t.mock.method(https,"request",(url,options,callback)=>{
    const request=new EventEmitter();
    request.destroy=()=>{};
    request.end=body=>{
      captured.push({method:options.method,body:body?.toString()});
      const response=new EventEmitter();
      response.statusCode=200;response.headers={};response.resume=()=>{};
      callback(response);response.emit("data",Buffer.from("Owned encrypted payload"));response.emit("end");
    };
    return request;
  });
  const previous=process.env.CLOUD_SERVER_VPN_ENABLED;
  process.env.CLOUD_SERVER_VPN_ENABLED="true";
  try{
    const result=await observeDownload({id:"mm-tunnel",source:"servers",route:"broker"});
    assert.equal(result.status,"OK");assert.deepEqual(result.httpStatuses,[200]);
    assert.deepEqual(captured,[{method:"POST",body:"hash=xsandokUpdatex"}]);
    assert.equal(result.decryptionPerformed,false);
  }finally{if(previous===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=previous;}
});

