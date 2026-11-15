import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {gunzipSync} from "node:zlib";
import {test} from "node:test";
import {allowsHcPartial} from "../lib/hc-partial-result.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";

const wrapper=JSON.parse(readFileSync(new URL("../../../tests/golden/hc_legacy57.json",import.meta.url)));
const fixture=JSON.parse(gunzipSync(Buffer.from(wrapper.payload,"base64")));
const report=fixture.cases.unresolved.expected;
const response=()=>({status:"success",format:"hc",isPartial:true,warnings:["HC_UNRESOLVED_FIELDS"],
  structuredJson:structuredClone(report),rawText:JSON.stringify(report,null,2)+"\n"});
const payload={format:"hc",dataBase64:"YWJj"};
process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
const forward=result=>({fetchImpl:async()=>Response.json(result)});

test("HC worker gateway retains the full authenticated record with its explicit unresolved slot",async()=>{
  const result=response();
  assert.equal(allowsHcPartial("file",payload,result),true);
  const reply=await fetchWorker("file",payload,{workerToken:"test-only"},forward(result));
  assert.equal(reply.status,200);
  const actual=await reply.json();
  assert.equal(actual.isPartial,true);
  assert.deepEqual(actual.structuredJson,report);
  assert.deepEqual(JSON.parse(actual.rawText),report);
});

test("HC partial exception rejects truncation, mismatched JSON and unknown partial shapes",async()=>{
  const edits=[
    x=>{x.rawText=x.rawText.slice(0,-10);},
    x=>{x.structuredJson.Config.v2rayConfig="changed";},
    x=>{delete x.structuredJson.Config.psiphon;},
    x=>{x.structuredJson.UnresolvedFields[0].index=26;},
    x=>{x.structuredJson.UnresolvedFields.push({index:0});},
    x=>{x.structuredJson.Metadata.envelope.verCfg=58;},
    x=>{x.structuredJson.Metadata.config.verApp=566;},
    x=>{x.warnings=[];},
    x=>{x.warnings.push("OTHER_FAILURE");},
    x=>{x.format="tls";},
    x=>{x.structuredJson.Config.psiphon="invented";},
  ];
  for(const edit of edits){
    const result=response();edit(result);
    assert.equal(allowsHcPartial("file",payload,result),false);
    await assert.rejects(fetchWorker("file",payload,{workerToken:"test-only"},forward(result)),/INVALID_WORKER_RESULT/);
  }
  assert.equal(allowsHcPartial("text",payload,response()),false);
  assert.equal(allowsHcPartial("file",{format:"tls"},response()),false);
});
