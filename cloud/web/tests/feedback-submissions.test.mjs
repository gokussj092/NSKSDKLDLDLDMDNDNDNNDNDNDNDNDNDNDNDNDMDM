import test from "node:test";
import assert from "node:assert/strict";
import {validateFeedback,persistFeedback,feedbackRequest} from "../lib/feedback-submissions.mjs";
import {routes,bodyLimit} from "../lib/v2-routes.mjs";
import {protectedActions} from "../lib/action-integrity.mjs";
import {raspActions} from "../lib/rasp-policy.mjs";

const base={
  submissionId:"d613205a-ecc5-4ed5-a414-9a4d79d121d8",
  category:"method",appLink:"https://play.google.com/store/apps/details?id=com.example.test",
  description:"Support the VPN file format and server catalog",issues:[],
  appVersion:"1.1.26",appBuild:41,
};
test("method request accepts Play, Uptodown and other public providers",()=>{
  for(const appLink of [
    base.appLink,"https://sample.en.uptodown.com/android","https://downloads.example.org/my-app.apk"
  ]) {
    const parsed=validateFeedback({...base,appLink});
    assert.equal(parsed.category,"method");
    assert.equal(parsed.appLink,new URL(appLink).href);
  }
  assert.equal(validateFeedback({...base,appLink:"http://localhost/admin"}),null);
  assert.equal(validateFeedback({...base,appLink:"file:///etc/passwd"}),null);
  assert.equal(validateFeedback({...base,appLink:"https://user:pass@example.org/app"}),null);
  assert.equal(validateFeedback({...base,description:""}),null);
});
test("bug reports require selected checkboxes but free text is optional",()=>{
  const bug={...base,category:"bug",appLink:"",description:"",
    issues:["decode_failed","catalog_download"]};
  assert.deepEqual(validateFeedback(bug).issues,bug.issues);
  assert.equal(validateFeedback({...bug,issues:[]}),null);
  assert.equal(validateFeedback({...bug,issues:["other","other"]}),null);
  assert.equal(validateFeedback({...bug,issues:["invented"]}),null);
  assert.equal(validateFeedback({...bug,description:"Optional user report"}).description,
    "Optional user report");
});
test("suggestions need description and never accept attached file or private JSON",()=>{
  assert.equal(validateFeedback({...base,category:"suggestion",appLink:"",
    description:"Improve the import interface",issues:[]}).category,"suggestion");
  assert.equal(validateFeedback({...base,category:"suggestion",appLink:"",
    description:"",issues:[]}),null);
  assert.equal(validateFeedback({...base,secret:"PRIVATE_KEY"}),null);
  assert.equal(validateFeedback({...base,appLink:base.appLink,issues:["app_crash"]}),null);
});
test("feedback uses V2-bound request only, with action Integrity and RASP",async()=>{
  assert.equal(routes[18],"feedback");
  assert.equal(bodyLimit(18),16384);
  assert.equal(protectedActions.has(18),true);
  assert.equal(raspActions.has(18),true);
  const direct=await feedbackRequest(new Request("http://localhost/api/v1/feedback",{
    method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(base),
  }));
  assert.equal(direct.status,401);
});
test("per-request idempotency returns one receipt without duplicate records",async()=>{
  const keys=new Map();
  const records=new Map();
  const mock={
    async get(key){return keys.get(key)||null;},
    async eval(script,{keys:names,arguments:args}){
      if(script.includes("spdecode:throttle:v1"))return 1;
      if(keys.has(names[0]))return keys.get(names[0]);
      keys.set(names[0],args[0]);
      records.set(names[2],JSON.parse(args[1]));
      assert.equal(args[2],String(90*24*3600));
      assert.equal(args[3],"500");
      return args[0];
    }
  };
  const claims={key:"some-public-hardware-key"};
  const clean=validateFeedback(base);
  const first=await persistFeedback(mock,claims,clean,base.submissionId);
  const retry=await persistFeedback(mock,claims,clean,base.submissionId);
  assert.match(first.requestId,/^[0-9a-f-]{36}$/);
  assert.equal(retry.requestId,first.requestId);
  assert.equal(retry.duplicate,true);
  assert.equal(records.size,1);
  assert.equal([...records.values()][0].category,"method");
  assert.equal(JSON.stringify([...records.values()][0]).includes("secret"),false);
});
