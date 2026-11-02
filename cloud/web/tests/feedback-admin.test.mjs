import test from "node:test";
import assert from "node:assert/strict";
import {
 parseFeedbackFilters,listFeedback,validateFeedbackUpdate,updateFeedback,feedbackAdminRequest,
} from "../lib/feedback-admin.mjs";
const ID_A="d613205a-ecc5-4ed5-a414-9a4d79d121d8";
const ID_B="48ae83e8-5bd1-400b-821f-b68d519e2223";
const cfg={enabled:true,publicOrigin:"https://panel.example.test"};
const record=(id,extra={})=>({
 id,receivedAt:"2026-11-02T12:00:00.000Z",category:"bug",
 description:"",appLink:"",issues:["decode_failed","catalog_download"],
 appVersion:"1.1.26",appBuild:41,...extra,
});
const filters={category:"all",status:"all",priority:"all",page:0};
class RedisFake {
 constructor(items=[]){
  this.rows=new Map(items.map(x=>["spfeedback:record:"+x.id,JSON.stringify(x)]));
  this.ids=items.map(x=>x.id);
  this.ttls=new Map([...this.rows.keys()].map(x=>[x,500]));
 }
 async lRange(name,start,stop){
  assert.equal(name,"spfeedback:pending");
  return this.ids.slice(start,stop+1);
 }
 async mGet(keys){return keys.map(k=>this.rows.get(k)||null);}
 async eval(script,opts){
  assert.match(script,/KEEPTTL/);
  const key=opts.keys[0],old=this.rows.get(key);
  if(!old)return [0];
  const item=JSON.parse(old);
  if((item.revision||0)!==Number(opts.arguments[0]))return [1];
  item.status=opts.arguments[1];item.priority=opts.arguments[2];
  item.operatorNote=opts.arguments[3];item.updatedAt=opts.arguments[4];
  item.revision=(item.revision||0)+1;
  this.rows.set(key,JSON.stringify(item));
  return [2,JSON.stringify(item)];
 }
}
test("admin list defaults to new/normal for legacy records, with bounded paging",async()=>{
 const db=new RedisFake([record(ID_A),record(ID_B,{
   category:"method",appLink:"https://example.com/app",
   description:"Please add this decoder",issues:[],status:"reviewing",priority:"high",
 })]);
 const out=await listFeedback(db,filters);
 assert.equal(out.totals.available,2);
 assert.equal(out.totals.new,1);
 assert.equal(out.totals.method,1);
 assert.equal(out.items[0].status,"new");
 assert.equal(out.items[0].priority,"normal");
 assert.equal((await listFeedback(db,{...filters,status:"reviewing"})).total,1);
 assert.equal((await listFeedback(db,{...filters,category:"method",priority:"high"})).total,1);
 assert.equal((await listFeedback(db,{...filters,page:1})).items.length,0);
});
test("expired and malformed records are ignored; list remains bounded to 500",async()=>{
 const db=new RedisFake([record(ID_A),record(ID_B)]);
 db.ids.unshift("invalid-id");db.ids.push(ID_A);
 db.rows.delete("spfeedback:record:"+ID_B);
 assert.equal((await listFeedback(db,filters)).total,1);
 const rows=Array.from({length:45},(_,i)=>record(
  "d613205a-ecc5-4ed5-a414-"+(i+1).toString(16).padStart(12,"0")));
 const full=new RedisFake(rows);
 assert.equal((await listFeedback(full,filters)).items.length,20);
 assert.equal((await listFeedback(full,{...filters,page:2})).items.length,5);
});
test("query filters reject unknown, duplicates or invalid pagination",()=>{
 const get=q=>parseFeedbackFilters("https://panel.example.test/api/admin/feedback"+q);
 assert.deepEqual(get(""),filters);
 assert.equal(get("?status=illegal"),null);
 assert.equal(get("?category=method&category=bug"),null);
 assert.equal(get("?page=25"),null);
 assert.equal(get("?search=password"),null);
 assert.equal(get("?priority=high").priority,"high");
});
test("operator mutation uses CAS and keeps original TTL on status/priority/note",async()=>{
 const db=new RedisFake([record(ID_A)]);
 const input={id:ID_A,expectedRevision:0,status:"reviewing",priority:"high",note:"Verificar nuevo error"};
 assert.deepEqual(validateFeedbackUpdate(input),input);
 const saved=await updateFeedback(db,input);
 assert.equal(saved.record.revision,1);
 assert.equal(saved.record.priority,"high");
 assert.equal(saved.record.operatorNote,"Verificar nuevo error");
 assert.equal(db.ttls.get("spfeedback:record:"+ID_A),500);
 assert.deepEqual(await updateFeedback(db,input),{error:"REVISION_CONFLICT",status:409});
 assert.deepEqual(await updateFeedback(db,{...input,id:ID_B}),{error:"NOT_FOUND",status:404});
 assert.equal(validateFeedbackUpdate({...input,token:"secret"}),null);
 assert.equal(validateFeedbackUpdate({...input,expectedRevision:-1}),null);
 assert.equal(validateFeedbackUpdate({...input,note:"x".repeat(601)}),null);
 assert.equal(validateFeedbackUpdate({...input,status:"deleted"}),null);
});
test("admin endpoint rejects unauthorized reads and CSRF-free mutations",async()=>{
 const db=new RedisFake([record(ID_A)]);
 const opts={settingsProvider:()=>cfg,storeProvider:async()=>db,authenticate:async(db,req)=>req.headers.get("cookie")==="session=ok"};
 const unauth=await feedbackAdminRequest(new Request("https://panel.example.test/api/admin/feedback"),opts);
 assert.equal(unauth.status,401);
 const body={id:ID_A,expectedRevision:0,status:"resolved",priority:"normal",note:"OK"};
 const req=(headers={})=>new Request("https://panel.example.test/api/admin/feedback",{
  method:"POST",headers:{"Content-Type":"application/json","Cookie":"session=ok",...headers},body:JSON.stringify(body),
 });
 assert.equal((await feedbackAdminRequest(req(),opts)).status,403);
 assert.equal((await feedbackAdminRequest(req({
   Origin:"https://evil.example.test","X-SPDecode-Admin-Action":"1",
 }),opts)).status,403);
 const accepted=await feedbackAdminRequest(req({
   Origin:cfg.publicOrigin,"X-SPDecode-Admin-Action":"1",
 }),opts);
 assert.equal(accepted.status,200);
 assert.equal((await accepted.json()).record.status,"resolved");
 const listing=await feedbackAdminRequest(new Request("https://panel.example.test/api/admin/feedback",{
  headers:{Cookie:"session=ok"},
 }),opts);
 assert.equal(listing.status,200);
 assert.equal((await listing.json()).feedback.totals.resolved,1);
});
