import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,readFile,writeFile,rm,stat} from "node:fs/promises";
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {resolveTunneltweakCatalog,validateBuildState} from "../lib/tunneltweak-builds.mjs";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
const catalog=Buffer.from(JSON.stringify(JSON.parse(readFileSync(new URL("../../../tests/golden/tunneltweak_vectors.json",import.meta.url),"utf8")).wrapper));
async function setup(t){const dir=await mkdtemp(join(tmpdir(),"tweak-history-"));t.after(()=>rm(dir,{recursive:true,force:true}));return join(dir,"builds.json");}
const upgrade=n=>({status:426,data:Buffer.from(JSON.stringify({status:"update_required",minVersionCode:n}))});
const state=async path=>validateBuildState(JSON.parse(await readFile(path,"utf8")));
test("records failures, learns the advertised build, and persists across resolver calls",async t=>{
 const path=await setup(t),calls=[];
 const result=await resolveTunneltweakCatalog(async build=>{calls.push(build);return build===53?upgrade(57):{data:catalog};},{statePath:path});
 assert.deepEqual(result,catalog);assert.deepEqual(calls,[53,57]);
 const s=await state(path);assert.equal(s.auto.build,57);assert.equal(s.builds.find(x=>x.build===53).working,false);assert.equal(s.builds.at(-1).working,true);
 await resolveTunneltweakCatalog(async build=>{assert.equal(build,57);return {data:catalog};},{statePath:path});
 assert.equal((await state(path)).builds.at(-1).successes,2);assert.equal((await stat(path)).mode&0o777,0o600);
});
test("explicit version refusal without a minimum tries the immediate successor",async t=>{
 const path=await setup(t),calls=[];
 await resolveTunneltweakCatalog(async build=>{calls.push(build);return build===53?{status:426,data:Buffer.from('{"status":"update_required"}')}: {data:catalog};},{statePath:path});
 assert.deepEqual(calls,[53,54]);
});
test("network errors, authorization and rate limits never trigger build guessing",async t=>{
 const path=await setup(t);
 for(const status of [401,403,429,503]){
  let calls=0;await assert.rejects(()=>resolveTunneltweakCatalog(async()=>{calls++;throw Object.assign(Error("private-marker"),{httpStatus:status});},{statePath:path}));
  assert.equal(calls,1);assert.equal((await state(path)).auto.build,53);assert.equal((await state(path)).builds.at(-1).working,true);
 }
 assert(!(await readFile(path,"utf8")).includes("private-marker"));
});
test("invalid metadata and a three-attempt ceiling bound recovery",async t=>{
 const path=await setup(t);
 for(const n of [null,0,-1,true,"54",53,54.5,2147483648]){
  let calls=0;await assert.rejects(()=>resolveTunneltweakCatalog(async()=>{calls++;return upgrade(n);},{statePath:path}));assert.equal(calls,1);
 }
 let calls=0;await assert.rejects(()=>resolveTunneltweakCatalog(async build=>{calls++;return upgrade(build+1);},{statePath:path}));
 assert.equal(calls,3);const s=await state(path);assert.equal(s.auto.build,56);assert.equal(s.builds.at(-1).working,null);
});
test("HTML, error JSON and truncated carriers never become a working download",async t=>{
 const path=await setup(t);
 for(const data of ["<html>private-marker</html>","{}",'{"success":false}', '{"data":"abc"}'])
  await assert.rejects(()=>resolveTunneltweakCatalog(async()=>({data:Buffer.from(data)}),{statePath:path}),/REMOTE_RESPONSE_INVALID/);
 assert.equal((await state(path)).builds.at(-1).successes,1);
});
test("malformed or unrelated HTTP426 does not retire a confirmed build",async t=>{
 const path=await setup(t);
 for(const data of ["{}","<html>upgrade</html>",'{"status":"error"}']){
  await assert.rejects(()=>resolveTunneltweakCatalog(async()=>({status:426,data:Buffer.from(data)}),{statePath:path}),/REMOTE_RESPONSE_INVALID/);
  assert.equal((await state(path)).auto.build,53);assert.equal((await state(path)).builds.at(-1).working,true);
 }
});
test("concurrent public downloads coalesce and retain complete history",async t=>{
 const path=await setup(t);let calls=0;
 const request=async()=>{calls++;await new Promise(resolve=>setTimeout(resolve,15));return {data:catalog};};
 const results=await Promise.all(Array.from({length:20},()=>resolveTunneltweakCatalog(request,{statePath:path})));
 assert.equal(calls,1);assert(results.every(x=>x.equals(catalog)));assert.equal((await state(path)).builds.length,2);
});
test("malformed history safely recovers from the recorded seed",async t=>{
 const path=await setup(t);await writeFile(path,'{"auto":{"build":-1}}');
 await resolveTunneltweakCatalog(async build=>{assert.equal(build,53);return {data:catalog};},{statePath:path});await state(path);
});
test("the real broker consumes bounded HTTP426 JSON then preserves pinned TLS on the next build",async t=>{
 const path=await setup(t),before={enabled:process.env.CLOUD_SERVER_VPN_ENABLED,path:process.env.CLOUD_TUNNELTWEAK_BUILD_STATE_PATH};
 process.env.CLOUD_SERVER_VPN_ENABLED="true";process.env.CLOUD_TUNNELTWEAK_BUILD_STATE_PATH=path;
 t.after(()=>{for(const [key,value] of [["CLOUD_SERVER_VPN_ENABLED",before.enabled],["CLOUD_TUNNELTWEAK_BUILD_STATE_PATH",before.path]]){if(value===undefined)delete process.env[key];else process.env[key]=value;}});
 t.mock.method(dns,"lookup",async host=>{assert.equal(host,"tunneltweak.com");return [{address:"93.184.216.34",family:4}];});
 const builds=[];t.mock.method(https,"request",(url,options,callback)=>{
  assert.equal(url.href,"https://tunneltweak.com/api/servers");assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,"TLSv1.2");
  const build=Number(options.headers["x-app-version"]);builds.push(build);
  const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
   const res=new EventEmitter();res.headers={};res.resume=()=>{};res.statusCode=build===53?426:200;
   callback(res);res.emit("data",build===53?upgrade(54).data:catalog);res.emit("end");
  });return req;
 });
 assert.deepEqual(await downloadVpnCatalog("tunneltweak"),catalog);assert.deepEqual(builds,[53,54]);assert.equal((await state(path)).auto.build,54);
});
