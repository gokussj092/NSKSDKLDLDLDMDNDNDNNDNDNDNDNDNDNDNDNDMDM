import assert from "node:assert/strict";
import {test} from "node:test";
import {randomBytes,generateKeyPairSync,scryptSync} from "node:crypto";
import {adminSettings,checkPassword,parseAdminCookie,authenticateAdmin,validMutation} from "../lib/c6-admin-auth.mjs";
import {loginRequest,statusRequest,maintenanceRequest,logoutRequest} from "../lib/c6-admin-api.mjs";
import {maintenanceEnabled,recordWorkerResult,aggregateMetrics} from "../lib/c6-ops-store.mjs";
import {decodeRequest,challengeRequest} from "../lib/c3-gateway.mjs";
import {externalImportRequest} from "../lib/c35-gateway.mjs";

class RedisFake{
  constructor(){this.data=new Map();this.count=new Map();}
  async set(k,v,{NX}={}){if(NX&&this.data.has(k))return null;this.data.set(k,v);return "OK";}
  async get(k){return this.data.get(k)??null;}
  async getDel(k){const v=await this.get(k);this.data.delete(k);return v;}
  async del(k){return this.data.delete(k)?1:0;}
  async incr(k){const c=Number(this.count.get(k)||0)+1;this.count.set(k,c);return c;}
  async expire(){return 1;}
  async ping(){return "PONG";}
  multi(){
    const client=this;
    const commands=[];
    const multi={
      incr(k){commands.push(["incr",k]);return multi;},
      expire(k,n){commands.push(["expire",k,n]);return multi;},
      async exec(){for(const [name,...args] of commands)await client[name](...args);return [];},
    };
    return multi;
  }
  async mGet(keys){return keys.map(x=>String(this.count.get(x)||0));}
}
const username="ghostadmin";
const salt=randomBytes(16),password="correct horse battery staple C6",hash="scrypt$16384$8$1$"+salt.toString("hex")+"$"+scryptSync(password,salt,64,{N:16384,r:8,p:1,maxmem:32*1024*1024}).toString("hex");
const rsa=generateKeyPairSync("rsa",{modulusLength:2048});
const env={
  CLOUD_ADMIN_ENABLED:"true",CLOUD_TRUST_PROXY:"true",CLOUD_ADMIN_USERNAME:username,
  CLOUD_ADMIN_PASSWORD_SCRYPT:hash,
  CLOUD_ADMIN_SESSION_KEY:"a".repeat(64),
  CLOUD_ADMIN_PUBLIC_ORIGIN:"https://panel.example.test",CLOUD_REDIS_URL:"redis://redis:6379",
  CLOUD_API_ENABLED:"true",CLOUD_WORKER_TOKEN:"w".repeat(48),
  CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",
  CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON:JSON.stringify({type:"service_account",
    client_email:"test@example.invalid",private_key:rsa.privateKey.export({type:"pkcs8",format:"pem"})}),
  WORKER_INTERNAL_URL:"http://decoder-worker:8787",
  CLOUD_EHI_IMPORT_ENABLED:"true",CLOUD_EHI_SIGN_KEY:"S".repeat(32),
  CLOUD_EHI_RESPONSE_KEY:"R".repeat(32),
};
Object.assign(process.env,env);
const request=(path="/api/admin/login",body={},cookie="",opts={})=>{
  const headers={"Content-Type":"application/json","Origin":opts.origin||env.CLOUD_ADMIN_PUBLIC_ORIGIN,
    "X-SPDecode-Admin-Action":"1","X-Real-IP":opts.ip||"198.51.100.4"};
  if(cookie)headers.Cookie=cookie;
  if(opts.site)headers["Sec-Fetch-Site"]=opts.site;
  if(opts.noAction)delete headers["X-SPDecode-Admin-Action"];
  return new Request(env.CLOUD_ADMIN_PUBLIC_ORIGIN+path,{
    method:"POST",headers,body:JSON.stringify(body),
  });
};
const getReq=(cookie="",ip="198.51.100.4")=>new Request(env.CLOUD_ADMIN_PUBLIC_ORIGIN+"/api/admin/session",{
  headers:{"Cookie":cookie,"X-Real-IP":ip},
});
const redisFactory=redis=>({storeProvider:async()=>redis,fetchImpl:async()=>({ok:true})});
const cookieOnly=reply=>reply.headers.get("set-cookie").split(";")[0];

test("C6 configuration fails closed on missing password hash, origin, Redis or proxy",()=>{
  assert.equal(adminSettings({}).enabled,false);
  assert.equal(adminSettings({...env,CLOUD_ADMIN_PASSWORD_SCRYPT:"invalid"}).enabled,false);
  assert.equal(adminSettings({...env,CLOUD_ADMIN_USERNAME:""}).enabled,false);
  assert.equal(adminSettings({...env,CLOUD_ADMIN_USERNAME:"admin;danger"}).enabled,false);
  assert.equal(adminSettings({...env,CLOUD_ADMIN_PUBLIC_ORIGIN:"http://panel.example.test"}).enabled,false);
  assert.equal(adminSettings({...env,CLOUD_TRUST_PROXY:"false"}).enabled,false);
  assert.equal(adminSettings({...env,CLOUD_ADMIN_SESSION_KEY:"short"}).enabled,false);
  assert.equal(adminSettings(env).enabled,true);
});
test("scrypt password hash verifies in constant-time comparison",async()=>{
  assert.equal(await checkPassword(password,hash),true);
  assert.equal(await checkPassword("invalid password number 123456789",hash),false);
  assert.equal(await checkPassword(password,"fake"),false);
});
test("admin login rejects cross-origin and missing CSRF header before Redis",async()=>{
  const redis=new RedisFake(),args=redisFactory(redis);
  const a=await loginRequest(request("/api/admin/login",{username,password},"",{origin:"https://evil.example"}),args);
  assert.equal(a.status,403);
  const b=await loginRequest(request("/api/admin/login",{username,password},"",{noAction:true}),args);
  assert.equal(b.status,403);
  const c=await loginRequest(request("/api/admin/login",{username,password},"",{site:"cross-site"}),args);
  assert.equal(c.status,403);
  assert.equal(redis.count.size,0);
});
test("admin login issues secure HttpOnly SameSite=Strict cookie and authenticates",async()=>{
  const redis=new RedisFake(),args=redisFactory(redis);
  const response=await loginRequest(request("/api/admin/login",{username,password}),args);
  assert.equal(response.status,200);
  const set=response.headers.get("set-cookie");
  assert.match(set,/HttpOnly/);assert.match(set,/Secure/);
  assert.match(set,/SameSite=Strict/);assert.match(set,/Path=\/api\/admin/);
  assert.equal(set.includes(password),false);
  const cookie=cookieOnly(response);
  assert.ok(parseAdminCookie(getReq(cookie)));
  assert.ok(await authenticateAdmin(redis,getReq(cookie)));
  assert.ok(await authenticateAdmin(redis,getReq(cookie,"198.51.100.99")),"Session must remain valid after network/IP changes");
  assert.equal(await authenticateAdmin(redis,getReq(cookie.slice(0,-5)+"fake")),null);
  assert.equal(await authenticateAdmin(redis,getReq(cookie+"; "+cookie)),null);
});
test("admin brute-force resistance denies after eight invalid attempts per username without IP checks",async()=>{
  const redis=new RedisFake(),args=redisFactory(redis);
  for(let i=0;i<8;i++){
    const r=await loginRequest(request("/api/admin/login",{username,password:"not-the-correct-admin-password-"+i}),args);
    assert.equal(r.status,401);
  }
  const r=await loginRequest(request("/api/admin/login",{username,password}),args);
  assert.equal(r.status,429);
});
test("user and password are required; wrong username is never accepted",async()=>{
  const redis=new RedisFake(),args=redisFactory(redis);
  assert.equal((await loginRequest(request("/api/admin/login",{password}),args)).status,400);
  assert.equal((await loginRequest(request("/api/admin/login",{username}),args)).status,400);
  assert.equal((await loginRequest(request("/api/admin/login",{username:"otheradmin",password}),args)).status,401);
  assert.equal((await loginRequest(request("/api/admin/login",{username,password}),args)).status,200);
});
test("admin sessions and login do not depend on client IP or forwarded IP header",async()=>{
  const redis=new RedisFake(),args=redisFactory(redis);
  const logged=await loginRequest(request("/api/admin/login",{username,password},"",{ip:"192.0.2.55"}),args);
  assert.equal(logged.status,200);
  const cookie=cookieOnly(logged);
  for(const ip of ["192.0.2.55","2001:db8::abcd","198.51.100.99"]){
    const response=await statusRequest(getReq(cookie,ip),args);
    assert.equal(response.status,200);
  }
  const authBody=Buffer.from(cookie.split("=")[1].split(".")[0],"base64url").toString("utf8");
  assert.equal(authBody.includes('"ip"'),false,"session must not carry IP fingerprint");
});
test("admin reports status without content; maintenance is CSRF-protected and revocable",async()=>{
  const redis=new RedisFake(),args=redisFactory(redis);
  const logged=await loginRequest(request("/api/admin/login",{username,password}),args);
  const cookie=cookieOnly(logged);
  let r=await statusRequest(getReq(cookie),args);
  assert.equal(r.status,200);
  let state=await r.json();
  assert.equal(state.services.redisConnected,true);
  assert.equal(state.maintenance,false);
  assert.equal(JSON.stringify(state).includes(password),false);
  assert.equal(JSON.stringify(state).includes(env.CLOUD_WORKER_TOKEN),false);
  r=await maintenanceRequest(request("/api/admin/maintenance",{enabled:true},cookie),args);
  assert.equal(r.status,200);
  assert.equal(await maintenanceEnabled(redis),true);
  const off=await maintenanceRequest(request("/api/admin/maintenance",{enabled:false},cookie,""),args);
  assert.equal(off.status,200);
  assert.equal(await maintenanceEnabled(redis),false);
  const denied=await maintenanceRequest(request("/api/admin/maintenance",{enabled:true},cookie,{origin:"https://evil.example"}),args);
  assert.equal(denied.status,403);
  const out=await logoutRequest(request("/api/admin/logout",{},cookie),args);
  assert.equal(out.status,200);
  assert.match(out.headers.get("set-cookie"),/Max-Age=0/);
  assert.equal((await statusRequest(getReq(cookie),args)).status,401);
});
test("maintenance rejects new Play Integrity challenges, decode and remote imports",async()=>{
  const redis=new RedisFake(),args=redisFactory(redis);
  await redis.set("spc6:maintenance","1");
  const r=await challengeRequest(request("/api/v1/session/challenge",{}),args);
  assert.equal(r.status,503);
  assert.equal((await r.json()).error.code,"SERVICE_UNAVAILABLE");
  const a=await decodeRequest(request("/api/v1/decode/file",{format:"tls",dataBase64:"YWJj"}),"file",args);
  assert.equal(a.status,503);
  const b=await externalImportRequest(request("/api/v1/decode/import/cloud",{reference:"test",consent:true}),"ehi",args);
  assert.equal(b.status,503);
});
test("only anonymous daily success/failure totals enter Redis",async()=>{
  const redis=new RedisFake();
  await recordWorkerResult(redis,"success");
  await recordWorkerResult(redis,"success");
  await recordWorkerResult(redis,"failed");
  const stats=await aggregateMetrics(redis);
  assert.deepEqual(stats,{window:"utc_today",successfulDecodes:2,failedDecodes:1});
  assert.equal([...redis.count.keys()].some(x=>x.includes("file")||x.includes("ip")||x.includes("token")),false);
});

test("deployment-enforced maintenance cannot be disabled from admin panel",async()=>{
  const redis=new RedisFake(),args=redisFactory(redis);
  const logged=await loginRequest(request("/api/admin/login",{username,password}),args);
  const cookie=cookieOnly(logged);
  process.env.CLOUD_FORCE_MAINTENANCE="true";
  try{
    assert.equal(await maintenanceEnabled(redis),true);
    const r=await maintenanceRequest(request("/api/admin/maintenance",{enabled:false},cookie),args);
    assert.equal(r.status,409);
    assert.equal((await r.json()).error.code,"MAINTENANCE_LOCKED");
    assert.equal(await maintenanceEnabled(redis),true);
  }finally{delete process.env.CLOUD_FORCE_MAINTENANCE;}
});
