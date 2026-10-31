import test from 'node:test';import assert from 'node:assert/strict';
import {scryptSync,randomBytes} from 'node:crypto';import {mkdtemp,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {loginRequest,v1ProtectionRequest,v1AvailabilityRequest,v1RetirementRequest} from '../lib/c6-admin-api.mjs';
import {v1PolicyStatus} from '../lib/v1-protection-policy.mjs';
const salt=randomBytes(16),password='strict v1 administrative test';
Object.assign(process.env,{CLOUD_ADMIN_ENABLED:'true',CLOUD_TRUST_PROXY:'true',CLOUD_ADMIN_USERNAME:'admin',CLOUD_ADMIN_PASSWORD_SCRYPT:'scrypt$16384$8$1$'+salt.toString('hex')+'$'+scryptSync(password,salt,64).toString('hex'),CLOUD_ADMIN_SESSION_KEY:'a'.repeat(64),CLOUD_ADMIN_PUBLIC_ORIGIN:'https://panel.example.test',CLOUD_REDIS_URL:'redis://redis:6379'});
class Redis {data=new Map();counts=new Map();async get(k){return this.data.get(k)??null;}async set(k,v){this.data.set(k,v);return 'OK';}async incr(k){const n=(this.counts.get(k)||0)+1;this.counts.set(k,n);return n;}async expire(){return 1;}async eval(s,o){return this.incr(o.keys[0]);}async lPush(){}async lTrim(){} }
const req=(body,cookie='',origin='https://panel.example.test',action=true)=>new Request('https://panel.example.test/api/admin/v1-protection',{method:'POST',headers:{Origin:origin,Cookie:cookie,'Content-Type':'application/json',...(action?{'X-SPDecode-Admin-Action':'1'}:{})},body:JSON.stringify(body)});
test('both controls require admin, CSRF, closed schema, CAS and administrative rate limits',async()=>{
 const root=await mkdtemp(join(tmpdir(),'v1-admin-'));const redis=new Redis(),options={storeProvider:async()=>redis,policyOptions:{root},turnstileVerifier:async()=>({ok:true})};
 try {
  let body={enabled:true,confirmation:'V1_PROTECCION_ACTIVAR',expectedRevision:0};
  assert.equal((await v1ProtectionRequest(req(body),options)).status,401);
  const login=await loginRequest(req({username:'admin',password}),options);assert.equal(login.status,200);
  const cookie=login.headers.get('set-cookie').split(';')[0];
  assert.equal((await v1ProtectionRequest(req(body,cookie,'https://evil.test'),options)).status,403);
  assert.equal((await v1ProtectionRequest(req(body,cookie,undefined,false),options)).status,403);
  assert.equal((await v1ProtectionRequest(req({...body,evil:true},cookie),options)).status,400);
  const changed=await v1ProtectionRequest(req(body,cookie),options);assert.equal(changed.status,200);
  assert.equal((await changed.json()).v1Policy.advancedProtection,true);
  assert.equal((await v1ProtectionRequest(req(body,cookie),options)).status,409);
  body={enabled:false,confirmation:'API_V1_DESACTIVAR',expectedRevision:1};
  assert.equal((await v1AvailabilityRequest(req(body,cookie),options)).status,200);
  assert.deepEqual(await v1PolicyStatus({root}),{apiEnabled:false,advancedProtection:true,revision:2});
  body={enabled:false,confirmation:'V1_PROTECCION_DESACTIVAR',expectedRevision:2};
  assert.equal((await v1ProtectionRequest(req(body,cookie),options)).status,200);
  assert.equal((await v1PolicyStatus({root})).apiEnabled,false);
  for(let i=0;i<12;i++)await v1ProtectionRequest(req(body,cookie),options);
  assert.equal((await v1ProtectionRequest(req(body,cookie),options)).status,429);
 }finally{await rm(root,{recursive:true,force:true});}
});

test('48-hour V1 shutdown scheduling requires authenticated administrator, CSRF and CAS',async()=>{
 const root=await mkdtemp(join(tmpdir(),'v1-retire-admin-'));
 const redis=new Redis(),options={storeProvider:async()=>redis,policyOptions:{root},turnstileVerifier:async()=>({ok:true})};
 try{
  const body={action:'schedule',confirmation:'API_V1_PROGRAMAR_48H',expectedRevision:0};
  assert.equal((await v1RetirementRequest(req(body),options)).status,401);
  const login=await loginRequest(req({username:'admin',password}),options);
  assert.equal(login.status,200);
  const cookie=login.headers.get('set-cookie').split(';')[0];
  assert.equal((await v1RetirementRequest(req(body,cookie,'https://evil.test'),options)).status,403);
  assert.equal((await v1RetirementRequest(req(body,cookie,undefined,false),options)).status,403);
  assert.equal((await v1RetirementRequest(req({...body,evil:true},cookie),options)).status,400);
  assert.equal((await v1RetirementRequest(req({...body,confirmation:'INVALID'},cookie),options)).status,400);
  const result=await v1RetirementRequest(req(body,cookie),options);
  assert.equal(result.status,200);
  const policy=(await result.json()).v1Policy;
  assert.equal(policy.revision,1);
  assert.equal(policy.apiEnabled,true);
  assert(Number.isSafeInteger(policy.retireAt));
  assert(policy.retireAt>Date.now()+47*3600000);
  assert.equal((await v1RetirementRequest(req(body,cookie),options)).status,409);
  const cancel={action:'cancel',confirmation:'API_V1_CANCELAR_PROGRAMACION',expectedRevision:1};
  const stop=await v1RetirementRequest(req(cancel,cookie),options);
  assert.equal(stop.status,200);
  assert.equal((await stop.json()).v1Policy.apiEnabled,true);
  assert.deepEqual(await v1PolicyStatus({root}),{apiEnabled:true,advancedProtection:false,revision:2});
 }finally{await rm(root,{recursive:true,force:true});}
});
