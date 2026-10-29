import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {v2PolicyStatus,changeV2Availability,loadV2Availability} from '../lib/v2-availability-policy.mjs';
import {v2Gate,isV2Path} from '../lib/v2-gate.mjs';
import {v1Gate} from '../lib/v1-gate.mjs';
const directory=()=>mkdtemp(join(tmpdir(),'spdecode-v2-policy-'));
test('V2 availability persists, rejects stale revisions, and never disables V1',async()=>{
 const root=await directory();
 try{
  assert.deepEqual(await v2PolicyStatus({root}),{enabled:true,revision:0});
  assert.deepEqual(await changeV2Availability(false,0,{root}),{enabled:false,revision:1});
  assert.equal(JSON.parse(await readFile(join(root,'v2-availability.json'),'utf8')).enabled,false);
  for(const method of ['GET','HEAD','OPTIONS','POST','PUT','DELETE']){
   for(const path of ['/api/v2','/api/v2/','/api/v2/transport','/api/v2/security-policy','/api%2fv2/transport','/API/v2/transport']){
    const req=new Request('https://example.test'+path,{method});
    const res=await v2Gate(req,{loadPolicy:()=>v2PolicyStatus({root})});
    assert.equal(res.status,410,method+' '+path);
   }
  }
  for(const path of ['/api/v1/health','/api/admin/session','/api/health/live','/admin/system','/'])
   assert.equal(await v2Gate(new Request('https://e.test'+path),
    {loadPolicy:()=>v2PolicyStatus({root})}),undefined);
  assert.equal(await v1Gate(new Request('https://e.test/api/v1/health'),
    {loadPolicy:async()=>({apiEnabled:true})}),undefined);
  await assert.rejects(changeV2Availability(true,0,{root}),/V2_POLICY_CONFLICT/);
  await changeV2Availability(true,1,{root});
  assert.equal(await v2Gate(new Request('https://e.test/api/v2/transport'),
    {loadPolicy:()=>v2PolicyStatus({root})}),undefined);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('V2 storage errors fail closed',async()=>{
 const root=await directory();
 try{
  for(const content of ['{bad','{}',JSON.stringify({version:1,enabled:true,revision:0,extra:true})]){
   await writeFile(join(root,'v2-availability.json'),content);
   await assert.rejects(loadV2Availability({root}));
   assert.equal((await v2Gate(new Request('https://e.test/api/v2/transport'),
    {loadPolicy:()=>v2PolicyStatus({root})})).status,503);
  }
  await assert.rejects(loadV2Availability({root:join(root,'missing')}),/V2_POLICY_UNAVAILABLE/);
  await assert.rejects(changeV2Availability('yes',0,{root}),/V2_POLICY_INVALID/);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('V2 path matcher rejects adjacent routes',()=>{
 for(const path of ['/api/v20','/api/v1','/api/admin','/admin','/api/health/live'])
  assert.equal(isV2Path(path),false);
});
