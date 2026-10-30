import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {loadV1Protection,v1PolicyStatus,changeV1Policy,setV1Protection,v1ProtectionRequired} from '../lib/v1-protection-policy.mjs';
import {v1Gate,nginxV1Gate} from '../lib/v1-gate.mjs';
const dir=()=>mkdtemp(join(tmpdir(),'spdecode-policy-'));
test('safe initial defaults, all four combinations, revision conflicts and restart persistence',async()=>{
 const root=await dir();try {
  assert.deepEqual(await v1PolicyStatus({root}),{advancedProtection:false,apiEnabled:true,revision:0});
  await writeFile(join(root,'providers.json'),'provider sentinel');
  for(const [available,advanced] of [[true,false],[true,true],[false,false],[false,true]]) {
   let p=await v1PolicyStatus({root});await changeV1Policy('apiEnabled',available,p.revision,{root});
   p=await v1PolicyStatus({root});await changeV1Policy('advancedProtection',advanced,p.revision,{root});
   const policy=await v1PolicyStatus({root});assert.equal(policy.apiEnabled,available);assert.equal(policy.advancedProtection,advanced);
   for(const method of ['GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE']) {
    for(const path of ['/api/v1','/api/v1/','/api/v1/health','/api/v1/ready','/api/v1/session','/api/v1/decode/file','/api/v1/unknown','/api%2fv1/health','/API/v1/health']) {
     const r=await v1Gate(new Request('https://example.test'+path,{method}),{loadPolicy:()=>v1PolicyStatus({root})});
     assert.equal(r?.status,available?undefined:410,method+' '+path);
    }
   }
   assert.equal((await nginxV1Gate({loadPolicy:()=>v1PolicyStatus({root})})).status,available?204:403);
  }
  assert.equal(await readFile(join(root,'providers.json'),'utf8'),'provider sentinel');
  const p=await v1PolicyStatus({root});
  const results=await Promise.allSettled(Array.from({length:12},()=>changeV1Policy('apiEnabled',true,p.revision,{root})));
  assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
  assert(results.filter(x=>x.status==='rejected').every(x=>x.reason.message==='V1_POLICY_CONFLICT'));
  const child=await new Promise((resolve,reject)=>{
   const p=spawn(process.execPath,['--input-type=module','-e',`import {v1PolicyStatus} from ${JSON.stringify(new URL('../lib/v1-protection-policy.mjs',import.meta.url).href)};console.log(JSON.stringify(await v1PolicyStatus({root:process.argv[1]})))`,root]);
   let out='';p.stdout.on('data',d=>out+=d);p.on('error',reject);p.on('exit',c=>c===0?resolve(JSON.parse(out)):reject(Error('child failed')));
  });assert.deepEqual(child,await v1PolicyStatus({root}));
 }finally{await rm(root,{recursive:true,force:true});}
});
test('legacy protection setting migrates; deprecated env flags cannot accidentally retire V1',async()=>{
 const root=await dir();try{
  await writeFile(join(root,'v1-protection.json'),JSON.stringify({version:1,enabled:true}));
  assert.deepEqual(await v1PolicyStatus({root}),{advancedProtection:true,apiEnabled:true,revision:0});
  await setV1Protection(false,{root,env:{CLOUD_V1_REQUIRE_BOUND_SESSION:'true'}});
  assert.equal(await v1ProtectionRequired({CLOUD_V1_REQUIRE_BOUND_SESSION:'true'},{root}),false);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('corruption/storage failures reject V1, while V2/site/admin paths are independent',async()=>{
 const root=await dir();try{
  for(const raw of ['{bad','{}',JSON.stringify({version:2,enabled:false,apiEnabled:true,revision:0,evil:true})]) {
   await writeFile(join(root,'v1-protection.json'),raw);
   await assert.rejects(loadV1Protection({root}));
   const options={loadPolicy:()=>v1PolicyStatus({root})};
   assert.equal((await v1Gate(new Request('https://e.test/api/v1/health'),options)).status,503);
   for(const path of ['/api/v2/transport','/api/admin/session','/admin/system','/api/health/live','/'])
    assert.equal(await v1Gate(new Request('https://e.test'+path),options),undefined);
  }
  await assert.rejects(changeV1Policy('unknown',true,0,{root}),/V1_POLICY_INVALID/);
  await assert.rejects(loadV1Protection({root:join(root,'missing')}));
 }finally{await rm(root,{recursive:true,force:true});}
});
test('kernel lock releases after process death without deleting lock files',async()=>{
 const root=await dir();try{
  const script=`import {withFileLock} from ${JSON.stringify(new URL('../lib/durable-json.mjs',import.meta.url).href)};await withFileLock(process.argv[1],'v1-policy',async()=>{console.log('locked');await new Promise(()=>{})});`;
  const child=spawn(process.execPath,['--input-type=module','-e',script,root]);
  await new Promise((resolve,reject)=>{child.stdout.once('data',resolve);child.once('error',reject);});
  child.kill('SIGKILL');await new Promise(r=>child.once('exit',r));
  await changeV1Policy('apiEnabled',false,0,{root});assert.equal((await v1PolicyStatus({root})).apiEnabled,false);
 }finally{await rm(root,{recursive:true,force:true});}
});
