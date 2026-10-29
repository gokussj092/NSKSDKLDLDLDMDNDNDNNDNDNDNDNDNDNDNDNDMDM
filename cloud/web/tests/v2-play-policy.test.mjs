import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {v2PlayPolicyStatus,changeV2PlayPolicy,MAX_V2_BETA_MS} from '../lib/v2-play-policy.mjs';
import {v2Settings} from '../lib/v2-config.mjs';
test('V2 Play check defaults ON, persists OFF for at most 15 days, and expires closed',async()=>{
 const root=await mkdtemp(join(tmpdir(),'spdecode-v2-play-')),now=1782600000000;
 try{
  assert.deepEqual(await v2PlayPolicyStatus({root,now}),
   {integrityRequired:true,betaUntil:null,revision:0});
  const off=await changeV2PlayPolicy(false,0,{root,now});
  assert.equal(off.integrityRequired,false);
  assert.equal(new Date(off.betaUntil).getTime(),now+MAX_V2_BETA_MS);
  assert.deepEqual(await v2PlayPolicyStatus({root,now:now+1000}),off);
  assert.deepEqual(await v2PlayPolicyStatus({root,now:now+MAX_V2_BETA_MS}),
   {integrityRequired:true,betaUntil:null,revision:1});
  assert.deepEqual(await changeV2PlayPolicy(true,1,{root,now}),
   {integrityRequired:true,betaUntil:null,revision:2});
  await assert.rejects(changeV2PlayPolicy(false,0,{root,now}),/V2_PLAY_POLICY_CONFLICT/);
  assert.equal(JSON.parse(await readFile(join(root,'v2-play-integrity.json'),'utf8')).integrityRequired,true);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('corrupted policy rejects reads and invalid writes',async()=>{
 const root=await mkdtemp(join(tmpdir(),'spdecode-v2-play-'));
 try{
  for(const text of ['{broken','{}','{"version":1,"integrityRequired":false,"betaUntil":0,"revision":0}']){
   await writeFile(join(root,'v2-play-integrity.json'),text);
   await assert.rejects(v2PlayPolicyStatus({root}));
  }
  await assert.rejects(changeV2PlayPolicy('off',0,{root}),/V2_PLAY_POLICY_INVALID/);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('beta mode still requires a valid signed app certificate and hardware attestation',()=>{
 const e={CLOUD_API_ENABLED:'true',CLOUD_REDIS_URL:'redis://redis:6379',
  CLOUD_WORKER_TOKEN:'w'.repeat(48),CLOUD_SESSION_SIGNING_KEY:'s'.repeat(48),
  CLOUD_GOOGLE_PLAY_PACKAGE:'com.ghostdeveloper.spdecode',
  CLOUD_PLAY_CERT_SHA256:'a1'.repeat(32),CLOUD_TRUST_PROXY:'true',
  CLOUD_KEY_ATTESTATION_TOKEN:'a'.repeat(64)};
 assert(!v2Settings(e).configured);
 assert(v2Settings(e,{playIntegrityRequired:false}).configured);
 assert(!v2Settings({...e,CLOUD_PLAY_CERT_SHA256:''},{playIntegrityRequired:false}).configured);
 assert(!v2Settings({...e,CLOUD_KEY_ATTESTATION_REQUIRED:'false'},{playIntegrityRequired:false}).configured);
 assert(!v2Settings({...e,CLOUD_KEY_ATTESTATION_TOKEN:''},{playIntegrityRequired:false}).configured);
 assert(!v2Settings({...e,CLOUD_TRUST_PROXY:'false'},{playIntegrityRequired:false}).configured);
 assert.equal(v2Settings(e,{playIntegrityRequired:false}).requireAction,false);
});
