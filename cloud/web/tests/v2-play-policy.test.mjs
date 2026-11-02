import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {v2PlayPolicyStatus,changeV2PlayPolicy,changeV2PlaySettings,compatiblePlayDefaults} from '../lib/v2-play-policy.mjs';
import {v2Settings} from '../lib/v2-config.mjs';
const draft=()=>{const {version,revision,...settings}=compatiblePlayDefaults();return settings;};
test('Play observes permanently; independent strict settings persist, CAS prevents lost changes',async()=>{
 const root=await mkdtemp(join(tmpdir(),'spdecode-v2-play-'));
 try{
  const initial=await v2PlayPolicyStatus({root});
  assert.equal(initial.mode,'observe');assert.equal(initial.integrityRequired,false);
  assert.equal(initial.permanent,true);assert.equal(initial.betaUntil,null);
  const strict=await changeV2PlaySettings({...draft(),mode:'enforce',deviceIntegrity:'strong',requireLicensed:true,requireAction:true},0,{root});
  assert.equal(strict.integrityRequired,true);assert.equal(strict.requireAction,true);
  const observe=await changeV2PlayPolicy(false,1,{root});
  assert.equal(observe.mode,'observe');assert.equal(observe.requireLicensed,true);
  assert.equal((await v2PlayPolicyStatus({root,now:Date.now()+365*86400000})).mode,'observe');
  await assert.rejects(changeV2PlayPolicy(true,0,{root}),/CONFLICT/);
  const off=await changeV2PlaySettings({...draft(),mode:'off'},2,{root});
  assert.equal(off.integrityRequested,false);
  assert.equal(JSON.parse(await readFile(join(root,'v2-play-integrity.json'),'utf8')).mode,'off');
 }finally{await rm(root,{recursive:true,force:true});}
});
test('v1 profiles migrate once to compatible defaults with monotonic revision',async()=>{
 const root=await mkdtemp(join(tmpdir(),'spdecode-v2-migrate-'));
 try{
  await writeFile(join(root,'v2-play-integrity.json'),JSON.stringify({version:1,integrityRequired:true,betaUntil:0,revision:9}));
  assert.equal((await v2PlayPolicyStatus({root})).revision,10);
  assert.equal((await v2PlayPolicyStatus({root})).revision,10);
  for(const bad of [{...draft(),mode:'anything'},{...draft(),requireSdk:'false'},
    {...draft(),sessionSeconds:7200},{...draft(),minimumDeviceSdk:23},{...draft(),extra:true}])
    await assert.rejects(changeV2PlaySettings(bad,10,{root}),/INVALID/);
  await writeFile(join(root,'v2-play-integrity.json'),'{broken');
  await assert.rejects(v2PlayPolicyStatus({root}),/INVALID/);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('observing Google still requires signed app identity, hardware attestation and trusted proxy',()=>{
 const e={CLOUD_API_ENABLED:'true',CLOUD_REDIS_URL:'redis://redis:6379',
  CLOUD_WORKER_TOKEN:'w'.repeat(48),CLOUD_SESSION_SIGNING_KEY:'s'.repeat(48),
  CLOUD_GOOGLE_PLAY_PACKAGE:'com.ghostdeveloper.spdecode',CLOUD_PLAY_CERT_SHA256:'a1'.repeat(32),
  CLOUD_TRUST_PROXY:'true',CLOUD_KEY_ATTESTATION_TOKEN:'a'.repeat(64)};
 const options={playIntegrityRequired:false,playPolicy:{...compatiblePlayDefaults(),integrityRequested:true}};
 assert(v2Settings(e,options).configured);
 assert.equal(v2Settings(e,options).minimumDeviceSdk,24);
 assert.equal(v2Settings(e,options).requireAction,false);
 for(const delta of [{CLOUD_PLAY_CERT_SHA256:''},{CLOUD_KEY_ATTESTATION_REQUIRED:'false'},
   {CLOUD_KEY_ATTESTATION_TOKEN:''},{CLOUD_TRUST_PROXY:'false'}])assert(!v2Settings({...e,...delta},options).configured);
});
