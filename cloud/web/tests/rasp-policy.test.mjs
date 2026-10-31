import test from 'node:test';
import assert from 'node:assert/strict';
import {raspSettings,parseRaspReport,decideRasp,accessRisk,denyAccessRisk,recordRasp} from '../lib/rasp-policy.mjs';
const clean={v:1,signals:0,evaluated:15,elapsedUs:1200};
const enforce=raspSettings({CLOUD_RASP_MODE:'enforce',CLOUD_RASP_MIN_VERSION_CODE:'35'});
test('strict RASP schema separates unknown from evaluated; no tools or arbitrary data',()=>{
  assert.deepEqual(parseRaspReport(clean),clean);
  for(const bad of [null,[],{}, {...clean,signals:16},{...clean,signals:4,evaluated:3},
    {...clean,v:2},{...clean,elapsedUs:-1},{...clean,elapsedUs:1.5},{...clean,apps:['termux']},
    {...clean,maps:'/proc/self/maps'}, {...clean,signals:'0'}])assert.equal(parseRaspReport(bad),null);
  assert.equal(decideRasp({...clean,evaluated:0},35,enforce).state,'unknown');
});
test('code/debug evidence denies action only in explicit, version-gated enforcement',()=>{
  for(const signals of [1,4,8,13]){
    const value={...clean,signals};assert.equal(decideRasp(value,35,enforce).deny,true);
    for(const mode of ['off','observe'])assert.equal(decideRasp(value,35,{...enforce,mode}).deny,false);
    assert.equal(decideRasp(value,34,enforce).deny,false);
  }
  assert.equal(decideRasp(clean,35,enforce).deny,false);
  assert.equal(decideRasp(null,35,enforce).deny,true);
  assert.equal(decideRasp({...clean,signals:2},35,enforce).deny,false,'module names alone are advisory');
});
test('rollout configuration is bounded and invalid settings fail closed',()=>{
  assert.equal(raspSettings().mode,'observe');assert.equal(raspSettings().minVersion,38);
  for(const env of [{CLOUD_RASP_MODE:'disabled'},{CLOUD_RASP_MIN_VERSION_CODE:'0'},
    {CLOUD_RASP_MIN_VERSION_CODE:'NaN'},{CLOUD_RASP_ACCESS_MODE:'true'}])
    assert.equal(raspSettings(env).configured,false);
});
const verdict=labels=>({tokenPayloadExternal:{environmentDetails:{appAccessRiskVerdict:{appsDetected:labels}}}});
test('Play access risk differentiates unavailable, capturing, controlling and overlay-only',()=>{
  assert.equal(accessRisk(null),'unknown');assert.equal(accessRisk(verdict([])),'unknown');
  assert.equal(accessRisk(verdict(['UNRECOGNIZED'])),'unknown');
  assert.equal(accessRisk(verdict(['KNOWN_INSTALLED','UNKNOWN_INSTALLED'])),'observed');
  for(const l of ['KNOWN_CAPTURING','UNKNOWN_CAPTURING','KNOWN_CONTROLLING','UNKNOWN_CONTROLLING']){
    assert.equal(accessRisk(verdict([l])),'restricted');
    assert.equal(denyAccessRisk(verdict([l]),{rasp:{...enforce,accessMode:'enforce'}},35),true);
    assert.equal(denyAccessRisk(verdict([l]),{rasp:{...enforce,mode:'off',accessMode:'enforce'}},35),false);
  }
  assert.equal(accessRisk(verdict(['UNKNOWN_OVERLAYS'])),'advisory');
  assert.equal(denyAccessRisk(verdict(['UNKNOWN_OVERLAYS']),{rasp:{...enforce,accessMode:'enforce'}},35),false);
});
test('aggregate metrics contain enums/build buckets only and expire; outages do not authorize',async()=>{
  const keys=[],ttls=[];const redis={incr:async k=>keys.push(k),expire:async(k,n)=>ttls.push(n)};
  await recordRasp(redis,decideRasp(clean,35,enforce),35,enforce);
  assert.equal(keys.length,2);assert(keys.every(k=>/^spsec:rasp:\d{4}-\d{2}-\d{2}:35:(observed|le5ms)$/.test(k)));
  assert.deepEqual(ttls,[691200,691200]);
  await recordRasp({incr:()=>{throw Error('offline');}},decideRasp(null,35,enforce),35,enforce);
  assert.equal(decideRasp(null,35,enforce).deny,true);
});
