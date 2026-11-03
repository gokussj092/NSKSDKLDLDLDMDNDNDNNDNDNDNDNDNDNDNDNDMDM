import test from 'node:test';
import assert from 'node:assert/strict';
import {recordAdmission,admissionDiagnostics,playSignals} from '../lib/v2-admission-diagnostics.mjs';
test('unknown signals remain unknown and observations do not inflate the rejection denominator',async()=>{
 const hash={},ttls=[];const redis={hIncrBy:async(_k,f,n)=>hash[f]=String(Number(hash[f]||0)+n),expire:async(_k,n)=>ttls.push(n),hGetAll:async()=>hash};
 await recordAdmission(redis,'SESSION','ACCEPTED','SESSION_ISSUED');
 await recordAdmission(redis,'SESSION','OBSERVED','PLAY_NOT_PROVIDED',playSignals(null));
 await recordAdmission(redis,'SESSION','REJECTED','ATTESTATION_REJECTED');
 const report=await admissionDiagnostics(redis);
 assert.equal(report.total,2);assert.equal(report.accepted,1);assert.equal(report.rejected,1);assert.equal(report.rejectionPercent,50);
 assert.equal(report.counts.SIGNAL_SDK_UNKNOWN,1);assert.equal(report.rootDetection,'unknown');
 assert(ttls.every(n=>n===8*86400));
 assert.equal(playSignals({tokenPayloadExternal:{deviceIntegrity:{deviceAttributes:{sdkVersion:'35'}}}}).sdk,null);
 assert.equal(playSignals({tokenPayloadExternal:{deviceIntegrity:{deviceAttributes:{sdkVersion:35}}}}).sdk,35);
});
test('telemetry outages cannot turn a security decision into a service failure',async()=>{
 await recordAdmission({hIncrBy:async()=>{throw Error('offline');}},'SESSION','REJECTED','PLAY_POLICY');
 assert.equal(await admissionDiagnostics({hGetAll:async()=>{throw Error('offline');}}),null);
});
