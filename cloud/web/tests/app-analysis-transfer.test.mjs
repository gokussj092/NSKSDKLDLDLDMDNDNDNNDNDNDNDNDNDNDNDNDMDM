import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {acceptBoundProof} from '../lib/bound-auth.mjs';
import {proofMessage} from '../lib/v2-proof.mjs';
import {keyId} from '../lib/device-security.mjs';
import {ipKey} from '../lib/c3-store.mjs';

// Real P-256 proofs, with deterministic counter behavior instead of a live Redis.
class Redis {
 values=new Map();counts=new Map();ttls=new Map();
 async set(k,v,{NX,EX}={}){if(NX&&this.values.has(k))return null;this.values.set(k,v);this.ttls.set(k,EX);return 'OK';}
 async eval(script,{keys,arguments:args}){
  assert(script.includes('spdecode:throttle:v1'));
  const key=keys[0],n=(this.counts.get(key)||0)+1;
  this.counts.set(key,n);this.ttls.set(key,Number(args[0]));return n;
 }
}
function device(jti=randomBytes(8).toString('hex')){
 const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 return {pair,claims:{jti,key:pair.publicKey.export({format:'der',type:'spki'}).toString('base64url')}};
}
function request(op,d,{ip='192.0.2.12',bytes=Buffer.from('synthetic HPKE wire bytes')}={}){
 const bearer='synthetic-session',ts=String(Math.floor(Date.now()/1000)),nonce=randomBytes(24).toString('base64url');
 const proof=sign('sha256',Buffer.from(proofMessage(op,'1.1.29',ts,nonce,bearer,bytes)),d.pair.privateKey).toString('base64url');
 const req=new Request('https://synthetic.invalid/api/v2/transport',{method:'POST',headers:{
  'x-real-ip':ip,'x-sp-timestamp':ts,'x-sp-nonce':nonce,'x-sp-proof':proof,'x-spdecode-app-version':'1.1.29'},body:bytes});
 return {req,bytes,bearer};
}
async function call(redis,op,d,options){const r=request(op,d,options);return acceptBoundProof(redis,r.req,op,r.bytes,r.bearer,d.claims);}

test('a maximum-size APK can upload continuously without consuming decoder work budget',async()=>{
 const redis=new Redis(),d=device();
 for(let n=0;n<Math.ceil(150_000_000/(2*1024*1024));n++)assert.equal(await call(redis,27,d),d.claims);
 assert(![...redis.counts.keys()].some(k=>k.includes('work:')||k.includes('work-')));
 assert.equal(redis.ttls.get('spc2:upload:key-day:'+keyId(d.claims.key)),86400);
});
test('upload session/key/IP/global/day limits remain enforced across new sessions',async()=>{
 for(const scope of ['session','key-minute','key-day','ip','global']){
  const redis=new Redis(),d=device(),r=request(27,d);
  const key=scope==='session'?'spc2:upload:session:'+d.claims.jti:
   scope.startsWith('key-')?'spc2:upload:'+scope+':'+keyId(d.claims.key):
   scope==='ip'?'spc2:upload:ip:'+ipKey(r.req):'spc2:upload:global';
  redis.counts.set(key,scope==='ip'?128:scope==='global'?256:scope==='key-day'?3600:96);
  if(scope.startsWith('key-'))d.claims.jti='renewed-session';
  if(scope==="global")await assert.rejects(call(redis,27,d),{code:"ENGINE_UNAVAILABLE"});
  else assert.deepEqual(await call(redis,27,d),{rateLimited:true},scope);
 }
});
test('invalid or replayed proofs cannot enter the upload budget',async()=>{
 const redis=new Redis(),d=device(),r=request(27,d);
 assert.equal(await acceptBoundProof(redis,r.req,27,r.bytes,r.bearer,d.claims),d.claims);
 const counts=[...redis.counts];
 assert.equal(await acceptBoundProof(redis,r.req,27,r.bytes,r.bearer,d.claims),null);
 const bad=request(27,d);bad.req.headers.set('x-sp-proof','invalid');
 assert.equal(await acceptBoundProof(redis,bad.req,27,bad.bytes,bad.bearer,d.claims),null);
 assert.deepEqual([...redis.counts],counts);
});
test('preflight/status/history polling does not consume analysis quotas; paid starts still do',async()=>{
 const redis=new Redis(),d=device();
 for(const op of [25,29,30])for(let n=0;n<15;n++)assert.equal(await call(redis,op,d),d.claims);
 assert(![...redis.counts.keys()].some(k=>k.includes('work:')||k.includes('work-')));
 for(let n=0;n<10;n++)assert.equal(await call(redis,26,d),d.claims);
 assert.deepEqual(await call(redis,26,d),{rateLimited:true});
});
