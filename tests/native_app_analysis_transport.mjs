// Real C++ HPKE/proof -> existing Node server -> real C++ reply decryption.
// Uses disposable cryptographic identities, never production credentials.
import assert from 'node:assert/strict';
import test from 'node:test';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {openHpkeRequest,unpackHpkeBody,sealHpkeReply} from '../cloud/web/lib/v2-hpke.mjs';
import {proofMessage,verifyProof} from '../cloud/web/lib/v2-proof.mjs';
import {inlineActionHash,protectedActions} from '../cloud/web/lib/action-integrity.mjs';

const cli=process.argv[2];
assert.ok(cli,'Pass the compiled native_app_analysis_transport fixture');
const bearer='fixture.session',timestamp='1793380000',nonce='A'.repeat(32),version='1.1.29';
const sha=bytes=>createHash('sha256').update(bytes).digest();
for(const op of [25,26,27,28,29,30,5,6]){
 test(`native operation ${op}: HPKE, signed bytes, action binding and authenticated reply`,async()=>{
  const hpke=generateKeyPairSync('x25519'),proof=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const publicKey=hpke.publicKey.export({format:'jwk'}).x;
  const privateKey=hpke.privateKey.export({format:'jwk'}).d;
  const rawPublic=Buffer.from(publicKey,'base64url');
  const pin=Buffer.concat([sha(rawPublic).subarray(0,8),rawPublic]);
  const metadata={accountToken:'synthetic-account-token-for-transport-test',fixture:true};
  const tail=[5,27].includes(op)?Buffer.from('synthetic attachment'):Buffer.alloc(0);
  const child=spawn(cli,[String(op),pin.toString('hex'),JSON.stringify(metadata),tail.toString('hex')],
    {stdio:['pipe','pipe','pipe'],timeout:15000});
  let stderr='';child.stderr.setEncoding('utf8');child.stderr.on('data',data=>stderr+=data);
  const exited=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});
  const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
  async function line(){const next=await lines.next();assert.equal(next.done,false,stderr);return next.value;}
  try{
   const wire=Buffer.from(await line(),'hex');
   const nativeProof=Buffer.from(await line(),'hex').toString('utf8');
   const actionId=await line(),actionHash=await line();
   const expected=proofMessage(op,version,timestamp,nonce,bearer,wire);
   assert.equal(nativeProof,expected,'native proof must cover the exact encrypted request');
   const encodedKey=proof.publicKey.export({format:'der',type:'spki'}).toString('base64url');
   const signature=sign('sha256',Buffer.from(nativeProof),proof.privateKey).toString('base64url');
   const request=new Request('https://fixture.invalid/api/v2/transport',{method:'POST',headers:{
    'x-sp-timestamp':timestamp,'x-sp-nonce':nonce,'x-sp-proof':signature,
    'x-spdecode-app-version':version}});
   assert.equal(verifyProof(request,op,wire,bearer,encodedKey,Number(timestamp)*1000),nonce);
   const altered=Buffer.from(wire);altered[altered.length-1]^=1;
   assert.equal(verifyProof(request,op,altered,bearer,encodedKey,Number(timestamp)*1000),null);
   if([26,28].includes(op)){
    assert.ok(protectedActions.has(op));
    assert.equal(inlineActionHash(bearer,op,sha(wire).toString('hex'),actionId),actionHash);
    assert.notEqual(inlineActionHash(bearer,op,sha(altered).toString('hex'),actionId),actionHash);
   }else assert.equal(actionId,'-');
   const opened=await openHpkeRequest(wire,op,{
    CLOUD_V2_HPKE_KEYRING:JSON.stringify([{publicKey,privateKey}])});
   const body=JSON.parse(unpackHpkeBody(opened.plaintext,op));
   assert.equal(body.accountToken,metadata.accountToken);
   if(tail.length)assert.equal(body.dataBase64,tail.toString('base64'));
   const response=op===25?{creditsAvailable:5,balance:7,held:2,creditPriceCents:399,
    currency:'USD',creditsPerAnalysis:1}:{ok:true};
   const reply=sealHpkeReply(opened,200,Buffer.from(JSON.stringify(response)));
   child.stdin.end(reply.toString('hex')+'\n');
   assert.deepEqual(JSON.parse(Buffer.from(await line(),'hex').toString('utf8')),response);
   assert.equal(await exited,0,stderr);
  }finally{child.kill();await exited;}
 });
}
