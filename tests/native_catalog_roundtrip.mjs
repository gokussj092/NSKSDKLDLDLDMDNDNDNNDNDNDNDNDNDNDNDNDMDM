import assert from 'node:assert/strict';
import {spawnSync,spawn} from 'node:child_process';
import {generateKeyPairSync} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {sealCatalog} from '../cloud/web/lib/catalog-envelope.mjs';
const cli=process.argv[2];
if(!cli)throw new Error('native catalog CLI required');
const pair=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const encoded=p=>p.publicKey.export({format:'der',type:'spki'}).toString('base64url');
const secret=p=>p.privateKey.export({format:'der',type:'pkcs8'}).toString('base64url');
function run(key,recipient,envelope,purpose='catalog') {
 return spawnSync(cli,[secret(key),recipient,purpose,envelope.serverKey,
   envelope.salt,envelope.iv,String(envelope.plainBytes),envelope.data],
   {encoding:'buffer',maxBuffer:8*1024*1024});
}
const p=pair();
const source={apps:[{name:'México 👻 漢字',label:'catalog native interoperability'}],
              catalogVersion:73,unchanged:false};
const sealed=sealCatalog(source,encoded(p),'catalog');
const result=run(p,encoded(p),sealed);
assert.equal(result.status,0,result.stderr?.toString());
assert.deepEqual(JSON.parse(gunzipSync(result.stdout).toString('utf8')),source);
const icon=sealCatalog({icons:['NPV']},encoded(p),'icon');
const i=run(p,encoded(p),icon,'icon');
assert.equal(i.status,0);
assert.deepEqual(JSON.parse(gunzipSync(i.stdout).toString('utf8')),{icons:['NPV']});
assert.notEqual(run(pair(),encoded(p),sealed).status,0,'wrong recipient');
assert.notEqual(run(p,encoded(p),sealed,'icon').status,0,'cross-purpose');
assert.notEqual(run(p,encoded(p),{...sealed,plainBytes:sealed.plainBytes+1}).status,0,'AAD length');
const damaged=Buffer.from(sealed.data,'base64url');damaged[0]^=1;
assert.notEqual(run(p,encoded(p),{...sealed,data:damaged.toString('base64url')}).status,0,'AEAD ciphertext tamper');
const badTag=Buffer.from(sealed.data,'base64url');badTag[badTag.length-1]^=1;
assert.notEqual(run(p,encoded(p),{...sealed,data:badTag.toString('base64url')}).status,0,'AEAD tag tamper');
assert.notEqual(run(p,encoded(p),{...sealed,serverKey:sealed.serverKey+'='}).status,0,'noncanonical key');
assert.notEqual(run(p,encoded(p),{...sealed,plainBytes:4*1024*1024+1}).status,0,'oversize');
// Native client generates and retains its own P-256 secret; no PKCS#8/JVM crossing.
async function nativeIssuedRoundtrip(document,purpose) {
 return await new Promise((resolve,reject)=>{
  const child=spawn(cli,['--live'],{stdio:['pipe','pipe','pipe'],timeout:20000});
  const chunks=[];let error='';let keySent=false;
  child.stdout.on('data',chunk=>chunks.push(chunk));
  child.stderr.on('data',chunk=>{
   error+=chunk.toString('utf8');
   if(!keySent && error.includes('\n')) {
    keySent=true;
    const pub=error.slice(0,error.indexOf('\n')).trim();
    try {
     const sealed=sealCatalog(document,pub,purpose);
     child.stdin.end([purpose,sealed.serverKey,sealed.salt,sealed.iv,
        String(sealed.plainBytes),sealed.data].join('\n')+'\n');
    }catch(e){child.kill();reject(e);}
   }
  });
  child.on('error',reject);
  child.on('close',(status)=>{
   if(status!==0||!keySent)reject(new Error('native-issued catalog failed: '+error+' exit '+status));
   else {
    try{resolve(JSON.parse(gunzipSync(Buffer.concat(chunks)).toString('utf8')))}
    catch(e){reject(e);}
   }
  });
 });
}
assert.deepEqual(await nativeIssuedRoundtrip(source,'catalog'),source);
assert.deepEqual(await nativeIssuedRoundtrip({icons:['NPV']},'icon'),{icons:['NPV']});
console.log('PASS native C++ generated/kept P-256 + unchanged Node.js authenticated envelope');
const bundled={iconBundle:{icons:[{id:'synthetic',contentBase64:'a'.repeat(5*1024*1024)}]}};
assert.deepEqual(await nativeIssuedRoundtrip(bundled,'catalog'),bundled);
console.log('PASS native catalog above 4 MiB with the 32 MiB catalog bound');
