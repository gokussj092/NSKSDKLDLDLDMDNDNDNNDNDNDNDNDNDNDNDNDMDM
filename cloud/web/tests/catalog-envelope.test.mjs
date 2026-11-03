import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createPublicKey,diffieHellman,hkdfSync,createDecipheriv} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {sealCatalog,validCatalogKey} from '../lib/catalog-envelope.mjs';
const pair=()=>generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const encoded=p=>p.publicKey.export({format:'der',type:'spki'}).toString('base64url');
function open(e,p,purpose='catalog') {
 const shared=diffieHellman({privateKey:p.privateKey,publicKey:createPublicKey({key:Buffer.from(e.serverKey,'base64url'),format:'der',type:'spki'})});
 const key=Buffer.from(hkdfSync('sha256',shared,Buffer.from(e.salt,'base64url'),Buffer.from('SPDECODE-CATALOG-1:'+purpose),32));
 const cipher=createDecipheriv('aes-256-gcm',key,Buffer.from(e.iv,'base64url'));
 cipher.setAAD(Buffer.from(['SPDECODE-CATALOG-1',purpose,encoded(p),e.serverKey,String(e.plainBytes)].join('\n')));
 const data=Buffer.from(e.data,'base64url');cipher.setAuthTag(data.subarray(-16));
 return JSON.parse(gunzipSync(Buffer.concat([cipher.update(data.subarray(0,-16)),cipher.final()]),{maxOutputLength:32*1024*1024}));
}
test('compressed catalog envelope decrypts Unicode and never repeats ephemeral key, salt or IV',()=>{
 const p=pair(),source={apps:[{name:'México 👻 漢字',metadata:'hello'.repeat(30000)}]};
 const e=sealCatalog(source,encoded(p),'catalog'),next=sealCatalog(source,encoded(p),'catalog');
 assert.deepEqual(open(e,p),source);assert(e.data.length<JSON.stringify(source).length/10);
 for(const field of ['serverKey','salt','iv','data'])assert.notEqual(e[field],next[field]);
 assert(!JSON.stringify(e).includes('México'));
});
test('wrong recipient, tampering, altered length and cross-purpose responses fail authentication',()=>{
 const p=pair(),e=sealCatalog({apps:[]},encoded(p),'catalog');
 assert.throws(()=>open(e,pair()));assert.throws(()=>open(e,p,'icon'));
 assert.throws(()=>open({...e,plainBytes:e.plainBytes+1},p));
 const data=Buffer.from(e.data,'base64url');data[0]^=1;
 assert.throws(()=>open({...e,data:data.toString('base64url')},p));
});
test('reject non-P256, noncanonical keys, arbitrary purposes and huge plaintext',()=>{
 const p=pair(),wrong=generateKeyPairSync('ec',{namedCurve:'secp384r1'});
 for(const key of ['',encoded(wrong),encoded(p)+'=',null])assert.equal(validCatalogKey(key),false);
 assert.throws(()=>sealCatalog({},encoded(p),'arbitrary'));
 assert.throws(()=>sealCatalog({data:'a'.repeat(32*1024*1024)},encoded(p),'catalog'));
});
