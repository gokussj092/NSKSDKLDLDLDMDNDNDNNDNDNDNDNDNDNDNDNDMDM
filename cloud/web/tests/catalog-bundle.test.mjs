import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {POST} from '../app/api/v1/server-vpn/catalog/route.js';
import {iconFor} from '../lib/server-vpn-catalog.mjs';
import {sealCatalog} from '../lib/catalog-envelope.mjs';
const request=bundle=>new Request('https://test.invalid/api/v1/server-vpn/catalog',{method:'POST',
 headers:{'content-type':'application/json',...(bundle?{'x-spdecode-catalog-bundle':'1'}:{})},body:'{"knownVersion":0}'});
test('one catalog response includes original icons and the legacy response stays compatible',async()=>{
 const response=await POST(request(true));assert.equal(response.status,200);const doc=await response.json();
 assert(doc.apps.length>50);assert.equal(doc.iconBundle.count,doc.apps.length);assert.equal(doc.iconBundle.icons.length,doc.apps.length);
 for(const app of doc.apps){const icon=doc.iconBundle.icons.find(i=>i.id===app.id);assert(icon);
  const bytes=Buffer.from(icon.contentBase64,'base64');assert.equal(createHash('sha256').update(bytes).digest('hex'),app.iconSha256);
  assert.deepEqual(bytes,iconFor(app.id).bytes);
 }
 const legacy=await POST(request(false));assert.equal(Object.hasOwn(await legacy.json(),'iconBundle'),false);
});
test('bundled catalogs above the old 4 MiB limit are accepted; icons keep their separate bound',()=>{
 const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'der',type:'spki'}).toString('base64url');
 const doc={data:'a'.repeat(5*1024*1024)};
 assert(sealCatalog(doc,key,'catalog').plainBytes>4*1024*1024);
 assert.throws(()=>sealCatalog(doc,key,'icon'));
});
