import assert from 'node:assert/strict';
import {test} from 'node:test';
import {EventEmitter} from 'node:events';
import {generateKeyPairSync} from 'node:crypto';
import {parseHttpCustomReference,importHttpCustomReference,downloadApproved,approvedUrl,ExternalImportError} from '../lib/c35-provider.mjs';
import {externalImportRequest} from '../lib/c35-gateway.mjs';
import {decodeRequest} from '../lib/c3-gateway.mjs';
import {catalog} from '../lib/server-vpn-catalog.mjs';
import {validatePublicTextFormats} from '../lib/text-format-catalog.mjs';
import {createChallenge,issueSession} from '../lib/c3-session.mjs';
const short='https://link.playsmarty.uk/Test-Only',direct='https://cloudvpn.mrfrankofc.com/Ab12Cd';
const encrypted=Buffer.from([0,255,128,13,10,0,120,13,10,190]);
const dns=async()=>[{address:'104.21.1.2',family:4}];
function transport(replies,requests=[]){return (url,options,callback)=>{
 requests.push({url:url.href,options});
 const req=new EventEmitter();req.write=()=>assert.fail('unexpected provider POST');req.destroy=()=>{};
 req.end=()=>queueMicrotask(()=>{
  const reply=replies.shift();assert(reply,'unexpected retry');
  const res=new EventEmitter();res.statusCode=reply.status??200;res.headers=reply.headers??{};res.destroy=()=>{};
  callback(res);
  if(res.statusCode===200){for(const chunk of reply.chunks??[encrypted])res.emit('data',chunk);res.emit('end');}
 });return req;
};}
test('HC references reject foreign origins, credentials, ports, encodings, traversal and query overrides',()=>{
 for(const link of [short,direct,' '+direct+'\n'])assert.equal(parseHttpCustomReference(link),link.trim());
 for(const link of ['http://link.playsmarty.uk/Ab12Cd','https://link.playsmarty.uk.evil.test/Ab12Cd',
  'https://link.playsmarty.uk@127.0.0.1/Ab12Cd','https://127.0.0.1/Ab12Cd',direct+'?url=http://localhost',
  direct+'#x',direct+'/extra','https://link.playsmarty.uk:443/Ab12Cd','https://link.playsmarty.uk/%41b12Cd',
  'https://link.playsmarty.uk/a/../Ab12Cd','https://cloudvpn.mrfrankofc.com/invalid-alias'])
  assert.throws(()=>parseHttpCustomReference(link),{code:'INVALID_REFERENCE'});
 assert.throws(()=>approvedUrl(' '+direct,'hc'),{code:'REMOTE_NETWORK_DENIED'});
});
test('bounded approved-host redirect pins DNS/TLS, sends no identity and preserves binary bytes',async()=>{
 const requests=[],hosts=[];
 const result=await downloadApproved({url:short,kind:'hc'},{resolve:async h=>{hosts.push(h);return dns();},
  request:transport([{status:302,headers:{location:direct}},{chunks:[encrypted.subarray(0,3),encrypted.subarray(3)]}],requests)});
 assert.deepEqual(result,encrypted);assert.equal(requests.length,2);
 assert.deepEqual(hosts,['link.playsmarty.uk','cloudvpn.mrfrankofc.com']);
 for(const {url,options} of requests){
  assert.equal(options.method,'GET');assert.equal(options.rejectUnauthorized,true);
  assert.equal(options.headers.Authorization,undefined);assert.equal(options.headers.Cookie,undefined);
  options.lookup(new URL(url).hostname,{all:true},(error,items)=>{
   assert.ifError(error);assert.deepEqual(items,[{address:'104.21.1.2',family:4}]);
  });
 }
});
test('private DNS and redirects outside the two validated reference forms fail before the next socket',async()=>{
 for(const location of ['http://cloudvpn.mrfrankofc.com/Ab12Cd','https://evil.test/Ab12Cd','https://127.0.0.1/Ab12Cd',direct+'?x=1']){
  const requests=[];
  await assert.rejects(()=>downloadApproved({url:short,kind:'hc'},{resolve:dns,request:transport([{status:302,headers:{location}}],requests)}),{code:'REMOTE_NETWORK_DENIED'});
  assert.equal(requests.length,1);
 }
 await assert.rejects(()=>downloadApproved({url:short,kind:'hc'},{resolve:async()=>[{address:'104.21.1.2',family:4},{address:'127.0.0.1',family:4}],request:()=>assert.fail('private DNS opened socket')}),{code:'REMOTE_NETWORK_DENIED'});
});
test('expired links map to 410 and HTTP failures are never retried or sent to a decoder',async()=>{
 for(const [status,code] of [[404,'REMOTE_CONFIG_UNAVAILABLE'],[410,'REMOTE_CONFIG_UNAVAILABLE'],[429,'REMOTE_PROVIDER_UNAVAILABLE'],[500,'REMOTE_PROVIDER_UNAVAILABLE']]){
  const requests=[];
  await assert.rejects(()=>downloadApproved({url:short,kind:'hc'},{resolve:dns,request:transport([{status}],requests)}),error=>error.code===code&&(status!==404||error.status===410));
  assert.equal(requests.length,1);
 }
});
test('HTML, compression, size overflow and loops are rejected without interpreting source code',async()=>{
 for(const response of [{headers:{'content-type':'text/html'}},{headers:{'content-encoding':'gzip'}},{headers:{'content-length':'8388609'}},{chunks:[Buffer.alloc(8*1024*1024),Buffer.from([1])]}])
  await assert.rejects(()=>downloadApproved({url:direct,kind:'hc'},{resolve:dns,request:transport([response])}));
 await assert.rejects(()=>downloadApproved({url:short,kind:'hc'},{resolve:dns,request:transport([{status:302,headers:{location:short}}])}),{code:'REMOTE_PROVIDER_UNAVAILABLE'});
 for(const data of [Buffer.alloc(0),Buffer.from('<!doctype html><html>expired</html>'),null])
  await assert.rejects(()=>importHttpCustomReference(direct,{download:async()=>data}),{code:'REMOTE_RESPONSE_INVALID'});
 await assert.rejects(()=>downloadApproved({url:direct,kind:'hc',method:'POST'}),{code:'REMOTE_NETWORK_DENIED'});
});
const rsa=generateKeyPairSync('rsa',{modulusLength:2048});
Object.assign(process.env,{CLOUD_API_ENABLED:'true',CLOUD_WORKER_TOKEN:'w'.repeat(48),CLOUD_SESSION_SIGNING_KEY:'z'.repeat(48),CLOUD_REDIS_URL:'redis://redis:6379',CLOUD_TRUST_PROXY:'true',CLOUD_GOOGLE_PLAY_PACKAGE:'com.ghostdeveloper.spdecode',WORKER_INTERNAL_URL:'http://decoder-worker:8787',CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON:JSON.stringify({type:'service_account',client_email:'synthetic@example.invalid',private_key:rsa.privateKey.export({type:'pkcs8',format:'pem'})})});
class Redis {
 constructor(){this.values=new Map();this.count=new Map();this.active=new Map();}
 async set(k,v,{NX}={}){if(NX&&this.values.has(k))return null;this.values.set(k,v);return 'OK';}
 async get(k){return this.values.get(k)??null;}
 async getDel(k){const v=await this.get(k);this.values.delete(k);return v;}
 async incr(k){const v=(this.count.get(k)||0)+1;this.count.set(k,v);return v;}
 async expire(){return 1;}
 async eval(_,args){const ids=this.active.get(args.keys[0])||new Map();ids.set(args.arguments[0],Date.now());this.active.set(args.keys[0],ids);return 1;}
 async zRem(k,id){this.active.get(k)?.delete(id);return 1;}
}
function send(body,token){return new Request('https://spdecode.test/api/v1/decode/import/http-custom',{method:'POST',headers:{'Content-Type':'application/json','X-Real-IP':'203.0.113.25',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(body)});}
async function session(redis){
 const ch=await createChallenge(redis,send({}));
 const issued=await issueSession(redis,send({}),{challengeId:ch.challengeId,integrityToken:'I'.repeat(100)},{signingKey:process.env.CLOUD_SESSION_SIGNING_KEY},async()=>true);
 assert(issued.accessToken);return issued.accessToken;
}
test('download-only route requires session and consent; returns original ciphertext without server storage',async()=>{
 const redis=new Redis(),bearer=await session(redis);let calls=0;
 const opts={storeProvider:async()=>redis,vendor:{download:async()=>{calls++;return encrypted;}}};
 assert.equal((await externalImportRequest(send({reference:short,consent:true}),'hc',opts)).status,401);
 for(const body of [{reference:short},{reference:short,consent:false},{reference:short,consent:true,url:direct}])
  assert.equal((await externalImportRequest(send(body,bearer),'hc',opts)).status,400);
 assert.equal(calls,0);
 const response=await externalImportRequest(send({reference:short,consent:true},bearer),'hc',opts),data=await response.json();
 assert.equal(response.status,200);assert.equal(calls,1);assert.equal(data.kind,'encrypted_file');assert.equal(data.format,'hc');
 assert.deepEqual(Buffer.from(data.dataBase64,'base64'),encrypted);assert.equal(data.sourceBytes,encrypted.length);
 assert.match(response.headers.get('cache-control'),/no-store/);
 const persisted=JSON.stringify([...redis.values]);assert(!persisted.includes(short));assert(!persisted.includes(encrypted.toString('base64')));
 for(const ids of redis.active.values())assert.equal(ids.size,0);
});
test('pasted HTTP reference passes exact ciphertext, password and HWID through the canonical HC worker',async()=>{
 const redis=new Redis(),bearer=await session(redis);let downloads=0,workers=0;
 const credentials={password:'  synthetic ñ  ',hwid:'A'.repeat(32)},original={config:[{options:{keep:[null,false,23]},host:'example.test'}]};
 const response=await decodeRequest(send({text:short,credentials},bearer),'text',{storeProvider:async()=>redis,vendor:{download:async()=>{downloads++;return encrypted;}},fetchImpl:async(url,options)=>{
  workers++;assert.equal(url,'http://decoder-worker:8787/internal/v1/decode/file');
  const input=JSON.parse(options.body);assert.equal(input.format,'hc');assert.deepEqual(input.credentials,credentials);assert.deepEqual(Buffer.from(input.dataBase64,'base64'),encrypted);
  return new Response(JSON.stringify({status:'success',kind:'file',format:'hc',isPartial:false,rawText:JSON.stringify(original),structuredJson:original}),{status:200});
 }});
 assert.equal(response.status,200);assert.deepEqual((await response.json()).structuredJson,original);assert.equal(downloads,1);assert.equal(workers,1);
});
test('unavailable source skips worker, releases lease and respects the persistent provider prerequisite',async()=>{
 const redis=new Redis(),bearer=await session(redis);let calls=0;
 const opts={storeProvider:async()=>redis,vendor:{download:async()=>{calls++;throw new ExternalImportError('REMOTE_CONFIG_UNAVAILABLE');}},fetchImpl:async()=>assert.fail('missing file reached worker')};
 const response=await externalImportRequest(send({reference:short,consent:true},bearer),'hc',opts);
 assert.equal(response.status,410);assert.equal((await response.json()).error.code,'REMOTE_CONFIG_UNAVAILABLE');
 for(const ids of redis.active.values())assert.equal(ids.size,0);
 process.env.CLOUD_HTTP_CUSTOM_IMPORT_ENABLED='false';
 try{assert.equal((await externalImportRequest(send({reference:short,consent:true},bearer),'hc',opts)).status,503);assert.equal(calls,1);}
 finally{delete process.env.CLOUD_HTTP_CUSTOM_IMPORT_ENABLED;}
});
test('online HTTPS metadata is additive and leaves the legacy text schema valid',()=>{
 const c=catalog();assert.equal(c.catalogVersion,53);validatePublicTextFormats({schemaVersion:1,formats:c.textFormats});
 assert.equal(c.onlineReferencesSchemaVersion,1);assert.equal(c.onlineReferenceCount,2);
 assert.deepEqual(c.onlineReferenceFormats.map(x=>x.prefix).sort(),['https://cloudvpn.mrfrankofc.com/','https://link.playsmarty.uk/'].sort());
 assert(c.onlineReferenceFormats.every(x=>x.suffix==='hc'&&x.kind==='cloud'));
});
