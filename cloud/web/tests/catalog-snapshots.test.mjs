import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,rm,writeFile} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {publishSnapshot,loadManifest,readChunk,hash,CHUNK_BYTES,displayVersion} from "../lib/catalog-snapshots.mjs";
import {catalogChunkRequest} from "../lib/catalog-chunk-api.mjs";
import {bindVerifiedRequest} from "../lib/v2-bound-request.mjs";
const image=Buffer.alloc(CHUNK_BYTES*2+17,17);Buffer.from("89504e470d0a1a0a","hex").copy(image);
function input(version=73){const sha=hash(image);return [{catalogVersion:version,displayVersion:null,apps:[{id:"fictional",name:"Synthetic only",iconSha256:sha}]},new Map([[sha,image]])];}
async function directory(t){const root=await mkdtemp(join(tmpdir(),"spdecode-snapshot-"));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
test("immutable manifest sizes and hashes exactly describe each published object",async t=>{
 const root=await directory(t),snapshot=await publishSnapshot(...input(),{root});
 assert.equal(hash(Buffer.from(snapshot.manifestBase64,"base64")),snapshot.snapshotId);
 const objects=snapshot.core.objects;assert.equal(objects.length,2);assert.equal(objects[1].chunkCount,3);
 let total=0;for(const obj of objects){let value=Buffer.alloc(0);for(let i=0;i<obj.chunkCount;i++){
  const chunk=await readChunk({snapshotId:snapshot.snapshotId,manifestHash:snapshot.snapshotId,objectHash:obj.sha256,chunkIndex:i},{root});
  const bytes=Buffer.from(chunk.dataBase64,"base64");assert.equal(bytes.length,chunk.byteLength);assert.equal(hash(bytes),obj.chunks[i]);value=Buffer.concat([value,bytes]);}
  assert.equal(value.length,obj.byteLength);assert.equal(hash(value),obj.sha256);total+=value.length;}
 assert.equal(total,snapshot.core.totalLogicalBytes);
 assert.equal((await publishSnapshot(...input(),{root})).snapshotId,snapshot.snapshotId);
});
test("an old immutable snapshot resumes after newer metadata publishes",async t=>{
 const root=await directory(t),old=await publishSnapshot(...input(),{root});const obj=old.core.objects[1];
 const request=i=>({snapshotId:old.snapshotId,manifestHash:old.snapshotId,objectHash:obj.sha256,chunkIndex:i});
 const first=await readChunk(request(0),{root});await publishSnapshot(...input(74),{root});
 const rest=await Promise.all([1,2].map(i=>readChunk(request(i),{root})));
 assert.deepEqual(Buffer.concat([first,...rest].map(x=>Buffer.from(x.dataBase64,"base64"))),image);
 assert.equal(rest.reduce((n,x)=>n+x.byteLength,0),image.length-CHUNK_BYTES);
});
test("expired snapshots, cross-snapshot substitutions, invalid indices and mutated files fail closed",async t=>{
 const root=await directory(t),s=await publishSnapshot(...input(),{root}),obj=s.core.objects[1];
 const good={snapshotId:s.snapshotId,manifestHash:s.snapshotId,objectHash:obj.sha256,chunkIndex:0};
 for(const bad of [{...good,chunkIndex:-1},{...good,chunkIndex:3},{...good,objectHash:"0".repeat(64)},{...good,manifestHash:"1".repeat(64)},{...good,url:"https://example.org/"}])await assert.rejects(()=>readChunk(bad,{root}));
 await assert.rejects(()=>loadManifest(s.snapshotId,{root,now:s.core.validUntil}),{code:"CATALOG_SNAPSHOT_EXPIRED"});
 await writeFile(join(root,"object-"+obj.sha256),Buffer.alloc(image.length));await assert.rejects(()=>readChunk(good,{root}),{code:"CATALOG_OBJECT_HASH_MISMATCH"});
});
test("publication rejects incomplete objects and editorial version is never inferred",async t=>{
 const root=await directory(t),[metadata]=input();await assert.rejects(()=>publishSnapshot(metadata,new Map(),{root}));
 assert.equal(displayVersion({}),null);assert.equal(displayVersion({CLOUD_SERVER_VPN_DISPLAY_VERSION:"13"}),"13");
 for(const value of ["0","-1","1.2","2738494x"])assert.throws(()=>displayVersion({CLOUD_SERVER_VPN_DISPLAY_VERSION:value}));
});
test("chunk API requires server-bound HPKE context, explicit feature flag and a session lease",async()=>{
 const request=()=>new Request("https://api.example.org/api/v1/server-vpn/chunk",{method:"POST",body:'{"snapshotId":"'+"a".repeat(64)+'"}'});
 assert.equal((await catalogChunkRequest("chunk",request())).status,401);
 const plain=request();bindVerifiedRequest(plain,{key:"k",jti:"j",hpke:false});assert.equal((await catalogChunkRequest("chunk",plain)).status,401);
 const disabled=request();bindVerifiedRequest(disabled,{key:"k",jti:"j",hpke:true});assert.equal((await catalogChunkRequest("chunk",disabled,{env:{}})).status,404);
 const enabled=request();bindVerifiedRequest(enabled,{key:"k",jti:"j",hpke:true});
 const redis={get:async()=>null,eval:async()=>1};
 const response=await catalogChunkRequest("chunk",enabled,{env:{CLOUD_CATALOG_CHUNKS_ENABLED:"true"},storeProvider:async()=>redis});assert.equal(response.status,409);
});
test("expiry pruning removes retired objects but preserves a still valid snapshot",async t=>{
 const root=await directory(t),old=await publishSnapshot(...input(),{root,now:1000});
 const current=await publishSnapshot(...input(74),{root,now:old.core.validUntil+1});
 await assert.rejects(()=>loadManifest(old.snapshotId,{root,now:old.core.validUntil+1}),{code:"CATALOG_SNAPSHOT_EXPIRED"});
 assert.equal((await loadManifest(current.snapshotId,{root,now:old.core.validUntil+1})).snapshotId,current.snapshotId);
 const obj=current.core.objects[1];assert.equal((await readChunk({snapshotId:current.snapshotId,manifestHash:current.snapshotId,objectHash:obj.sha256,chunkIndex:0},{root,now:old.core.validUntil+1})).byteLength,CHUNK_BYTES);
});
test("rate limits carry authenticated retry delay and do not create a download lease",async()=>{
 const request=new Request("https://api.example.org/api/v1/server-vpn/manifest",{method:"POST",body:'{"knownVersion":0}'});
 bindVerifiedRequest(request,{key:"k",jti:"j",hpke:true});
 const redis={eval:async()=>121,set:async()=>assert.fail("lease must not be written")};
 const response=await catalogChunkRequest("manifest",request,{env:{CLOUD_CATALOG_CHUNKS_ENABLED:"true"},storeProvider:async()=>redis});
 assert.equal(response.status,429);assert.equal(response.headers.get("Retry-After"),"60");assert.equal((await response.json()).error.retryAfterMillis,60000);
});
