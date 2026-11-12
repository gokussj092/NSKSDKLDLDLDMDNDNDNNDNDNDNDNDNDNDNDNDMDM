/** Immutable content-addressed directory objects. No provider payloads or URLs. */
import {createHash,randomUUID} from "node:crypto";
import {mkdir,open,readFile,rename,readdir,stat,unlink} from "node:fs/promises";
import {join} from "node:path";
export const CHUNK_BYTES=256*1024,MAX_TOTAL=64*1024*1024,MAX_OBJECT=6*1024*1024;
export const SNAPSHOT_TTL=7*86400_000;
export const snapshotRoot=()=>process.env.CLOUD_CATALOG_SNAPSHOT_ROOT||"/app/catalog-snapshots";
export const chunksEnabled=(env=process.env)=>env.CLOUD_CATALOG_CHUNKS_ENABLED==="true";
export const hash=bytes=>createHash("sha256").update(bytes).digest("hex");
const hex=value=>typeof value==="string"&&/^[a-f0-9]{64}$/.test(value);
const locks=new Map();
function invalid(code="CATALOG_SCHEMA_INVALID"){throw Object.assign(Error(code),{code});}
async function atomic(path,bytes){
 const tmp=path+".tmp-"+randomUUID();
 try{const f=await open(tmp,"wx",0o600);try{await f.writeFile(bytes);await f.sync();}finally{await f.close();}await rename(tmp,path);}finally{await unlink(tmp).catch(()=>{});}
}
async function pruneExpired(root,now){
 const names=await readdir(root),live=new Set(),references=new Set();
 for(const name of names){
  if(!/^manifest-[a-f0-9]{64}$/.test(name))continue;
  try{
   const bytes=await readFile(join(root,name));if(bytes.length>256*1024||hash(bytes)!==name.slice(9))continue;
   const core=JSON.parse(bytes);if(core.validUntil<=now){await unlink(join(root,name));continue;}
   live.add(name.slice(9));for(const obj of core.objects)references.add(obj.sha256);
  }catch{}
 }
 for(const name of names){
  if(/^object-[a-f0-9]{64}$/.test(name)&&!references.has(name.slice(7)))await unlink(join(root,name)).catch(()=>{});
  if(/^index-[a-f0-9]{64}$/.test(name)){const id=(await readFile(join(root,name),"utf8")).trim();if(!live.has(id))await unlink(join(root,name)).catch(()=>{});}
 }
}
export function displayVersion(env=process.env){
 const value=env.CLOUD_SERVER_VPN_DISPLAY_VERSION;
 if(value===undefined||value==="")return null;
 if(!/^[1-9][0-9]{0,8}$/.test(value))invalid();
 return value;
}
export async function publishSnapshot(metadata,icons,{root=snapshotRoot(),now=Date.now()}={}){
 const previous=locks.get(root)||Promise.resolve();let release;
 const current=new Promise(resolve=>{release=resolve;});locks.set(root,current);
 await previous.catch(()=>{});
 try{
  if(!metadata||!Number.isSafeInteger(metadata.catalogVersion)||metadata.catalogVersion<1||!Array.isArray(metadata.apps)||metadata.apps.length<1||metadata.apps.length>500)invalid();
  const meta=Buffer.from(JSON.stringify(metadata));if(meta.length>2*1024*1024)invalid();
  const fingerprint=hash(meta);await mkdir(root,{recursive:true,mode:0o700});await pruneExpired(root,now);
  try{const id=(await readFile(join(root,"index-"+fingerprint),"utf8")).trim();const existing=await loadManifest(id,{root,now});return existing;}catch{}
  const objects=[{type:"metadata",bytes:meta}],seen=new Set([fingerprint]),ids=new Set();
  for(const app of metadata.apps){
   if(typeof app.id!=="string"||!/^[a-z0-9-]{1,48}$/.test(app.id)||ids.has(app.id)||typeof app.name!=="string"||!app.name.trim()||app.name.length>80)invalid();
   ids.add(app.id);
   if(!hex(app.iconSha256))invalid();
   if(seen.has(app.iconSha256))continue;
   const bytes=icons.get(app.iconSha256);
   if(!Buffer.isBuffer(bytes)||bytes.length<32||bytes.length>MAX_OBJECT||hash(bytes)!==app.iconSha256||bytes.subarray(0,8).toString("hex")!=="89504e470d0a1a0a")invalid();
   seen.add(app.iconSha256);objects.push({type:"icon",bytes});
  }
  const total=objects.reduce((n,x)=>n+x.bytes.length,0);if(total>MAX_TOTAL)invalid("CATALOG_MEMORY_LIMIT");
  // Bounded disk quota. Expired snapshots were pruned above; never
  // delete a still resumable snapshot to make an incomplete publication fit.
  const names=await readdir(root);let disk=0;
  for(const name of names){if(!/^(?:object-|manifest-|index-)[a-f0-9]{64}$/.test(name))continue;disk+=(await stat(join(root,name))).size;}
  if(disk+total>256*1024*1024)invalid("CATALOG_STORAGE_LIMIT");
  const descriptors=[];
  for(const {type,bytes} of objects){
   const sha256=hash(bytes),path=join(root,"object-"+sha256);
   let valid=false;try{valid=hash(await readFile(path))===sha256;}catch{}
   if(!valid)await atomic(path,bytes);
   const chunks=[];for(let offset=0;offset<bytes.length;offset+=CHUNK_BYTES)chunks.push(hash(bytes.subarray(offset,offset+CHUNK_BYTES)));
   descriptors.push({type,sha256,byteLength:bytes.length,chunkSize:CHUNK_BYTES,chunkCount:chunks.length,chunks});
  }
  const core={protocol:"catalog-chunks-v1",schemaVersion:1,catalogVersion:metadata.catalogVersion,displayVersion:metadata.displayVersion??null,
   createdAt:now,validUntil:now+SNAPSHOT_TTL,totalLogicalBytes:total,objects:descriptors};
  const bytes=Buffer.from(JSON.stringify(core));if(bytes.length>256*1024)invalid();
  const snapshotId=hash(bytes);await atomic(join(root,"manifest-"+snapshotId),bytes);
  await atomic(join(root,"index-"+fingerprint),Buffer.from(snapshotId));
  return {snapshotId,manifestHash:snapshotId,manifestBase64:bytes.toString("base64"),core};
 }finally{release();if(locks.get(root)===current)locks.delete(root);}
}
export async function loadManifest(snapshotId,{root=snapshotRoot(),now=Date.now()}={}){
 if(!hex(snapshotId))invalid();
 let bytes;try{const info=await stat(join(root,"manifest-"+snapshotId));if(info.size>256*1024)invalid();bytes=await readFile(join(root,"manifest-"+snapshotId));}catch{invalid("CATALOG_SNAPSHOT_EXPIRED");}
 if(hash(bytes)!==snapshotId)invalid("CATALOG_OBJECT_HASH_MISMATCH");
 const core=JSON.parse(bytes);if(core.validUntil<=now)invalid("CATALOG_SNAPSHOT_EXPIRED");
 return {snapshotId,manifestHash:snapshotId,manifestBase64:bytes.toString("base64"),core};
}
export async function readChunk(input,options={}){
 if(!input||Object.keys(input).sort().join(",")!=="chunkIndex,manifestHash,objectHash,snapshotId"||input.snapshotId!==input.manifestHash||!hex(input.objectHash)||!Number.isSafeInteger(input.chunkIndex)||input.chunkIndex<0)invalid();
 const {core}=await loadManifest(input.snapshotId,options),obj=core.objects.find(x=>x.sha256===input.objectHash);
 if(!obj||input.chunkIndex>=obj.chunkCount)invalid();
 const offset=input.chunkIndex*obj.chunkSize,length=Math.min(obj.chunkSize,obj.byteLength-offset),data=Buffer.alloc(length);
 const f=await open(join(options.root||snapshotRoot(),"object-"+obj.sha256),"r");
 try{if((await f.stat()).size!==obj.byteLength)invalid("CATALOG_OBJECT_HASH_MISMATCH");let done=0;while(done<length){const {bytesRead}=await f.read(data,done,length-done,offset+done);if(!bytesRead)invalid("CATALOG_TRANSFER_TRUNCATED");done+=bytesRead;}}finally{await f.close();}
 if(hash(data)!==obj.chunks[input.chunkIndex])invalid("CATALOG_OBJECT_HASH_MISMATCH");
 return {...input,byteLength:length,sha256:obj.chunks[input.chunkIndex],dataBase64:data.toString("base64")};
}
