import {boundRequestClaims} from "./v2-bound-request.mjs";
import {store,throttle} from "./c3-store.mjs";
import {providerOverview} from "./c12-provider-controls.mjs";
import {catalog,iconFor} from "./server-vpn-catalog.mjs";
import {exportPolicy,exportCatalog,projectedCatalogVersion} from "./compatible-export-policy.mjs";
import {chunksEnabled,publishSnapshot,loadManifest,readChunk,hash} from "./catalog-snapshots.mjs";
const reply=(body,status=200)=>Response.json(body,{status,headers:{"Cache-Control":"no-store"}});
const prepared=new Map();
export async function currentSnapshot(request,preparedSummary=null){
 const summary=preparedSummary??await providerOverview(process.env,{syncCatalog:true}),policy=await exportPolicy();
 const version=projectedCatalogVersion(request,summary.catalogVersion,policy);
 const capabilities=exportCatalog(request,policy);
 const key=hash(Buffer.from(JSON.stringify({summary,version,capabilities,root:process.env.CLOUD_CATALOG_SNAPSHOT_ROOT||"default"})));
 const cached=prepared.get(key);if(cached&&cached.until>Date.now())return cached.promise;
 const promise=(async()=>{
 const availability=Object.fromEntries(summary.providers.map(p=>[p.id,p.enabled]));
 const methodStates=Object.fromEntries((summary.methodStatuses||[]).map(({id,methodRevision,maintenance})=>[id,{methodRevision,maintenance}]));
 const data=catalog({availability,methodStates,version});data.displayVersion=summary.displayVersion;
 if(capabilities)data.compatibleExports=capabilities;
 const icons=new Map();for(const app of data.apps){const image=iconFor(app.id);icons.set(image.sha256,image.bytes);}
 return publishSnapshot(data,icons);
 })();
 prepared.set(key,{until:Date.now()+300_000,promise});
 if(prepared.size>8)prepared.delete(prepared.keys().next().value);
 try{return await promise;}catch(error){if(prepared.get(key)?.promise===promise)prepared.delete(key);throw error;}
}
export async function catalogChunkRequest(kind,request,{env=process.env,storeProvider=store,publish=currentSnapshot}={}){
 const claims=boundRequestClaims(request);
 if(!claims?.hpke)return reply({error:{code:"UNAUTHORIZED"}},401);
 if(!chunksEnabled(env))return reply({error:{code:"CATALOG_CHUNKS_UNSUPPORTED"}},404);
 try{
  const text=await request.text();if(Buffer.byteLength(text)>2048)return reply({error:{code:"INVALID_REQUEST"}},400);
  const input=JSON.parse(text);if(!input||typeof input!=="object"||Array.isArray(input))throw Error("schema");
  const redis=await storeProvider(),owner=hash(Buffer.from(claims.jti+":"+claims.key));
  if(!await throttle(redis,"spc2:catalog-chunks-rate:"+owner,120,60))return Response.json({error:{code:"RATE_LIMITED",retryAfterMillis:60_000}},{status:429,headers:{"Cache-Control":"no-store","Retry-After":"60"}});
  if(kind==="manifest"){
   if(Object.keys(input).some(k=>!["knownVersion","snapshotId"].includes(k))||!Number.isSafeInteger(input.knownVersion)||input.knownVersion<0)throw Error("schema");
   let snapshot;
   if(input.snapshotId){try{snapshot=await loadManifest(input.snapshotId);}catch(e){if(e.code!=="CATALOG_SNAPSHOT_EXPIRED")throw e;}}
   snapshot??=await publish(request);
   if(snapshot.core.catalogVersion<input.knownVersion)return reply({error:{code:"CATALOG_VERSION_CONFLICT"}},409);
   await redis.set("spc2:catalog-lease:"+owner+":"+snapshot.snapshotId,"1",{EX:1800});
   const {core,...wire}=snapshot;return reply({protocol:"catalog-chunks-v1",...wire});
  }
  if(typeof input.snapshotId!=="string"||!/^[a-f0-9]{64}$/.test(input.snapshotId))throw Error("schema");
  if(!await redis.get("spc2:catalog-lease:"+owner+":"+input.snapshotId))return reply({error:{code:"CATALOG_LEASE_EXPIRED"}},409);
  return reply(await readChunk(input));
 }catch(error){const code=/^CATALOG_[A-Z_]+$/.test(error.code||"")?error.code:"INVALID_REQUEST";return reply({error:{code}},code==="CATALOG_SNAPSHOT_EXPIRED"?410:code==="INVALID_REQUEST"?400:503);}
}
