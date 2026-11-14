/** Encrypted cache of fixed-provider results, including validated MKK partials. Never cache user input. */
import {createCipheriv,createDecipheriv,createHmac,randomBytes,randomUUID} from "node:crypto";
import {mkdir,open,readFile,readdir,rename,stat,unlink} from "node:fs/promises";
import {join} from "node:path";
import {gzip,gunzip} from "node:zlib";
import {promisify} from "node:util";
import {jsonReply} from "./responses.mjs";

export const TTL_MS=4*60*60*1000;
export const REFRESH_AHEAD_MS=15*60*1000;
export const DEMAND_SECONDS=24*60*60;
export const MAX_ENTRY=6*1024*1024;
export const MAX_MKK_ENTRY=32*1024*1024;
const entryLimit=id=>id==="mkk-hyper"?MAX_MKK_ENTRY:MAX_ENTRY;
export const MAX_DISK=256*1024*1024;
const LEASE_MS=420_000,RETRY_SECONDS=300;
const pack=promisify(gzip),unpack=promisify(gunzip);
const PREFIX="spc8:catalog-cache:v1:";
const GLOBAL=PREFIX+"refresh";
const WRITE=PREFIX+"write";
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const safeId=id=>typeof id==="string"&&/^[a-z0-9-]{1,48}$/.test(id);
// Dedicated SSH-account catalogs remain excluded from shared caching.
const EXCLUDED=new Set(["opentunnel-ssh","speigo-vpn-ssh"]);
export const cacheable=id=>safeId(id)&&!EXCLUDED.has(id);
export const cacheEnabled=(env=process.env)=>env.CLOUD_SERVER_VPN_CACHE_ENABLED==="true";
const rootDefault=()=>process.env.CLOUD_SERVER_VPN_CACHE_ROOT||"/app/server-vpn-results";
const secretDefault=()=>process.env.CLOUD_SESSION_SIGNING_KEY||"";
const expiryError=()=>Object.assign(Error("SERVICE_UNAVAILABLE"),{code:"SERVICE_UNAVAILABLE"});
const demandKey=id=>PREFIX+"demand:"+id;
const lockKey=id=>PREFIX+"lock:"+id;
const backoffKey=id=>PREFIX+"retry:"+id;
const pathFor=(root,id)=>join(root,"catalog-"+id+".bin");
const derive=secret=>createHmac("sha256",secret).update("spdecode:server-vpn-results:v1").digest();
const aad=(id,revision)=>Buffer.from(JSON.stringify(["spdecode-catalog-result-v1",id,revision]));
const complete=(value)=>value?.status==="success"&&value.isPartial===false&&typeof value.rawText==="string"&&value.rawText.length>0;
// MKK is a fixed-source aggregate. Its worker contract already validates the
// full document; a successful partial must retain its explicit source warning.
function accepted(id,value){
 if(id!=="mkk-hyper")return complete(value);
 if(value?.status!=="success"||value.kind!=="vpn_catalog"||value.providerId!==id||
    typeof value.rawText!=="string"||!value.rawText.length)return false;
 const doc=value.structuredJson;
 if(doc?.provider!==id||doc.sourceCount!==4||!Array.isArray(doc.sources)||
    doc.sources.length!==4||
    doc.sources.some((s,i)=>s?.name!==["servers","static","subscriptions","legacy-subscriptions"][i]||
       !["ok","error"].includes(s.status)))return false;
 const good=doc.sources.filter(s=>s.status==="ok").length;
 if(good<1||doc.successfulSources!==good||doc.complete!==(good===4))return false;
 return good===4?value.isPartial===false:
   value.isPartial===true&&Array.isArray(value.warnings)&&value.warnings.includes("PARTIAL_SOURCE_FAILURE");
}
async function acquire(redis,key,ms=LEASE_MS){
 const token=randomUUID();
 return await redis.set(key,token,{NX:true,PX:ms})==="OK"?token:null;
}
async function release(redis,key,token){
 if(!token)return;
 await redis.eval("if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end",
  {keys:[key],arguments:[token]}).catch(()=>{});
}
async function readEntry({root,secret,id,revision,now}){
 try{
  const file=pathFor(root,id),info=await stat(file);
  if(!info.isFile()||info.size<29||info.size>entryLimit(id)+65536)return null;
  const bytes=await readFile(file);
  if(bytes.length<29||bytes.length>entryLimit(id)+65536)return null;
  const cipher=createDecipheriv("aes-256-gcm",derive(secret),bytes.subarray(0,12));
  cipher.setAAD(aad(id,revision));cipher.setAuthTag(bytes.subarray(12,28));
  const compressed=Buffer.concat([cipher.update(bytes.subarray(28)),cipher.final()]);
  const clear=await unpack(compressed,{maxOutputLength:entryLimit(id)});
  const item=JSON.parse(clear.toString("utf8"));
  if(!Number.isSafeInteger(item.createdAt)||item.createdAt>now()+5000||!accepted(id,item.result))return null;
  return item;
 }catch{return null;}
}
function current(item,now){return item&&now()-item.createdAt<TTL_MS;}
function reply(item){return jsonReply({...item.result,requestId:randomUUID()},200);}
async function writeEntry(redis,ctx,result,lockToken){
 // The original worker response is already validated by fetchWorker.
 if(!accepted(ctx.id,result)||await redis.get(lockKey(ctx.id))!==lockToken)return false;
 const safe={...result};delete safe.requestId;
 const clear=Buffer.from(JSON.stringify({createdAt:ctx.now(),result:safe}));
 if(clear.length>entryLimit(ctx.id))return false;
 const compressed=await pack(clear,{level:3});
 const nonce=randomBytes(12),cipher=createCipheriv("aes-256-gcm",derive(ctx.secret),nonce);
 cipher.setAAD(aad(ctx.id,ctx.revision));
 const encrypted=Buffer.concat([cipher.update(compressed),cipher.final()]);
 const bytes=Buffer.concat([nonce,cipher.getAuthTag(),encrypted]);
 const writer=await acquire(redis,WRITE,60_000);
 if(!writer)return false;
 let tmp;
 try{
  await mkdir(ctx.root,{recursive:true,mode:0o700});
  let total=0;
  const file=pathFor(ctx.root,ctx.id);
  for(const name of await readdir(ctx.root)){
   if(!/^catalog-[a-z0-9-]{1,48}\.bin$/.test(name)&&!/^\.tmp-[a-f0-9-]{36}$/.test(name))continue;
   const other=join(ctx.root,name);
   try{
    const info=await stat(other);
    if(other===file)continue;
    if(ctx.now()-info.mtimeMs>TTL_MS){await unlink(other).catch(()=>{});}
    else total+=info.size;
   }catch{}
  }
  if(total+bytes.length>MAX_DISK)return false;
  if(await redis.get(lockKey(ctx.id))!==lockToken||!await ctx.isCurrent())return false;
  tmp=join(ctx.root,".tmp-"+randomUUID());
  const out=await open(tmp,"wx",0o600);try{await out.writeFile(bytes);await out.sync();}finally{await out.close();}
  // Recheck provider revision/maintenance before atomic publication.
  if(await redis.get(lockKey(ctx.id))!==lockToken||!await ctx.isCurrent())return false;
  await rename(tmp,file);return true;
 }finally{if(tmp)await unlink(tmp).catch(()=>{});await release(redis,WRITE,writer);}
}
async function requestContext(redis,config){
 const {id,revision,load}=config;
 const ctx={id,revision,load,root:config.root??rootDefault(),secret:config.secret??secretDefault(),
  now:config.now??Date.now,isCurrent:config.isCurrent??(async()=>true)};
 if(!cacheable(id)||typeof revision!=="string"||ctx.secret.length<32)return null;
 return ctx;
}
/** On a miss only the Redis lease owner calls the worker. Hits never occupy worker slots. */
export async function sharedCatalog(redis,config){
 if(!(config.enabled??cacheEnabled())||!cacheable(config.id))return config.load();
 const ctx=await requestContext(redis,config);if(!ctx)return config.load();
 await redis.set(demandKey(ctx.id),"1",{EX:DEMAND_SECONDS});
 if(!await ctx.isCurrent())throw expiryError();
 const cached=await readEntry(ctx);
 if(current(cached,ctx.now))return reply(cached);
 if(await redis.get(backoffKey(ctx.id)))throw expiryError();
 const token=await acquire(redis,lockKey(ctx.id));
 if(!token){
  const begin=ctx.now(),wait=config.sleep??delay;
  // Bound total wait; never launch a duplicate if another request owns a miss.
  while(ctx.now()-begin<(config.waitMs??160_000)){
   await wait(1000);
   if(!await redis.get(lockKey(ctx.id)))break;
  }
  // Last look closes the race between publication and lock release.
  const item=await readEntry(ctx);if(current(item,ctx.now)&&await ctx.isCurrent())return reply(item);
  throw expiryError();
 }
 try{
  const item=await readEntry(ctx);
  if(!await ctx.isCurrent())throw expiryError();
  if(current(item,ctx.now))return reply(item);
  const response=await ctx.load();
  if(!await ctx.isCurrent())throw expiryError();
  if(response.ok){
   const result=await response.clone().json().catch(()=>null);
   if(accepted(ctx.id,result))await writeEntry(redis,ctx,result,token).catch(()=>false);
   else await redis.set(backoffKey(ctx.id),"1",{EX:RETRY_SECONDS});
  }else if(response.status!==429){
   await redis.set(backoffKey(ctx.id),"1",{EX:RETRY_SECONDS});
  }
  return response;
 }catch(error){if(error?.code!=="RATE_LIMITED")await redis.set(backoffKey(ctx.id),"1",{EX:RETRY_SECONDS}).catch(()=>{});throw error;}
 finally{await release(redis,lockKey(ctx.id),token);}
}
/** One background refresh at a time across processes; no cold-start bulk warming. */
export async function renewDemandedCatalog(redis,configs){
 if(!configs.length)return false;
 const global=await acquire(redis,GLOBAL);if(!global)return false;
 try{
  // Leave interactive work priority; the loader also obtains the normal global slot.
  await redis.zRemRangeByScore("spsec:active:global","-inf",Date.now()-300_000);
  if(await redis.zCard("spsec:active:global")>0)return false;
  for(const config of configs){
   if(!(config.enabled??cacheEnabled())||!cacheable(config.id))continue;
   const ctx=await requestContext(redis,config);if(!ctx)continue;
   if(!await redis.get(demandKey(ctx.id))||await redis.get(backoffKey(ctx.id)))continue;
   if(!await ctx.isCurrent())continue;
   // Do not decrypt every large catalog on every scheduler tick.
   let age=Infinity;
   try{age=ctx.now()-(await stat(pathFor(ctx.root,ctx.id))).mtimeMs;}catch{}
   if(age<TTL_MS-REFRESH_AHEAD_MS)continue;
   const token=await acquire(redis,lockKey(ctx.id));if(!token)continue;
   try{
    const old=await readEntry(ctx);
    if(old&&ctx.now()-old.createdAt<TTL_MS-REFRESH_AHEAD_MS)continue;
    if(!await ctx.isCurrent())continue;
    const response=await ctx.load();
    if(response.status!==429){
     const result=response.ok?await response.json().catch(()=>null):null;
     // Never degrade an unexpired complete MKK snapshot to a partial one.
     const downgrade=ctx.id==="mkk-hyper"&&current(old,ctx.now)&&old.result.isPartial===false&&result?.isPartial===true;
     if(downgrade||!accepted(ctx.id,result)||!await writeEntry(redis,ctx,result,token))
      await redis.set(backoffKey(ctx.id),"1",{EX:RETRY_SECONDS});
    }
    return true;
   }catch(error){if(error?.code!=="RATE_LIMITED")await redis.set(backoffKey(ctx.id),"1",{EX:RETRY_SECONDS}).catch(()=>{});return true;}
   finally{await release(redis,lockKey(ctx.id),token);}
  }
  return false;
 }finally{await release(redis,GLOBAL,global);}
}
