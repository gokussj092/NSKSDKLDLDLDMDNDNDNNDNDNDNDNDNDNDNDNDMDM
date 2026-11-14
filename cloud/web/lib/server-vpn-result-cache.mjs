/** Private plain-JSON cache of authorized shared fixed-provider results. Never cache user input. */
import {randomUUID} from "node:crypto";
import {mkdir,open,readFile,readdir,rename,stat,unlink} from "node:fs/promises";
import {join} from "node:path";
import {jsonReply} from "./responses.mjs";

export const TTL_MS=4*60*60*1000;
export const REFRESH_AHEAD_MS=15*60*1000;
export const DEMAND_SECONDS=24*60*60;
export const MAX_ENTRY=6*1024*1024;
export const MAX_MKK_ENTRY=32*1024*1024;
const entryLimit=id=>id==="mkk-hyper"?MAX_MKK_ENTRY:MAX_ENTRY;
export const MAX_DISK=256*1024*1024;
const LEASE_MS=420_000,RETRY_SECONDS=300;
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
const expiryError=()=>Object.assign(Error("SERVICE_UNAVAILABLE"),{code:"SERVICE_UNAVAILABLE"});
const demandKey=id=>PREFIX+"demand:"+id;
const lockKey=id=>PREFIX+"lock:"+id;
const backoffKey=id=>PREFIX+"retry:"+id;
const pathFor=(root,id)=>join(root,"catalog-"+id+".json");
const SCHEMA=2;
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
async function readEntry({root,id,revision,now}){
 try{
  const file=pathFor(root,id),info=await stat(file);
  if(!info.isFile()||(info.mode&0o077)!==0||info.size<2||info.size>entryLimit(id))return null;
  const bytes=await readFile(file);
  if(bytes.length<2||bytes.length>entryLimit(id))return null;
  const item=JSON.parse(bytes.toString("utf8"));
  if(item?.schema!==SCHEMA||item.id!==id||item.revision!==revision||
     !Number.isSafeInteger(item.createdAt)||item.createdAt>now()+5000||
     !accepted(id,item.result))return null;
  return item;
 }catch{return null;}
}
function current(item,now){return item&&now()-item.createdAt<TTL_MS;}
function reply(item){return jsonReply({...item.result,requestId:randomUUID()},200);}
async function writeEntry(redis,ctx,result,lockToken){
 // The original worker response is already validated by fetchWorker.
 if(!accepted(ctx.id,result)||await redis.get(lockKey(ctx.id))!==lockToken)return false;
 const safe={...result};delete safe.requestId;
 const bytes=Buffer.from(JSON.stringify({schema:SCHEMA,id:ctx.id,revision:ctx.revision,createdAt:ctx.now(),result:safe}));
 if(bytes.length>entryLimit(ctx.id))return false;
 const writer=await acquire(redis,WRITE,60_000);
 if(!writer)return false;
 let tmp;
 try{
  await mkdir(ctx.root,{recursive:true,mode:0o700});
  let total=0;
  const file=pathFor(ctx.root,ctx.id);
  for(const name of await readdir(ctx.root)){
   const legacy=/^catalog-[a-z0-9-]{1,48}\.bin$/.test(name);
   if(!legacy&&!/^catalog-[a-z0-9-]{1,48}\.json$/.test(name)&&!/^\.tmp-[a-f0-9-]{36}$/.test(name))continue;
   const other=join(ctx.root,name);
   try{
    const info=await stat(other);
    if(other===file)continue;
    // Old encrypted entries are disposable; do not decrypt/migrate them.
    if(legacy||ctx.now()-info.mtimeMs>TTL_MS){
     try{await unlink(other);}catch{total+=info.size;}
    }else total+=info.size;
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
 const ctx={id,revision,load,root:config.root??rootDefault(),
  now:config.now??Date.now,isCurrent:config.isCurrent??(async()=>true)};
 if(!cacheable(id)||typeof revision!=="string"||!revision)return null;
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
   // Do not parse every large catalog on every scheduler tick.
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
