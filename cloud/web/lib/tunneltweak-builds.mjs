/** Persistent public-client build history. Never retain catalogs or API keys. */
import {readFileSync,constants} from "node:fs";
import {open,mkdir,rename,unlink,stat} from "node:fs/promises";
import {dirname} from "node:path";
import {randomUUID} from "node:crypto";

const SEED=JSON.parse(readFileSync(new URL("../content/tunneltweak-builds.seed.json",import.meta.url),"utf8"));
const MAX_STATE=1024*1024,MAX_BUILD=2147483647;
export const TUNNELTWEAK_INITIAL_BUILD=SEED.auto.build;
export const tunneltweakStatePath=()=>process.env.CLOUD_TUNNELTWEAK_BUILD_STATE_PATH||"/app/provider-control/tunneltweak-builds.json";
const validBuild=n=>Number.isSafeInteger(n)&&n>0&&n<=MAX_BUILD;
const fresh=()=>structuredClone(SEED);
export function validateBuildState(s){
  if(!s||s.schemaVersion!==1||s.provider!=="tunneltweak"||s.auto?.enabled!==true||!validBuild(s.auto.build)||
     !Array.isArray(s.builds)||s.builds.length>4096)throw Error("BUILD_STATE_INVALID");
  const seen=new Set();
  for(const r of s.builds){
    if(!r||!validBuild(r.build)||seen.has(r.build)||![true,false,null].includes(r.working)||
       !Number.isSafeInteger(r.checks)||r.checks<0||!Number.isSafeInteger(r.successes)||r.successes<0||r.successes>r.checks||
       !(r.lastHttpStatus===null||Number.isInteger(r.lastHttpStatus)&&r.lastHttpStatus>=100&&r.lastHttpStatus<=599)||
       !(r.lastCheckedAt===null||typeof r.lastCheckedAt==="string"&&/^\d{4}-\d{2}-\d{2}(?:T[\d:.]+Z)?$/.test(r.lastCheckedAt))||
       !["NOT_TRIED","DOWNLOAD_OK","UPDATE_REQUIRED","TEMPORARY_FAILURE","RESPONSE_INVALID"].includes(r.lastCode)||
       Object.keys(r).sort().join(",")!=="build,checks,lastCheckedAt,lastCode,lastHttpStatus,successes,working")
      throw Error("BUILD_STATE_INVALID");
    seen.add(r.build);
  }
  if(!seen.has(s.auto.build)||Object.keys(s.auto).sort().join(",")!=="build,enabled"||
     Object.keys(s).sort().join(",")!=="auto,builds,provider,schemaVersion")throw Error("BUILD_STATE_INVALID");
  return s;
}
async function load(path){
  let file;
  try{
    file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);
    const info=await file.stat();if(!info.isFile()||info.size>MAX_STATE)throw Error("BUILD_STATE_INVALID");
    return validateBuildState(JSON.parse(await file.readFile("utf8")));
  }catch(error){if(error.code!=="ENOENT")console.warn("[tunneltweak] BUILD_STATE_UNAVAILABLE");return fresh();}
  finally{await file?.close();}
}
const empty=build=>({build,working:null,checks:0,successes:0,lastCheckedAt:null,lastHttpStatus:null,lastCode:"NOT_TRIED"});
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function record(path,build,status,code,next){
  await mkdir(dirname(path),{recursive:true,mode:0o700});
  const lock=path+".lock";let fd;
  for(let n=0;n<100;n++){
    try{fd=await open(lock,"wx",0o600);break;}
    catch(e){
      if(e.code!=="EEXIST")throw e;
      try{if(Date.now()-(await stat(lock)).mtimeMs>60000)await unlink(lock);}catch{}
      await pause(20);
    }
  }
  if(!fd)throw Error("BUILD_STATE_BUSY");
  const temporary=path+"."+randomUUID()+".tmp";
  try{
    const s=await load(path);let row=s.builds.find(x=>x.build===build);
    if(!row){row=empty(build);s.builds.push(row);}
    row.checks++;row.lastCheckedAt=new Date().toISOString();row.lastHttpStatus=status;row.lastCode=code;
    if(code==="DOWNLOAD_OK"){row.working=true;row.successes++;s.auto.build=Math.max(s.auto.build,build);}
    if(code==="UPDATE_REQUIRED")row.working=false;
    if(next){if(!s.builds.some(x=>x.build===next))s.builds.push(empty(next));s.auto.build=Math.max(s.auto.build,next);}
    s.builds.sort((a,b)=>a.build-b.build);validateBuildState(s);
    const encoded=JSON.stringify(s,null,2)+"\n";
    if(Buffer.byteLength(encoded)>MAX_STATE)throw Error("BUILD_STATE_LIMIT");
    const out=await open(temporary,"wx",0o600);
    try{await out.writeFile(encoded);await out.sync();}finally{await out.close();}
    await rename(temporary,path);
  }finally{
    await unlink(temporary).catch(()=>{});await fd.close();await unlink(lock).catch(()=>{});
  }
}
function updateDocument(data){
  if(!Buffer.isBuffer(data)||data.length>65536)return null;
  let d;try{d=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(data));}catch{return null;}
  if(!d||d.status!=="update_required")return null;
  return d;
}
export function nextTunneltweakBuild(data,current){
  const d=updateDocument(data);if(!d)return null;
  if(Object.hasOwn(d,"minVersionCode"))return validBuild(d.minVersionCode)&&d.minVersionCode>current?d.minVersionCode:null;
  return current<MAX_BUILD?current+1:null;
}
export function validTunneltweakDownload(data){
  if(!Buffer.isBuffer(data)||!data.length||data.length>8*1024*1024)return false;
  let d;try{d=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(data));}catch{return false;}
  if(!d||Array.isArray(d)||d.success===false||d.status==="error"||d.status==="update_required")return false;
  if(typeof d.data==="string"){
    const b=d.data.replace(/\s/g,"");
    return b.length>=60&&b.length%4===0&&/^[A-Za-z0-9+/]+={0,2}$/.test(b);
  }
  return Array.isArray(d.servers)&&d.servers.length>0&&Array.isArray(d.configs);
}
const active=new Map();
export function resolveTunneltweakCatalog(request,{statePath=tunneltweakStatePath()}={}){
  // Coalesce only the fixed public catalog, never keyed/private subscriptions.
  if(active.has(statePath))return active.get(statePath);
  const pending=(async()=>{
    let build=(await load(statePath)).auto.build;
    const save=async(status,code,next)=>{try{await record(statePath,build,status,code,next);}catch{console.warn("[tunneltweak] BUILD_STATE_SAVE_FAILED");}};
    for(let attempt=0;attempt<3;attempt++){
      let answer;
      try{answer=await request(build);}catch(error){await save(Number.isInteger(error.httpStatus)?error.httpStatus:null,"TEMPORARY_FAILURE");throw error;}
      const status=answer.status??200;
      if(status===200){
        if(!validTunneltweakDownload(answer.data)){await save(status,"RESPONSE_INVALID");throw Error("REMOTE_RESPONSE_INVALID");}
        await save(status,"DOWNLOAD_OK");return answer.data;
      }
      if(status!==426){await save(status,"TEMPORARY_FAILURE");throw Error("REMOTE_PROVIDER_UNAVAILABLE");}
      if(!updateDocument(answer.data)){await save(status,"RESPONSE_INVALID");throw Error("REMOTE_RESPONSE_INVALID");}
      const next=nextTunneltweakBuild(answer.data,build);
      await save(status,"UPDATE_REQUIRED",next);
      if(next===null||attempt===2)throw Error("REMOTE_PROVIDER_UNAVAILABLE");
      build=next;
    }
  })().finally(()=>active.delete(statePath));
  active.set(statePath,pending);return pending;
}
