/** Durable V1 policy stored separately from ephemeral Redis security state. */
import {open,readFile,rename,unlink} from "node:fs/promises";
import {join} from "node:path";
import {randomUUID} from "node:crypto";
const ROOT="/app/provider-control",FILE="v1-protection.json",LOCK="v1-protection.lock";
export async function loadV1Protection({root=ROOT}={}){
 let raw;try{raw=await readFile(join(root,FILE),"utf8");}
 catch(e){if(e?.code==="ENOENT")return {version:1,enabled:false};throw e;}
 if(raw.length>256)throw Error("V1_POLICY_INVALID");
 let v;try{v=JSON.parse(raw);}catch{throw Error("V1_POLICY_INVALID");}
 if(!v||typeof v!=="object"||Array.isArray(v)||Object.keys(v).sort().join(",")!=="enabled,version"||
   v.version!==1||typeof v.enabled!=="boolean")throw Error("V1_POLICY_INVALID");
 return v;
}
export async function v1ProtectionRequired(env=process.env,{root=ROOT}={}){
 return env.CLOUD_V1_REQUIRE_BOUND_SESSION==="true" || (await loadV1Protection({root})).enabled;
}
export async function v1ProtectionStatus(env=process.env,{root=ROOT}={}){
 return {enabled:await v1ProtectionRequired(env,{root}),locked:env.CLOUD_V1_REQUIRE_BOUND_SESSION==="true"};
}
export async function setV1Protection(enabled,{root=ROOT,env=process.env}={}){
 if(typeof enabled!=="boolean")throw Error("V1_POLICY_INVALID");
 if(!enabled&&env.CLOUD_V1_REQUIRE_BOUND_SESSION==="true")throw Error("V1_POLICY_LOCKED");
 const lockPath=join(root,LOCK);let lock;
 for(let i=0;i<15;i++){
  try{lock=await open(lockPath,"wx",0o600);break;}
  catch(e){if(e?.code!=="EEXIST")throw e;await new Promise(resolve=>setTimeout(resolve,100));}
 }
 if(!lock)throw Error("V1_POLICY_BUSY");
 let tmp=null;
 try{
  const previous=await loadV1Protection({root});
  if(previous.enabled!==enabled){
   tmp=join(root,".v1-protection-"+randomUUID());
   const file=await open(tmp,"wx",0o600);
   try{await file.writeFile(JSON.stringify({version:1,enabled})+"\n");await file.sync();}
   finally{await file.close();}
   await rename(tmp,join(root,FILE));tmp=null;
   const dir=await open(root,"r");try{await dir.sync();}finally{await dir.close();}
  }
  return v1ProtectionStatus(env,{root});
 }finally{
  if(tmp)await unlink(tmp).catch(()=>{});
  await lock.close();await unlink(lockPath).catch(()=>{});
 }
}
