/** Persistent, time-limited V2 Play Integrity admission. Independent of V1 and V2 availability.
 * A disabled Play check is a TESTER beta window, not equivalent to verified Google Play.
 * Hardware app-signature attestation stays mandatory during this window.
 */
import {readFile,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {withFileLock,atomicJson} from './durable-json.mjs';
export const MAX_V2_BETA_MS=15*24*60*60*1000;
const ROOT=process.env.CLOUD_V2_POLICY_ROOT||'/app/provider-control';
const FILE='v2-play-integrity.json';
const initial=()=>({version:1,integrityRequired:true,betaUntil:0,revision:0});
function valid(p){
 if(!p||typeof p!=='object'||Array.isArray(p)||
    Object.keys(p).sort().join(',')!=='betaUntil,integrityRequired,revision,version'||
    p.version!==1||typeof p.integrityRequired!=='boolean'||
    !Number.isSafeInteger(p.revision)||p.revision<0||
    !Number.isSafeInteger(p.betaUntil)||p.betaUntil<0||
    (p.integrityRequired&&p.betaUntil!==0)||(!p.integrityRequired&&p.betaUntil===0))
   throw Error('V2_PLAY_POLICY_INVALID');
 return p;
}
async function read(root){
 let raw;
 try{raw=await readFile(join(root,FILE),'utf8');}
 catch(e){if(e.code==='ENOENT')return null;throw Error('V2_PLAY_POLICY_UNAVAILABLE');}
 if(Buffer.byteLength(raw)>1024)throw Error('V2_PLAY_POLICY_INVALID');
 try{return valid(JSON.parse(raw));}catch{throw Error('V2_PLAY_POLICY_INVALID');}
}
export async function loadV2PlayPolicy(options={}){
 const root=options.root||ROOT;
 try{if(!(await stat(root)).isDirectory())throw Error('NOT_DIRECTORY');}
 catch(e){
  if(e.code==='ENOENT'&&!options.root&&process.env.NODE_ENV!=='production')return initial();
  throw Error('V2_PLAY_POLICY_UNAVAILABLE');
 }
 const saved=await read(root);if(saved)return saved;
 return withFileLock(root,'v2-play-policy',async()=>{
  const current=await read(root);if(current)return current;
  const value=initial();await atomicJson(root,FILE,value);return value;
 });
}
export async function v2PlayPolicyStatus(options={}){
 const p=await loadV2PlayPolicy(options);
 const now=options.now??Date.now();
 const active=!p.integrityRequired&&p.betaUntil>now&&p.betaUntil<=now+MAX_V2_BETA_MS;
 return {integrityRequired:!active,betaUntil:active?new Date(p.betaUntil).toISOString():null,
   revision:p.revision};
}
export async function changeV2PlayPolicy(integrityRequired,expectedRevision,options={}){
 if(typeof integrityRequired!=='boolean'||
    !Number.isSafeInteger(expectedRevision)||expectedRevision<0)
  throw Error('V2_PLAY_POLICY_INVALID');
 const root=options.root||ROOT,now=options.now??Date.now();
 return withFileLock(root,'v2-play-policy',async()=>{
  const current=(await read(root))||initial();
  if(current.revision!==expectedRevision)throw Error('V2_PLAY_POLICY_CONFLICT');
  const next={version:1,integrityRequired,
    betaUntil:integrityRequired?0:now+MAX_V2_BETA_MS,revision:current.revision+1};
  await atomicJson(root,FILE,next);
  return {integrityRequired,betaUntil:integrityRequired?null:new Date(next.betaUntil).toISOString(),
    revision:next.revision};
 });
}
