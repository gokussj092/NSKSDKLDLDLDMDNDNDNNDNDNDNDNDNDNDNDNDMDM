/** Durable notice-only volume. Redis remains ephemeral for security state. */
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {withFileLock,atomicJson} from './durable-json.mjs';
const ROOT='/app/notices',FILE='feed.json',EXPECTED='/app/notices/feed.json';
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const clean=(s,max)=>typeof s==='string'&&s.trim().length>0&&s===s.trim()&&s.length<=max&&!/[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(s);
export function validStoredNotice(n) {
 return n&&typeof n==='object'&&!Array.isArray(n)&&Object.keys(n).sort().join(',')==='body,createdAt,expiresAt,id,title'&&
  uuid.test(n.id)&&clean(n.title,80)&&clean(n.body,500)&&Number.isSafeInteger(n.createdAt)&&n.createdAt>0&&
  Number.isSafeInteger(n.expiresAt)&&n.expiresAt>n.createdAt&&n.expiresAt<=n.createdAt+7*86400000;
}
function validate(feed){
 if(!Array.isArray(feed)||feed.length>20||!feed.every(validStoredNotice)||new Set(feed.map(n=>n.id)).size!==feed.length)
  throw Error('NOTICE_STORE_INVALID');
 return feed;
}
export function noticeStorageEnabled(env=process.env) {
 const value=env.CLOUD_NOTICE_STORE_PATH;
 if(value===undefined||value===''){
  if(env.NODE_ENV==='production')throw Error('NOTICE_STORE_UNAVAILABLE');
  return false; // Legacy unit fixtures only; Compose always configures the durable volume.
 }
 if(value!==EXPECTED)throw Error('NOTICE_STORE_INVALID');return true;
}
export async function readStoredFeed({root=ROOT,env=process.env}={}) {
 if(!noticeStorageEnabled(env))return null;
 let raw;try{raw=await readFile(join(root,FILE),'utf8');}catch(e){if(e.code==='ENOENT')return null;throw e;}
 if(Buffer.byteLength(raw)>100000)throw Error('NOTICE_STORE_INVALID');
 try{return validate(JSON.parse(raw));}catch{throw Error('NOTICE_STORE_INVALID');}
}
export async function writeStoredFeed(feed,{root=ROOT,env=process.env}={}) {
 if(!noticeStorageEnabled(env))return false;
 validate(feed);
 await withFileLock(root,'notice-feed',()=>atomicJson(root,FILE,feed));return true;
}
/** Migration and append share one OS lock, including across Redis/process restarts. */
export async function transactStoredFeed(notice,{root=ROOT,env=process.env,legacy=async()=>[]}={}) {
 if(!noticeStorageEnabled(env))return null;
 if(notice&&!validStoredNotice(notice))throw Error('NOTICE_STORE_INVALID');
 return withFileLock(root,'notice-feed',async()=>{
  let feed=await readStoredFeed({root,env});const missing=feed===null;
  if(missing)feed=validate(await legacy());
  const now=Date.now();const active=feed.filter(n=>n.createdAt<=now+5000&&n.expiresAt>now);
  const duplicate=!!notice&&active.some(n=>n.id===notice.id);
  const next=notice&&!duplicate?[...active,notice].slice(-20):active;
  if(missing||notice&&!duplicate||active.length!==feed.length)await atomicJson(root,FILE,next);
  return {feed:next,duplicate};
 });
}
