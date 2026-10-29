/** Durable, bounded application notice feed. Authentication state stays in ephemeral Redis.
 * The path is fixed by Compose, never supplied by a request.
 */
import {open,readFile,rename,unlink} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';

const ROOT='/app/notices',FILENAME='feed.json',EXPECTED='/app/notices/feed.json';
export function noticeStorageEnabled(env=process.env){
 const value=env.CLOUD_NOTICE_STORE_PATH;
 if(value===undefined||value==='')return false; // Unit tests and legacy servers.
 if(value!==EXPECTED)throw Error('NOTICE_STORE_INVALID');
 return true;
}
export async function readStoredFeed({root=ROOT,env=process.env}={}){
 if(!noticeStorageEnabled(env))return null;
 let raw;
 try{raw=await readFile(join(root,FILENAME),'utf8');}
 catch(e){if(e?.code==='ENOENT')return null;throw e;}
 if(raw.length>100000)throw Error('NOTICE_STORE_INVALID');
 let feed;try{feed=JSON.parse(raw);}catch{throw Error('NOTICE_STORE_INVALID');}
 if(!Array.isArray(feed)||feed.length>20)throw Error('NOTICE_STORE_INVALID');
 return feed;
}
export async function writeStoredFeed(feed,{root=ROOT,env=process.env}={}){
 if(!noticeStorageEnabled(env))return false;
 if(!Array.isArray(feed)||feed.length>20)throw Error('NOTICE_STORE_INVALID');
 const json=JSON.stringify(feed);
 if(json.length>100000)throw Error('NOTICE_STORE_INVALID');
 const tmp=join(root,'.feed-'+randomUUID());
 let created=false;
 try{
  const handle=await open(tmp,'wx',0o600);created=true;
  try{await handle.writeFile(json+'\n','utf8');await handle.sync();}
  finally{await handle.close();}
  await rename(tmp,join(root,FILENAME));created=false;
  const dir=await open(root,'r');try{await dir.sync();}finally{await dir.close();}
  return true;
 }finally{
  if(created)await unlink(tmp).catch(()=>{});
 }
}
