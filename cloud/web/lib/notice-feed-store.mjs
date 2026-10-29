import {randomUUID} from 'node:crypto';
import {open,readFile,rename,unlink} from 'node:fs/promises';
import {join} from 'node:path';

// Public notice text only. Never store credentials or admin sessions here.
// The directory is a dedicated, persistent Docker volume, independent of Redis.
const ROOT='/app/notice-feed';
export async function readPersistedNotices(root=ROOT){
  let raw;
  try{raw=await readFile(join(root,'notices.json'),'utf8');}
  catch(error){if(error?.code==='ENOENT')return [];throw error;}
  if(raw.length>100000)throw Error('FEED_INVALID');
  const parsed=JSON.parse(raw);
  if(!Array.isArray(parsed)||parsed.length>20)throw Error('FEED_INVALID');
  return parsed;
}
export async function writePersistedNotices(items,root=ROOT){
  if(!Array.isArray(items)||items.length>20)throw Error('FEED_INVALID');
  const raw=JSON.stringify(items)+'\n';
  if(raw.length>100000)throw Error('FEED_INVALID');
  const tmp=join(root,'.notices-'+randomUUID());
  const file=await open(tmp,'wx',0o600);
  try{await file.writeFile(raw,'utf8');await file.sync();}
  finally{await file.close();}
  try{await rename(tmp,join(root,'notices.json'));}
  catch(error){await unlink(tmp).catch(()=>{});throw error;}
}
