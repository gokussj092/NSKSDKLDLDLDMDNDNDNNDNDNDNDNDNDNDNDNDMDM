/** Persistent notices, separated from ephemeral Redis sessions and challenges.
 * Mounted /app/notice-feed is a dedicated Docker volume writable only by web.
 */
import {readFile,open,rename,unlink} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
const ROOT='/app/notice-feed',FILE='feed.json';
export async function readNoticeState({root=ROOT}={}) {
  let value;
  try{value=await readFile(join(root,FILE),'utf8');}
  catch(e){if(e?.code==='ENOENT')return [];throw e;}
  if(value.length>100000)throw Error('FEED_INVALID');
  const records=JSON.parse(value);
  if(!Array.isArray(records)||records.length>20)throw Error('FEED_INVALID');
  return records;
}
export async function writeNoticeState(records,{root=ROOT}={}) {
  if(!Array.isArray(records)||records.length>20)throw Error('FEED_INVALID');
  const payload=JSON.stringify(records);
  if(payload.length>100000)throw Error('FEED_INVALID');
  const path=join(root,FILE),temporary=join(root,'.feed-'+randomUUID());
  const out=await open(temporary,'wx',0o600);
  try{await out.writeFile(payload+'\n');await out.sync();}
  finally{await out.close();}
  try{await rename(temporary,path);}
  catch(e){await unlink(temporary).catch(()=>{});throw e;}
}
