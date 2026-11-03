/** Public metadata only; internal decoder routing stays server-side. */
import {readFileSync,existsSync} from 'node:fs';
import {join} from 'node:path';

const allowedKeys=['suffix','name','kind','offlineSupported','cloudSupported','credentialFields'];
const extraKeys=['targetAppId','name','banner'];
export const FORMAT_DETECTION=Object.freeze({rule:'longest-filename-suffix',caseInsensitive:true,separator:'.'});
let cache=null,sourceCache=null;
export function validatePublicFormats(parsed){
  if(!parsed || parsed.schemaVersion!==1 ||
     parsed.detection?.rule!=='longest-filename-suffix' ||
     parsed.detection.caseInsensitive!==true ||
     parsed.detection.separator!=='.' ||
     !Array.isArray(parsed.formats) ||
     parsed.formats.length<1 || parsed.formats.length>1024)
    throw Error('FORMATS_INVALID');
  if(parsed.unlockedRevision!==undefined &&
     (!Number.isSafeInteger(parsed.unlockedRevision)||parsed.unlockedRevision<1))
    throw Error('UNLOCKED_REVISION_INVALID');
  const seen=new Set(),exportIds=new Set();let hasUnlock=false;
  for(const entry of parsed.formats){
    if(!entry || Object.keys(entry).length!==allowedKeys.length+
         (entry.unlockedExport===undefined?0:1) ||
       Object.keys(entry).some(k=>!allowedKeys.includes(k)&&k!=='unlockedExport') ||
       typeof entry.suffix!=='string' ||
       !/^[\p{L}\p{N}_.-]{1,64}$/u.test(entry.suffix) ||
       entry.suffix!==entry.suffix.toLowerCase() ||
       seen.has(entry.suffix) ||
       typeof entry.name!=='string' || !entry.name.trim() || entry.name.length>120 ||
       entry.kind!=='file' ||
       typeof entry.offlineSupported!=='boolean' || entry.cloudSupported!==true ||
       !Array.isArray(entry.credentialFields) ||
       entry.credentialFields.length>3 ||
       new Set(entry.credentialFields).size!==entry.credentialFields.length ||
       entry.credentialFields.some(x=>!['password','hwid','publicKey','recipientKey'].includes(x)))
      throw Error('FORMATS_INVALID_ENTRY');
    if(entry.unlockedExport!==undefined){
      hasUnlock=true;
      const u=entry.unlockedExport;
      if(!u||typeof u!=='object'||Array.isArray(u)||
         Object.keys(u).length!==extraKeys.length||
         Object.keys(u).some(k=>!extraKeys.includes(k))||
         !/^[a-z0-9][a-z0-9_-]{0,15}$/.test(entry.suffix)||
         typeof u.targetAppId!=='string'||!/^[a-z0-9][a-z0-9-]{0,47}$/.test(u.targetAppId)||
         exportIds.has(u.targetAppId)||
         typeof u.name!=='string'||!u.name.trim()||u.name!==u.name.trim()||
         u.name.length>80||/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(u.name)||
         !['none','spdecode-html'].includes(u.banner))throw Error('UNLOCKED_ENTRY_INVALID');
      exportIds.add(u.targetAppId);
    }
    seen.add(entry.suffix);
  }
  if(hasUnlock && parsed.unlockedRevision===undefined)throw Error('UNLOCKED_REVISION_MISSING');
  const list=parsed.formats;
  for(let i=1;i<list.length;i++){
    const a=list[i-1].suffix,b=list[i].suffix;
    if(a.length<b.length || (a.length===b.length && a>=b))
      throw Error('FORMATS_ORDER_INVALID');
  }
  return list.map(({unlockedExport,...publicEntry})=>publicEntry);
}
function sourceCatalog(){
  if(sourceCache)return sourceCache;
  const deployed=join(process.cwd(),'content','file-formats.json');
  const source=existsSync(deployed)?deployed:new URL('../content/file-formats.json',import.meta.url);
  const data=readFileSync(source,'utf8');
  if(Buffer.byteLength(data,'utf8')>262144)throw Error('FORMATS_SIZE_LIMIT');
  const parsed=JSON.parse(data);
  cache=validatePublicFormats(parsed);
  sourceCache=parsed;
  return parsed;
}
export function publicFormats(){sourceCatalog();return cache;}
/** One existing catalog governs decryption formats and verified Unlocked metadata.
 * Legacy APK format objects are kept unchanged on the wire.
 */
export function fileFormatUnlockedExports(){
  const parsed=sourceCatalog();
  return {revision:parsed.unlockedRevision??0,
    formats:parsed.formats.filter(x=>x.unlockedExport!==undefined)
      .map(x=>({suffix:x.suffix,...x.unlockedExport}))};
}
