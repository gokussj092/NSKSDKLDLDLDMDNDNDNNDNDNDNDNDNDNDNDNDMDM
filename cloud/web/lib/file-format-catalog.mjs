/** Public metadata only; internal decoder routing stays server-side. */
import {readFileSync} from 'node:fs';
import {join} from 'node:path';

const allowedKeys=['suffix','name','kind','offlineSupported','cloudSupported','credentialFields'];
export const FORMAT_DETECTION=Object.freeze({rule:'longest-filename-suffix',caseInsensitive:true,separator:'.'});
let cache=null;
export function validatePublicFormats(parsed){
  if(!parsed || parsed.schemaVersion!==1 ||
     parsed.detection?.rule!=='longest-filename-suffix' ||
     parsed.detection.caseInsensitive!==true ||
     parsed.detection.separator!=='.' ||
     !Array.isArray(parsed.formats) ||
     parsed.formats.length<1 || parsed.formats.length>1024)
    throw Error('FORMATS_INVALID');
  const seen=new Set();
  for(const entry of parsed.formats){
    if(!entry || Object.keys(entry).length!==allowedKeys.length ||
       Object.keys(entry).some(k=>!allowedKeys.includes(k)) ||
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
       entry.credentialFields.some(x=>!['password','hwid','publicKey'].includes(x)))
      throw Error('FORMATS_INVALID_ENTRY');
    seen.add(entry.suffix);
  }
  const list=parsed.formats;
  for(let i=1;i<list.length;i++){
    const a=list[i-1].suffix,b=list[i].suffix;
    if(a.length<b.length || (a.length===b.length && a>=b))
      throw Error('FORMATS_ORDER_INVALID');
  }
  return list;
}

export function publicFormats(){
  if(cache)return cache;
  const data=readFileSync(join(process.cwd(),'content','file-formats.json'),'utf8');
  if(Buffer.byteLength(data,'utf8')>262144)throw Error('FORMATS_SIZE_LIMIT');
  cache=validatePublicFormats(JSON.parse(data));
  return cache;
}
