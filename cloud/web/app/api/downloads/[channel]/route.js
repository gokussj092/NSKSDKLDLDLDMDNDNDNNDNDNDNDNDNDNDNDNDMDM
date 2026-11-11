import {createReadStream} from 'node:fs';
import {open,readFile} from 'node:fs/promises';
import {Readable} from 'node:stream';
import {join,realpath} from 'node:path';
import {stat} from 'node:fs/promises';

export const runtime='nodejs';
export const dynamic='force-dynamic';
const ROOT='/app/public-apks';
const CHANNELS=new Set(['online','offline']);
const json=(body,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'public, max-age=60','X-Content-Type-Options':'nosniff'}});
function channel(params){const key=params?.channel;return typeof key==='string'&&CHANNELS.has(key)?key:null;}
async function verified(key){
 const releaseRoot=await realpath(join(ROOT,key,'current'));
 if(!releaseRoot.startsWith(join(ROOT,key,'slots')+'/'))return null;
 const prefix=join(releaseRoot,'release');
 const raw=JSON.parse(await readFile(prefix+'.json','utf8'));
 if(!raw||raw.channel!==key||!/^[0-9a-f]{64}$/.test(raw.sha256||'')||
    !/^\d+\.\d+\.\d+$/.test(raw.version||'')||
    !Number.isInteger(raw.versionCode)||raw.versionCode<1||
    !Number.isSafeInteger(raw.bytes)||raw.bytes<100000)return null;
 const fp=prefix+'.apk';
 const file=await open(fp,'r');
 try{
  const details=await file.stat();
  if(!details.isFile()||details.size!==raw.bytes)return null;
  return {raw,file,details,releaseRoot};
 }finally{await file.close();}
}
export async function GET(request,{params}){
 const key=channel(await params);
 if(!key)return json({error:'NOT_FOUND'},404);
 const metadata=request.nextUrl.searchParams.has('metadata');
 let result;
 try{result=await verified(key);}catch{return json({available:false,channel:key},404);}
 if(!result)return json({available:false,channel:key},404);
 const {raw,details,releaseRoot}=result;
 if(metadata)return json({available:true,channel:key,version:raw.version,versionCode:raw.versionCode,sha256:raw.sha256,bytes:raw.bytes,publishedAt:raw.publishedAt,packageName:raw.packageName,sourceCommit:raw.sourceCommit});
 // Only two hardcoded files inside the read-only APK mount. No path traversal,
 // no arbitrary file names, no directory listing and no secrets.
 const filePath=join(releaseRoot,'release.apk');
 const body=Readable.toWeb(createReadStream(filePath,{flags:'r'}));
 return new Response(body,{headers:{
  'Content-Type':'application/vnd.android.package-archive',
  'Content-Disposition':`attachment; filename="SP-DECODE-${key}-v${raw.version}.apk"`,
  'Content-Length':String(details.size),
  'Cache-Control':'public, max-age=60, must-revalidate',
  'X-Content-Type-Options':'nosniff',
  'X-APK-SHA256':raw.sha256,
 }});
}
