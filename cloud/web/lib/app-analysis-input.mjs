/** Read-only input delivery for the analysis bot; never a user login or credit mutation. */
import {createHmac,timingSafeEqual} from 'node:crypto';
import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {database} from './commerce/db.mjs';
import {fail,reply,safe} from './commerce/config.mjs';
import {MAX_APK_BYTES,UUID_RE,settings,verifyBotToken} from './app-analysis.mjs';

export const INPUT_LINK_TTL_SECONDS=15*60;
const READY=new Set(['QUEUED_FOR_ANALYSIS','ANALYZING','AWAITING_HUMAN',
 'COMPLETED','COMPLETED_PARTIAL']);
const HEX64=/^[a-f0-9]{64}$/;
const NO_STORE={'Cache-Control':'private, no-store, max-age=0',
 'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
 'X-Robots-Tag':'noindex, nofollow'};
const same=(a,b)=>{
 const x=Buffer.from(a),y=Buffer.from(b);
 return x.length===y.length&&timingSafeEqual(x,y);
};
function apiOrigin(env){
 // The API host already proxies this prefix. The public site's V2 routes
 // are deliberately restricted; never derive a bearer link from Host.
 const raw=env.CLOUD_API_PUBLIC_ORIGIN||'https://api.spdecode.xyz';
 let url;try{url=new URL(raw);}catch{fail('APP_ANALYSIS_INPUT_LINK_NOT_CONFIGURED',503);}
 if(url.origin!==raw||url.username||url.password||
    (url.protocol!=='https:'&&!(env.NODE_ENV!=='production'&&
      url.protocol==='http:'&&url.hostname==='localhost')))
  fail('APP_ANALYSIS_INPUT_LINK_NOT_CONFIGURED',503);
 return raw;
}
function mac(row,exp,env){
 const key=settings(env).downloadSecret;
 if(key.length<32)fail('APP_ANALYSIS_DOWNLOAD_NOT_CONFIGURED',503);
 // Domain separation prevents replay of a finished-result download link.
 return createHmac('sha256',key).update(JSON.stringify([
  'spdecode-app-analysis-input-v1',row.job_id,row.account_id,
  row.input_sha256,Number(row.input_bytes),exp])).digest('hex');
}
function ready(row){
 const expires=new Date(row.expires_at).getTime();
 if(row.status==='EXPIRED'||!Number.isFinite(expires)||expires<=Date.now())
  fail('APP_ANALYSIS_JOB_EXPIRED',410);
 const size=Number(row.input_bytes);
 if(!READY.has(row.status)||!Number.isSafeInteger(size)||size<1||
    size>MAX_APK_BYTES||Number(row.received_bytes)!==size||!HEX64.test(row.input_sha256||''))
  fail('APP_ANALYSIS_INPUT_NOT_READY',409);
}
async function job(db,id){
 if(!UUID_RE.test(id||''))fail('INVALID_REQUEST');
 return (await db.query('SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[id])).rows[0];
}
function inputLink(row,env){
 ready(row);
 const exp=Math.min(Math.floor(Date.now()/1000)+INPUT_LINK_TTL_SECONDS,
   Math.floor(new Date(row.expires_at).getTime()/1000));
 if(exp<=Math.floor(Date.now()/1000))fail('APP_ANALYSIS_JOB_EXPIRED',410);
 const sig=mac(row,exp,env);
 return {jobId:row.job_id,filename:row.filename,packageName:row.package_name,
  appName:row.app_name,bytes:Number(row.input_bytes),sha256:row.input_sha256,
  inputDownloadUrl:apiOrigin(env)+'/api/v2/app-analysis/'+row.job_id+
    '/input?exp='+exp+'&sig='+sig,
  expiresAt:new Date(exp*1000).toISOString()};
}
function validSignature(row,exp,sig,env){
 const now=Math.floor(Date.now()/1000);
 if(!Number.isSafeInteger(exp)||exp<=now||exp>now+INPUT_LINK_TTL_SECONDS+30||
    !HEX64.test(sig||''))return false;
 try{return same(sig,mac(row,exp,env));}catch{return false;}
}

/** Bot API: renew a single-job capability, including jobs queued before deployment. */
export const inputLinkRequest=(request,jobId,{db,env=process.env}={})=>safe(async()=>{
 verifyBotToken(request,env);
 const row=await job(db||database(),jobId);
 if(!row)fail('APP_ANALYSIS_JOB_NOT_FOUND',404);
 return reply(inputLink(row,env));
});

/** Private queue detail; the existing anonymous queue-status count stays unchanged. */
export const inputQueueRequest=(request,{db,env=process.env}={})=>safe(async()=>{
 verifyBotToken(request,env);
 const rows=(await (db||database()).query(`SELECT * FROM spdecode_shop.app_analysis_jobs
  WHERE status IN ('QUEUED_FOR_ANALYSIS','ANALYZING','AWAITING_HUMAN')
    AND expires_at>now() AND received_bytes=input_bytes
  ORDER BY created_at ASC,job_id ASC LIMIT 50`)).rows;
 return reply({jobs:rows.map(row=>({...inputLink(row,env),status:row.status}))});
});

/** One byte range only; suffix/open-ended requests support resumable APK downloads. */
export function inputRange(value,size){
 if(value===null)return null;
 const m=value.length<=120&&/^bytes=(\d*)-(\d*)$/i.exec(value);
 if(!m||(!m[1]&&!m[2]))return false;
 let start,end;
 if(!m[1]){
  const suffix=Number(m[2]);
  if(!Number.isSafeInteger(suffix)||suffix<1)return false;
  start=Math.max(0,size-suffix);end=size-1;
 }else{
  start=Number(m[1]);end=m[2]?Number(m[2]):size-1;
  if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start>=size||end<start)return false;
  end=Math.min(end,size-1);
 }
 return {start,end};
}

/** GET/HEAD with a bot token OR a purpose-bound, 15-minute link; no account session. */
export const inputDownloadRequest=(request,jobId,{db,env=process.env,root}={})=>safe(async()=>{
 const url=new URL(request.url),signed=url.searchParams.has('sig');
 const sig=url.searchParams.get('sig')||'',expText=url.searchParams.get('exp')||'';
 const unauthorized=()=>fail('APP_ANALYSIS_INPUT_UNAUTHORIZED',401);
 if(signed){
  if(!HEX64.test(sig)||!/^\d{10,11}$/.test(expText))unauthorized();
 }else verifyBotToken(request,env);
 const row=await job(db||database(),jobId);
 if(!row){if(signed)unauthorized();fail('APP_ANALYSIS_JOB_NOT_FOUND',404);}
 if(signed&&!validSignature(row,Number(expText),sig,env))unauthorized();
 ready(row);
 let file;
 try{
  try{file=await open(join(root||settings(env).root,jobId,'input.apk'),
    constants.O_RDONLY|constants.O_NOFOLLOW);}
  catch{fail('APP_ANALYSIS_INPUT_UNAVAILABLE',503);}
  const info=await file.stat(),size=Number(row.input_bytes);
  if(!info.isFile()||info.size!==size)fail('APP_ANALYSIS_INPUT_UNAVAILABLE',503);
  const etag='"sha256-'+row.input_sha256+'"';
  const range=inputRange(request.headers.has('if-range')&&request.headers.get('if-range')!==etag
    ?null:request.headers.get('range'),size);
  if(range===false)return Response.json({error:{code:'INVALID_RANGE'}},{status:416,
    headers:{...NO_STORE,'Content-Range':'bytes */'+size,'Accept-Ranges':'bytes'}});
  const filename=(row.filename||'application.apk').replace(/[^A-Za-z0-9_. -]/g,'_').slice(0,128);
  const headers={...NO_STORE,'Content-Type':filename.endsWith('.apks')
    ?'application/zip':'application/vnd.android.package-archive',
   'Content-Disposition':'attachment; filename="'+filename+'"','Accept-Ranges':'bytes',
   'Content-Length':String(range?range.end-range.start+1:size),
   'X-Input-SHA256':row.input_sha256,'ETag':etag};
  if(range)headers['Content-Range']='bytes '+range.start+'-'+range.end+'/'+size;
  if(request.method==='HEAD')return new Response(null,{status:range?206:200,headers});
  const stream=file.createReadStream({...range,autoClose:true});file=null;
  return new Response(Readable.toWeb(stream),{status:range?206:200,headers});
 }finally{if(file)await file.close();}
});
