import {createReadStream} from 'node:fs';
import {Readable} from 'node:stream';
import {stat} from 'node:fs/promises';
import {safe,reply,fail} from '../../../../../../lib/commerce/config.mjs';
import {requireAccount} from '../../../../../../lib/commerce/auth.mjs';
import {database} from '../../../../../../lib/commerce/db.mjs';
import {resultPath,verifyDownloadSignature,UUID_RE} from '../../../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Serves result.zip (scripts only). Two access paths, both bound to the
// owning account: a signed 24 h link (?exp&sig, HMAC) or a Bearer session.
// The signed link is what the app receives in the job view; it is never
// pasted into a support message.
export const GET=async(request,{params})=>safe(async()=>{
 const {jobId}=await params;
 if(!UUID_RE.test(jobId||''))fail('INVALID_REQUEST');
 const row=(await database().query(
   'SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[jobId])).rows[0];
 if(!row)fail('APP_ANALYSIS_JOB_NOT_FOUND',404);
 const url=new URL(request.url);
 const exp=Number(url.searchParams.get('exp')||'');
 const sig=url.searchParams.get('sig')||'';
 if(sig){
  if(!verifyDownloadSignature(jobId,row.account_id,exp,sig))fail('APP_ANALYSIS_DOWNLOAD_UNAUTHORIZED',401);
 }else{
  const session=await requireAccount(request);
  if(session.user.id!==row.account_id)fail('APP_ANALYSIS_ACCESS_DENIED',403);
 }
 if(row.status!=='COMPLETED'&&row.status!=='COMPLETED_PARTIAL')
  fail('APP_ANALYSIS_JOB_NOT_COMPLETED',409);
 if(new Date(row.expires_at).getTime()<=Date.now())fail('APP_ANALYSIS_JOB_EXPIRED',410);
 if(!row.result_sha256||!row.result_bytes)fail('APP_ANALYSIS_JOB_NOT_COMPLETED',409);
 const path=resultPath(jobId);
 let size;
 try{size=(await stat(path)).size;}catch{fail('APP_ANALYSIS_RESULT_UNAVAILABLE',503);}
 if(size!==Number(row.result_bytes))fail('APP_ANALYSIS_RESULT_UNAVAILABLE',503);
 const short=jobId.slice(0,8);
 const filename=((row.package_name||'app-analysis')+'-analysis-'+short+'.zip')
   .replace(/[^A-Za-z0-9_.-]/g,'_');
 return new Response(Readable.toWeb(createReadStream(path,{flags:'r'})),{headers:{
  'Content-Type':'application/zip',
  'Content-Disposition':'attachment; filename="'+filename+'"',
  'Content-Length':String(size),
  'Cache-Control':'private, no-store',
  'X-Content-Type-Options':'nosniff',
  'X-Result-SHA256':row.result_sha256,
 }});
});
