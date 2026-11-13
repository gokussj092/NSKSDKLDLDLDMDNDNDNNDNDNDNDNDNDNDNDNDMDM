/**
 * Commercial APK analysis gateway. Device HPKE/PoP/Integrity remains mandatory
 * but does not replace an authenticated, extant commercial account or credit.
 */
import {createHash} from 'node:crypto';
import {boundRequestClaims} from './v2-bound-request.mjs';
import {jsonReply} from './responses.mjs';
import {database,transaction} from './commerce/db.mjs';
import {accountAuth} from './commerce/auth.mjs';
import {creditBalance,reserveCredit,completeCredit,releaseCredit} from './commerce/credits.mjs';
import {ShopError,fail} from './commerce/config.mjs';
const METHODS=Object.freeze({21:'start',22:'chunk',23:'finish',24:'result'});
const MAX_BODY=3*1024*1024,MAX_RESULT=2*1024*1024;
const reply=(code,status)=>jsonReply({error:{code}},status);
const HEX=/^[a-f0-9]{32}$/;
const jobId=value=>{
 if(typeof value!=='string'||!HEX.test(value))fail('APK_QA_JOB_INVALID');
 return value.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
};
function settings(env=process.env){
 const key=env.CLOUD_APK_QA_INTERNAL_TOKEN||'';
 return {enabled:env.CLOUD_APK_QA_ENABLED==='true'&&
   env.SPDECODE_ANALYSIS_CREDITS_READY==='true'&&key.length>=32,
   key,endpoint:'http://apk-qa:8792'};
}
async function readJSON(request,limit){
 if(request.headers.get('content-type')?.split(';')[0]?.trim()!=='application/json'||
    !request.body||request.headers.has('content-encoding'))throw Error('INVALID_REQUEST');
 const length=Number(request.headers.get('content-length'));
 if(Number.isFinite(length)&&length>limit)throw Error('INPUT_TOO_LARGE');
 const reader=request.body.getReader(),chunks=[];let size=0;
 try{for(;;){
   const {done,value}=await reader.read();if(done)break;
   size+=value.length;if(size>limit){await reader.cancel();throw Error('INPUT_TOO_LARGE');}
   chunks.push(value);
 }}finally{reader.releaseLock();}
 const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
 if(!data||typeof data!=='object'||Array.isArray(data))throw Error('INVALID_REQUEST');
 return data;
}
export async function verifyApkAccount(token){
 if(typeof token!=='string'||token.length<24||token.length>1024||/\s/.test(token))
   fail('SIGN_IN_REQUIRED',401);
 const auth=accountAuth();
 const session=await auth.api.getSession({headers:new Headers({authorization:'Bearer '+token})});
 if(!session?.user?.id||!session.user.emailVerified)fail('SIGN_IN_REQUIRED',401);
 const row=await database().query('SELECT id FROM shop_user WHERE id=$1',[session.user.id]);
 if(!row.rowCount)fail('SIGN_IN_REQUIRED',401);
 return session.user.id;
}
async function preflight(accountId){
 const db=database(),row=await db.query('SELECT id FROM shop_user WHERE id=$1',[accountId]);
 if(!row.rowCount)fail('SIGN_IN_REQUIRED',401);
 const credits=await creditBalance(accountId);
 if(credits.available<1)fail('INSUFFICIENT_CREDITS',402);
}
async function bindJob(accountId,hash,hex){
 const id=jobId(hex),db=database(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true';
 await reserveCredit(accountId,id);
 try{
  await transaction(async client=>{
   const exists=(await client.query('SELECT * FROM spdecode_shop.apk_qa_jobs WHERE job_id=$1 FOR UPDATE',[id])).rows[0];
   if(exists){
    if(exists.account_id!==accountId||exists.device_key_hash!==hash||
      exists.payment_live!==live)fail('APK_QA_ACCESS_DENIED',403);
    return;
   }
   await client.query(`INSERT INTO spdecode_shop.apk_qa_jobs
    (job_id,account_id,device_key_hash,payment_live) VALUES($1,$2,$3,$4)`,
    [id,accountId,hash,live]);
  },db);
 }catch(e){
  await releaseCredit(accountId,id).catch(()=>{});
  throw e;
 }
}
async function authorizeJob(accountId,hash,hex){
 const id=jobId(hex),db=database(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true';
 const row=(await db.query(`SELECT j.state,r.state AS reservation
   FROM spdecode_shop.apk_qa_jobs j
   JOIN spdecode_shop.credit_reservations r ON r.job_id=j.job_id
   WHERE j.job_id=$1 AND j.account_id=$2 AND j.device_key_hash=$3
     AND j.payment_live=$4 AND r.account_id=$2 AND r.payment_live=$4`,
   [id,accountId,hash,live])).rows[0];
 if(!row||row.state==='released'||!['held','completed'].includes(row.reservation))
   fail('APK_QA_ACCESS_DENIED',403);
}
async function settleJob(accountId,hex,state){
 const id=jobId(hex),db=database();
 if(state==='COMPLETED'){
  await completeCredit(accountId,id);
  await db.query(`UPDATE spdecode_shop.apk_qa_jobs SET state='completed',updated_at=now()
    WHERE job_id=$1 AND account_id=$2`,[id,accountId]);
 }else if(['FAILED','REJECTED'].includes(state)){
  const row=(await db.query('SELECT state FROM spdecode_shop.apk_qa_jobs WHERE job_id=$1 AND account_id=$2',
    [id,accountId])).rows[0];
  if(row?.state==='completed')return;
  await releaseCredit(accountId,id);
  await db.query(`UPDATE spdecode_shop.apk_qa_jobs SET state='released',updated_at=now()
    WHERE job_id=$1 AND account_id=$2`,[id,accountId]);
 }
}
const commercialBilling={preflight,bindJob,authorizeJob,settleJob};
export async function apkQaRequest(request,operation,{env=process.env,send=fetch,
  authenticate=verifyApkAccount,billing=commercialBilling}={}){
 const action=METHODS[operation],cfg=settings(env);
 if(!action)return reply('INVALID_REQUEST',400);
 const claims=boundRequestClaims(request);
 if(!claims||claims.hpke!==true||typeof claims.key!=='string'||
    claims.key.length<32||claims.scope!=='decode')return reply('UNAUTHORIZED',401);
 if(!cfg.enabled)return reply('APK_QA_DISABLED',503);
 if(request.method!=='POST')return reply('INVALID_REQUEST',405);
 let payload;
 try{payload=await readJSON(request,operation===22?MAX_BODY:4096);}
 catch(e){const over=e?.message==='INPUT_TOO_LARGE';
   return reply(over?'INPUT_TOO_LARGE':'INVALID_REQUEST',over?413:400);}
 const token=payload.accountToken;
 delete payload.accountToken;delete payload.accountId;delete payload.deviceKeyHash;
 if(operation===21&&(payload.consent!==true||payload.qaFirstPass!==true))
   return reply('CONSENT_REQUIRED',403);
 const owner=createHash('sha256').update(claims.key,'utf8').digest('hex');
 let accountId;
 try{
  // A valid device session is NEVER sufficient to initiate commercial work.
  accountId=await authenticate(token);
  if(operation===21)await billing.preflight(accountId);
  else await billing.authorizeJob(accountId,owner,payload.jobId);
 }catch(e){
  return reply(e instanceof ShopError?e.code:'ACCOUNT_AUTH_UNAVAILABLE',
    e instanceof ShopError?e.status:503);
 }
 payload.deviceKeyHash=owner;
 try{
  const response=await send(cfg.endpoint+'/internal/qa/'+action,{
   method:'POST',headers:{'content-type':'application/json','x-sp-apk-internal':cfg.key},
   body:JSON.stringify(payload),signal:AbortSignal.timeout(12000),cache:'no-store'});
  if(!Number.isInteger(response.status)||response.status<200||response.status>599)
    throw Error('INVALID_INTERNAL_RESPONSE');
  const type=response.headers.get('content-type')?.split(';')[0]?.trim();
  if(type!=='application/json')throw Error('INVALID_INTERNAL_RESPONSE');
  const value=await readJSON(response,MAX_RESULT);
  if(!response.ok){
   if(operation===24&&['FAILED','REJECTED'].includes(value?.status))
     await billing.settleJob(accountId,payload.jobId,value.status);
   const code=value.error;
   if(!/^[A-Z_]{3,40}$/.test(code||''))return reply('APK_QA_UNAVAILABLE',503);
   return reply(code,response.status);
  }
  if(operation===21){
   await billing.bindJob(accountId,owner,value.jobId);
  }else if(operation===24&&['COMPLETED','FAILED','REJECTED'].includes(value.status)){
   await billing.settleJob(accountId,payload.jobId,value.status);
  }
  // Tokens/identity never reach the worker or are returned inside the V2 response.
  return jsonReply(value,response.status);
 }catch(e){
  if(e instanceof ShopError)return reply(e.code,e.status);
  return reply('APK_QA_UNAVAILABLE',503);
 }
}
