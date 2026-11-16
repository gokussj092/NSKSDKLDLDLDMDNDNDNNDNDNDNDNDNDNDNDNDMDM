/**
 * Outbound webhook emitter for app analysis (SP-DECODE Arnes, fase 1).
 *
 * The server notifies Yamada with a signed POST when a job is created and on
 * every terminal change. Yamada never polls. The payload carries only opaque
 * identifiers (jobId, accountId, status, errorCode) — never the APK, the
 * result, or any credential. Retries are recorded in
 * spdecode_shop.app_analysis_webhook_deliveries; a missing webhook URL is
 * recorded as 'skipped' and never fails the job.
 *
 * Signature (documented for the receiver): header
 * `x-spdecode-signature` is HMAC-SHA256(secret, timestamp + "." + event +
 * "." + JSON.stringify(body)) as lowercase hex; `x-spdecode-timestamp` is
 * unix seconds; the receiver must compare with timingSafeEqual and reject
 * timestamps outside +-300 s (same window as the Mercado Pago inbound
 * verifier in lib/commerce/providers.mjs).
 */
import {createHmac,timingSafeEqual,randomUUID} from 'node:crypto';
import {database} from './commerce/db.mjs';

const MAX_ATTEMPTS=3;
const RETRY_DELAY_MS=60*1000;

export function webhookSettings(env=process.env){
 const url=env.SPDECODE_APP_ANALYSIS_WEBHOOK_URL||'';
 const secret=env.SPDECODE_APP_ANALYSIS_WEBHOOK_SECRET||'';
 return {url,secret,configured:!!url&&secret.length>=32};
}

export function signWebhook(secret,event,body,timestamp=Math.floor(Date.now()/1000)){
 const payload=timestamp+'.'+event+'.'+JSON.stringify(body);
 return {timestamp,signature:createHmac('sha256',secret).update(payload,'utf8').digest('hex')};
}

export function verifyWebhookSignature(secret,event,body,timestamp,signature){
 if(!secret||secret.length<32||typeof signature!=='string')return false;
 const now=Math.floor(Date.now()/1000);
 if(!Number.isInteger(timestamp)||Math.abs(now-timestamp)>300)return false;
 const expected=signWebhook(secret,event,body,timestamp).signature;
 const a=Buffer.from(signature,'utf8'),b=Buffer.from(expected,'utf8');
 return a.length===b.length&&timingSafeEqual(a,b);
}

async function recordDelivery(db,jobId,event,status,attempts,error){
 await db.query(`INSERT INTO spdecode_shop.app_analysis_webhook_deliveries
   (id,job_id,event,status,attempts,last_error,next_retry_at)
   VALUES($1,$2,$3,$4,$5,$6,$7)`,
  [randomUUID(),jobId,event,status,attempts,
   error?String(error).slice(0,500):null,
   status==='failed'||status==='pending'
     ?new Date(Date.now()+RETRY_DELAY_MS).toISOString():null]);
}

/**
 * Emit one event. `send` defaults to global fetch and is injectable in tests.
 * Returns {delivered:boolean, skipped?:boolean, status}.
 */
export async function emitAnalysisWebhook(event,job,{db=database(),env=process.env,
  send=fetch,now=()=>Date.now()}={}){
 const cfg=webhookSettings(env);
 const body={event,jobId:job.jobId,accountId:job.accountId,status:job.status,
   ...(job.errorCode?{errorCode:job.errorCode}:{})};
 if(!cfg.configured){
  await recordDelivery(db,job.jobId,event,'skipped',0,
    cfg.url?'APP_ANALYSIS_WEBHOOK_SECRET_TOO_SHORT':'APP_ANALYSIS_WEBHOOK_URL_MISSING')
    .catch(()=>{});
  return {delivered:false,skipped:true,status:'skipped'};
 }
 const {timestamp,signature}=signWebhook(cfg.secret,event,body,Math.floor(now()/1000));
 let attempts=0,lastError=null;
 for(;attempts<MAX_ATTEMPTS;attempts++){
  try{
   const response=await send(cfg.url,{method:'POST',
     headers:{'content-type':'application/json',
       'x-spdecode-event':event,
       'x-spdecode-timestamp':String(timestamp),
       'x-spdecode-signature':signature},
     body:JSON.stringify(body),signal:AbortSignal.timeout(10000)});
   if(response.ok){
    await recordDelivery(db,job.jobId,event,'delivered',attempts+1,null).catch(()=>{});
    return {delivered:true,status:'delivered'};
   }
   lastError='HTTP_'+response.status;
  }catch(e){lastError=e?.message||'WEBHOOK_SEND_FAILED';}
  if(attempts+1<MAX_ATTEMPTS)
   await new Promise(resolve=>setTimeout(resolve,RETRY_DELAY_MS));
 }
 await recordDelivery(db,job.jobId,event,'failed',attempts,lastError).catch(()=>{});
 return {delivered:false,status:'failed',error:lastError};
}

/** Re-attempt deliveries stuck in 'failed'/'pending' past next_retry_at. */
export async function retryPendingWebhooks({db=database(),env=process.env,send=fetch}={}){
 const rows=(await db.query(`SELECT DISTINCT ON (job_id,event) job_id,event
   FROM spdecode_shop.app_analysis_webhook_deliveries
   WHERE status IN ('failed','pending') AND next_retry_at<=now()
   ORDER BY job_id,event,created_at DESC LIMIT 50`)).rows;
 let retried=0;
 for(const row of rows){
  const job=(await db.query(`SELECT job_id,account_id,status,error_code
    FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1`,[row.job_id])).rows[0];
  if(!job)continue;
  const out=await emitAnalysisWebhook(row.event,
    {jobId:job.job_id,accountId:job.account_id,status:job.status,
     errorCode:job.error_code},{db,env,send});
  if(out.delivered)retried++;
 }
 return {retried,pending:rows.length};
}
