import {randomUUID} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {fail} from './config.mjs';
const validJob=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
export async function creditBalance(accountId,{db=database(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 const result=await db.query(`SELECT
   COALESCE((SELECT SUM(delta) FROM spdecode_shop.credit_ledger
     WHERE account_id=$1 AND payment_live=$2),0)::integer AS balance,
   (SELECT COUNT(*) FROM spdecode_shop.credit_reservations
     WHERE account_id=$1 AND payment_live=$2 AND state='held')::integer AS held`,[accountId,live]);
 const row=result.rows[0];return {balance:row.balance,held:row.held,available:row.balance-row.held,live};
}
// A verified Google-authenticated analysis session must bind the accountId
// to its server-issued jobId. These functions are intentionally NOT exposed
// as an unauthenticated public API.
export async function reserveCredit(accountId,jobId,{db=database(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 if(process.env.SPDECODE_ANALYSIS_CREDITS_READY!=='true'||!validJob(jobId))fail('CREDITS_UNAVAILABLE',503);
 return transaction(async client=>{
   const user=(await client.query('SELECT id FROM shop_user WHERE id=$1 FOR UPDATE',[accountId])).rows[0];
   if(!user)fail('SIGN_IN_REQUIRED',401);
   const old=(await client.query('SELECT * FROM spdecode_shop.credit_reservations WHERE job_id=$1 FOR UPDATE',[jobId])).rows[0];
   if(old){if(old.account_id!==accountId||old.payment_live!==live)fail('CREDIT_JOB_CONFLICT',409);
     if(old.state==='released')fail('CREDIT_JOB_RELEASED',409);return {id:old.id,state:old.state,jobId};}
   const state=await creditBalance(accountId,{db:client,live});
   if(state.available<1)fail('INSUFFICIENT_CREDITS',402);
   const id=randomUUID();
   await client.query(`INSERT INTO spdecode_shop.credit_reservations
     (id,account_id,job_id,payment_live,state) VALUES($1,$2,$3,$4,'held')`,[id,accountId,jobId,live]);
   return {id,state:'held',jobId,remaining:state.available-1};
 },db);
}
export async function completeCredit(accountId,jobId,{db=database(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 if(!validJob(jobId))fail('INVALID_JOB');
 return transaction(async client=>{
   const user=(await client.query('SELECT id FROM shop_user WHERE id=$1 FOR UPDATE',[accountId])).rows[0];
   if(!user)fail('SIGN_IN_REQUIRED',401);
   const item=(await client.query('SELECT * FROM spdecode_shop.credit_reservations WHERE job_id=$1 AND account_id=$2 AND payment_live=$3 FOR UPDATE',[jobId,accountId,live])).rows[0];
   if(!item)fail('CREDIT_JOB_NOT_FOUND',404);
   if(item.state==='completed')return {state:'completed',jobId};
   if(item.state!=='held')fail('CREDIT_JOB_RELEASED',409);
   await client.query(`INSERT INTO spdecode_shop.credit_ledger
     (id,account_id,job_id,movement_kind,delta,payment_live)
     VALUES($1,$2,$3,'spend',-1,$4) ON CONFLICT(job_id,movement_kind) DO NOTHING`,
     [randomUUID(),accountId,jobId,live]);
   await client.query("UPDATE spdecode_shop.credit_reservations SET state='completed',updated_at=now() WHERE id=$1",[item.id]);
   return {state:'completed',jobId};
 },db);
}
export async function releaseCredit(accountId,jobId,{db=database(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 if(!validJob(jobId))fail('INVALID_JOB');
 return transaction(async client=>{
   const user=(await client.query('SELECT id FROM shop_user WHERE id=$1 FOR UPDATE',[accountId])).rows[0];
   if(!user)fail('SIGN_IN_REQUIRED',401);
   const item=(await client.query('SELECT * FROM spdecode_shop.credit_reservations WHERE job_id=$1 AND account_id=$2 AND payment_live=$3 FOR UPDATE',[jobId,accountId,live])).rows[0];
   if(!item)fail('CREDIT_JOB_NOT_FOUND',404);
   if(item.state==='completed')fail('CREDIT_ALREADY_SPENT',409);
   if(item.state==='held')await client.query("UPDATE spdecode_shop.credit_reservations SET state='released',updated_at=now() WHERE id=$1",[item.id]);
   return {state:'released',jobId};
 },db);
}
