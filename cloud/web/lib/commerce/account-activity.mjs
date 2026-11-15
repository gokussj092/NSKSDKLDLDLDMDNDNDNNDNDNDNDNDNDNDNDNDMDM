import {database} from './db.mjs';
import {requireAccount} from './auth.mjs';
import {reply,safe} from './config.mjs';

export async function activityFor(accountId,{db=database(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 const [orders,credits,analyses,gifts]=await Promise.all([
  db.query(`SELECT id,product_id,status,created_at,paid_at,quote
    FROM spdecode_shop.orders WHERE account_id=$1 AND payment_live=$2
    ORDER BY created_at DESC LIMIT 40`,[accountId,live]),
  db.query(`SELECT id,movement_kind,delta,created_at,order_id,job_id
    FROM spdecode_shop.credit_ledger WHERE account_id=$1 AND payment_live=$2
    ORDER BY created_at DESC LIMIT 80`,[accountId,live]),
  db.query(`SELECT job_id,state,created_at,updated_at
    FROM spdecode_shop.apk_qa_jobs WHERE account_id=$1 AND payment_live=$2
    ORDER BY created_at DESC LIMIT 40`,[accountId,live]),
  db.query(`SELECT r.id,r.created_at,g.kind FROM spdecode_shop.gift_redemptions r
    JOIN spdecode_shop.gift_codes g ON g.id=r.gift_id
    WHERE r.account_id=$1 ORDER BY r.created_at DESC LIMIT 30`,[accountId])
 ]);
 const timeline=[
  ...orders.rows.map(x=>({id:x.id,kind:'order',status:x.status,
    label:x.product_id,amountCents:x.quote?.total??null,currency:x.quote?.currency??'USD',
    at:x.created_at})),
  ...credits.rows.map(x=>({id:x.id,kind:'credit',status:x.movement_kind,
    label:'analysis-credits',delta:x.delta,at:x.created_at})),
  ...analyses.rows.map(x=>({id:x.job_id,kind:'analysis',status:x.state,
    label:'apk-analysis',at:x.created_at})),
  ...gifts.rows.map(x=>({id:x.id,kind:'gift',status:'redeemed',
    label:x.kind,at:x.created_at}))
 ].sort((a,b)=>new Date(b.at)-new Date(a.at)).slice(0,100);
 return {operations:timeline};
}
export const activityRequest=request=>safe(async()=>{
 if(request.method!=='GET')return reply({error:{code:'METHOD_NOT_ALLOWED'}},405);
 const session=await requireAccount(request);
 return reply(await activityFor(session.user.id));
});
