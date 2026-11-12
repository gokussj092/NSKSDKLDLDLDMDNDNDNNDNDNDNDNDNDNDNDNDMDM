import {randomBytes,randomUUID,createHmac} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {fail} from './config.mjs';

const KINDS=new Set(['credits','ads-free','offline-3']);
const CODE=/^SPG-[A-Za-z0-9_-]{22}$/;
const liveMode=()=>process.env.SPDECODE_PAYMENTS_LIVE==='true';

function digest(code,key=process.env.SPDECODE_SHOP_TOKEN_KEY){
  if(typeof key!=='string'||key.length<32)fail('GIFTS_NOT_CONFIGURED',503);
  return createHmac('sha256',key)
    .update('spdecode:gifts:v1\0').update(code).digest('hex');
}
export function validateGiftSpec(input){
  if(!input||typeof input!=='object'||Array.isArray(input)||
     Object.keys(input).some(k=>!['kind','title','credits','days','maxUses','expiresAt'].includes(k)))
    fail('INVALID_GIFT');
  const title=typeof input.title==='string'?input.title.trim():'';
  if(!KINDS.has(input.kind)||title.length<2||title.length>80||
     /[\x00-\x1F\x7F]/.test(title)||
     !Number.isSafeInteger(input.maxUses)||input.maxUses<1||input.maxUses>10000)
    fail('INVALID_GIFT');
  if(input.kind==='credits'){
    if(!Number.isSafeInteger(input.credits)||input.credits<1||input.credits>1000||
       input.days!==undefined)fail('INVALID_GIFT');
  }else if(!Number.isSafeInteger(input.days)||input.days<1||input.days>3650||
             input.credits!==undefined)fail('INVALID_GIFT');
  let expiry=null;
  if(input.expiresAt!==undefined&&input.expiresAt!==null&&input.expiresAt!==''){
    if(typeof input.expiresAt!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/.test(input.expiresAt))
      fail('INVALID_GIFT');
    const time=Date.parse(input.expiresAt);
    if(!Number.isFinite(time)||time<=Date.now()+60*1000||time>Date.now()+3650*86400000)
      fail('INVALID_GIFT');
    expiry=new Date(time);
  }
  return {title,kind:input.kind,credits:input.kind==='credits'?input.credits:null,
    days:input.kind==='credits'?null:input.days,maxUses:input.maxUses,expiresAt:expiry};
}

export async function createGift(input,actor,{db=database()}={}){
  const spec=validateGiftSpec(input);
  if(typeof actor!=='string'||actor.length<1)fail('UNAUTHORIZED',401);
  const code='SPG-'+randomBytes(16).toString('base64url');
  const id=randomUUID();
  await transaction(async client=>{
    await client.query(`INSERT INTO spdecode_shop.gift_codes
      (id,code_digest,title,kind,credits,duration_days,max_uses,expires_at,created_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [id,digest(code),spec.title,spec.kind,spec.credits,spec.days,spec.maxUses,
       spec.expiresAt,actor]);
    await client.query(`INSERT INTO spdecode_shop.audit(actor_id,action,resource_id)
      VALUES($1,'gift_created',$2)`,[actor,id]);
  },db);
  // Only this admin response ever includes the raw code.
  return {id,code,kind:spec.kind,title:spec.title,maxUses:spec.maxUses};
}

export async function disableGift(id,actor,{db=database()}={}){
  if(typeof id!=='string'||!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(id))
    fail('INVALID_GIFT');
  await transaction(async client=>{
    const row=await client.query('UPDATE spdecode_shop.gift_codes SET enabled=false WHERE id=$1 RETURNING id',[id]);
    if(!row.rowCount)fail('GIFT_NOT_FOUND',404);
    await client.query(`INSERT INTO spdecode_shop.audit(actor_id,action,resource_id)
      VALUES($1,'gift_disabled',$2)`,[actor,id]);
  },db);
  return {disabled:true,id};
}
export async function listGifts({db=database()}={}){
  const [codes,redemptions]=await Promise.all([
    db.query(`SELECT id,title,kind,credits,duration_days AS days,max_uses,used,enabled,
      expires_at,created_at FROM spdecode_shop.gift_codes
      ORDER BY created_at DESC LIMIT 100`),
    db.query(`SELECT r.id,r.gift_id,r.account_id,r.order_id,r.created_at,
        g.title,g.kind,u.name,p.username,
        COALESCE(p.avatar_data,u.image) AS avatar
      FROM spdecode_shop.gift_redemptions r
      JOIN spdecode_shop.gift_codes g ON g.id=r.gift_id
      LEFT JOIN shop_user u ON u.id=r.account_id
      LEFT JOIN spdecode_shop.profiles p ON p.account_id=r.account_id
      ORDER BY r.created_at DESC LIMIT 100`)
  ]);
  return {codes:codes.rows,redemptions:redemptions.rows};
}

async function checkRate(accountId,db){
  const attempts=(await db.query(`INSERT INTO spdecode_shop.gift_attempt_limits
    (account_id,window_start,attempts) VALUES($1,now(),1)
    ON CONFLICT (account_id) DO UPDATE SET
      attempts=CASE WHEN spdecode_shop.gift_attempt_limits.window_start<now()-interval '15 minutes'
        THEN 1 ELSE spdecode_shop.gift_attempt_limits.attempts+1 END,
      window_start=CASE WHEN spdecode_shop.gift_attempt_limits.window_start<now()-interval '15 minutes'
        THEN now() ELSE spdecode_shop.gift_attempt_limits.window_start END
    RETURNING attempts`,[accountId])).rows[0]?.attempts;
  if(!Number.isInteger(attempts)||attempts>8)fail('GIFT_RATE_LIMITED',429);
}

export async function redeemGift(accountId,raw,{db=database()}={}){
  if(typeof accountId!=='string'||!accountId)fail('SIGN_IN_REQUIRED',401);
  // Write the rate counter before the benefit transaction. Invalid attempts
  // must not roll their own throttling state back.
  await checkRate(accountId,db);
  if(typeof raw!=='string'||!CODE.test(raw.trim()))fail('GIFT_INVALID',404);
  const code=raw.trim(),fingerprint=digest(code),live=liveMode();
  return transaction(async client=>{
    const gift=(await client.query('SELECT * FROM spdecode_shop.gift_codes WHERE code_digest=$1 FOR UPDATE',[fingerprint])).rows[0];
    if(!gift||!gift.enabled||gift.used>=gift.max_uses||
       (gift.expires_at&&new Date(gift.expires_at)<=new Date()))fail('GIFT_INVALID',404);
    const already=await client.query(`SELECT 1 FROM spdecode_shop.gift_redemptions
      WHERE gift_id=$1 AND account_id=$2`,[gift.id,accountId]);
    if(already.rowCount)fail('GIFT_ALREADY_REDEEMED',409);
    const owner=await client.query('SELECT id FROM shop_user WHERE id=$1 FOR UPDATE',[accountId]);
    if(!owner.rowCount)fail('SIGN_IN_REQUIRED',401);
    const id=randomUUID();
    const product=gift.kind==='credits'?'analysis-credits':gift.kind;
    const snapshot=gift.kind==='credits'?{id:product,credits:gift.credits,term:'gift'}:
      {id:product,days:gift.duration_days,maxDevices:gift.kind==='offline-3'?3:null,
        term:'gift'};
    // Gift orders are zero-cost records, never passed to provider webhooks.
    // Payment mode still distinguishes QA from production entitlements.
    const quote={subtotal:0,tax:0,total:0,currency:'USD',taxMode:'gift'};
    await client.query(`INSERT INTO spdecode_shop.orders
      (id,account_id,product_id,product_snapshot,quote,provider,
       idempotency_key,request_digest,status,payment_live,paid_at)
      VALUES($1,$2,$3,$4,$5,'gift',$6,$7,'paid',$8,now())`,
      [id,accountId,product,snapshot,quote,randomUUID(),gift.id,live]);
    if(gift.kind==='credits'){
      await client.query(`INSERT INTO spdecode_shop.credit_ledger
        (id,account_id,order_id,movement_kind,delta,payment_live)
        VALUES($1,$2,$3,'grant',$4,$5)`,
        [randomUUID(),accountId,id,gift.credits,live]);
    }else{
      const previous=gift.kind==='ads-free'?
        (await client.query(`SELECT MAX(expires_at) AS until
          FROM spdecode_shop.entitlements
          WHERE account_id=$1 AND product_id='ads-free'
            AND status='active' AND payment_live=$2 AND expires_at>now()`,
          [accountId,live])).rows[0]?.until:null;
      const start=Math.max(Date.now(),previous?new Date(previous).getTime():0);
      const expiry=new Date(start+gift.duration_days*86400000);
      await client.query(`INSERT INTO spdecode_shop.entitlements
        (id,order_id,account_id,product_id,days,expires_at,status,payment_live)
        VALUES($1,$2,$3,$4,$5,$6,'active',$7)`,
        [randomUUID(),id,accountId,product,gift.duration_days,expiry,live]);
    }
    await client.query(`INSERT INTO spdecode_shop.gift_redemptions
      (id,gift_id,account_id,order_id) VALUES($1,$2,$3,$4)`,
      [randomUUID(),gift.id,accountId,id]);
    await client.query('UPDATE spdecode_shop.gift_codes SET used=used+1 WHERE id=$1',[gift.id]);
    await client.query(`INSERT INTO spdecode_shop.audit(actor_id,action,resource_id)
      VALUES($1,'gift_redeemed',$2)`,[accountId,gift.id]);
    return {redeemed:true,product,credits:gift.kind==='credits'?gift.credits:null,
      days:gift.duration_days,orderId:id};
  },db);
}
