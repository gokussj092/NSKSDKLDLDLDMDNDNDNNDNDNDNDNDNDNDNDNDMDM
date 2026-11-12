import {randomUUID,randomBytes,createHash,createHmac} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {fail,paymentReady,publicIp} from './config.mjs';
import {planAvailable,planFor,taxQuote,validatePurchase} from './catalog.mjs';
import {startPayment} from './providers.mjs';
export async function catalog(db=database()){
  return (await db.query('SELECT * FROM spdecode_shop.products ORDER BY id')).rows;
}
export async function taxRules(db=database()){
  return (await db.query("SELECT value FROM spdecode_shop.settings WHERE id='tax-rules'")).rows[0]?.value||[];
}
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
export async function checkout(accountId,input,{db=database(),start=startPayment}={}){
  const body=validatePurchase(input);
  const live=process.env.SPDECODE_PAYMENTS_LIVE==='true';
  if(!paymentReady(body.provider))fail('PAYMENT_METHOD_UNAVAILABLE',409);
  const fingerprint=digest([body.product,body.term,body.provider,body.currency,body.version,body.country,body.region,body.allowedIp,live]);
  const order=await transaction(async client=>{
    const existing=(await client.query('SELECT * FROM spdecode_shop.orders WHERE account_id=$1 AND idempotency_key=$2',
      [accountId,body.idempotencyKey])).rows[0];
    if(existing){if(existing.request_digest!==fingerprint)fail('IDEMPOTENCY_CONFLICT',409);return existing;}
    const row=(await client.query('SELECT * FROM spdecode_shop.products WHERE id=$1 FOR SHARE',[body.product])).rows[0];
    if(!row||row.version!==body.version)fail('PRICE_CHANGED',409);
    if(!planAvailable(row.settings,body.term))fail('PRODUCT_UNAVAILABLE',409);
    const rules=await taxRules(client),quote=taxQuote(row.settings,body.currency,body.country,body.region||'',rules,body.term);
    const id=randomUUID();
    const term=planFor(row.settings,body.term);
    const values=[id,accountId,body.product,{...row.settings,term:term.id,credits:term.credits??null,days:term.days,termsVersion:'2026-11-10'},quote,body.provider,body.idempotencyKey,fingerprint,body.allowedIp,live];
    await client.query(`INSERT INTO spdecode_shop.orders
      (id,account_id,product_id,product_snapshot,quote,provider,idempotency_key,request_digest,allowed_ip,payment_live)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(account_id,idempotency_key) DO NOTHING`,values);
    const saved=(await client.query('SELECT * FROM spdecode_shop.orders WHERE account_id=$1 AND idempotency_key=$2',
      [accountId,body.idempotencyKey])).rows[0];
    if(saved.request_digest!==fingerprint)fail('IDEMPOTENCY_CONFLICT',409);return saved;
  },db);
  if(order.status==='paid')return {orderId:order.id,status:'paid'};
  if(!['created','pending'].includes(order.status))fail('ORDER_CLOSED',409);
  if(order.checkout_url)return {orderId:order.id,status:order.status,url:order.checkout_url};
  const lease=await db.query(`UPDATE spdecode_shop.orders SET checkout_lock_until=now()+interval '60 seconds'
    WHERE id=$1 AND checkout_url IS NULL AND (checkout_lock_until IS NULL OR checkout_lock_until<now()) RETURNING id`,[order.id]);
  if(!lease.rowCount)fail('CHECKOUT_IN_PROGRESS',409);
  try{
    const payment=await start(order);
    await db.query(`UPDATE spdecode_shop.orders SET provider_id=$2,checkout_url=$3,status='pending',checkout_lock_until=NULL WHERE id=$1`,
      [order.id,payment.id,payment.url]);
    return {orderId:order.id,status:'pending',url:payment.url};
  }catch(e){await db.query('UPDATE spdecode_shop.orders SET checkout_lock_until=NULL WHERE id=$1',[order.id]);throw e;}
}
export async function settle(provider,event,{db=database()}={}){
  if(!event)return {ignored:true};
  if(!/^[0-9a-f-]{36}$/.test(event.orderId||'')||typeof event.eventId!=='string'||event.eventId.length>200)fail('INVALID_PAYMENT_EVENT');
  return transaction(async client=>{
    const order=(await client.query('SELECT * FROM spdecode_shop.orders WHERE id=$1 FOR UPDATE',[event.orderId])).rows[0];
    if(!order||order.provider!==provider||order.provider_id!==event.providerId)fail('PAYMENT_ORDER_MISMATCH',409);
    if(typeof event.live!=='boolean'||event.live!==order.payment_live)fail('PAYMENT_MODE_MISMATCH',409);
    if(event.type==='paid'){
      const q=order.quote;
      if(event.currency!==q.currency||!Number.isSafeInteger(event.total)||event.total<1||
        (event.automaticTax?event.subtotal!==q.subtotal||!Number.isSafeInteger(event.tax)||event.tax<0||
          event.total!==event.subtotal+event.tax:event.total!==q.total))fail('PAYMENT_AMOUNT_MISMATCH',409);
    }else if(!['refunded','disputed'].includes(event.type))fail('INVALID_PAYMENT_EVENT');
    const inserted=await client.query(`INSERT INTO spdecode_shop.events(provider,event_id,order_id,type)
      VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING event_id`,[provider,event.eventId,order.id,event.type]);
    if(!inserted.rowCount)return {duplicate:true};
    if(event.type==='paid'){
      // Refund/dispute is terminal; an out-of-order success cannot restore access.
      if(['refunded','disputed'].includes(order.status))return {ignored:true};
      if(order.status!=='paid'){
        const q=event.automaticTax?{...order.quote,tax:event.tax,total:event.total,taxMode:'provider-verified',taxLabel:'Tax',
          country:event.country||order.quote.country,region:event.region||order.quote.region}:order.quote;
        await client.query("UPDATE spdecode_shop.orders SET status='paid',paid_at=now(),quote=$2 WHERE id=$1",[order.id,q]);
        const p=order.product_snapshot;
        // Serialize against account deletion. Retain accounting for a late
        // payment without recreating active access or erased connection data.
        const owner=await client.query('SELECT id FROM shop_user WHERE id=$1 FOR UPDATE',[order.account_id]);
        if(order.product_id==='analysis-credits'){
          // Never issue a license/API key for credits. The verified webhook is
          // the only source of a positive balance movement.
          if(owner.rows.length&&Number.isInteger(p.credits)&&p.credits>0&&p.credits<=100){
            await client.query(`INSERT INTO spdecode_shop.credit_ledger
              (id,account_id,order_id,movement_kind,delta,payment_live)
              VALUES($1,$2,$3,'grant',$4,$5) ON CONFLICT(order_id,movement_kind) DO NOTHING`,
              [randomUUID(),order.account_id,order.id,p.credits,order.payment_live]);
          }
        }else{
          // Ad-free access starts only after a verified payment webhook.
          // Existing paid time is preserved when the same owner renews.
          let expires=null;
          if(order.product_id==='ads-free'){
            const prior=await client.query(`SELECT MAX(expires_at) AS until
              FROM spdecode_shop.entitlements
              WHERE account_id=$1 AND product_id='ads-free' AND status='active'
                AND payment_live=$2 AND expires_at>now()`,[order.account_id,order.payment_live]);
            const previous=prior.rows[0]?.until?.getTime?.()||0;
            expires=new Date(Math.max(Date.now(),previous)+30*86400000);
          }
          await client.query(`INSERT INTO spdecode_shop.entitlements(id,order_id,account_id,product_id,allowed_ip,quota,days,status,payment_live,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(order_id) DO NOTHING`,
            [randomUUID(),order.id,order.account_id,order.product_id,owner.rows.length?order.allowed_ip:null,p.quota,p.days,owner.rows.length?'active':'revoked',order.payment_live,expires]);
        }
      }
    }else{
      await client.query('UPDATE spdecode_shop.orders SET status=$2,refunded_at=now() WHERE id=$1',[order.id,event.type]);
      await client.query("UPDATE spdecode_shop.entitlements SET status='revoked' WHERE order_id=$1",[order.id]);
      if(order.product_id==='analysis-credits'){
        // A refund/dispute reverses the whole grant, including already-spent
        // credits. Negative balances suspend future analysis reservations.
        await client.query(`INSERT INTO spdecode_shop.credit_ledger
          (id,account_id,order_id,movement_kind,delta,payment_live)
          SELECT $1,account_id,order_id,'refund',-delta,payment_live
          FROM spdecode_shop.credit_ledger
          WHERE order_id=$2 AND movement_kind='grant'
          ON CONFLICT(order_id,movement_kind) DO NOTHING`,[randomUUID(),order.id]);
      }
    }
    return {received:true};
  },db);
}
export function tokenDigest(token,key=process.env.SPDECODE_SHOP_TOKEN_KEY){
  if(typeof key!=='string'||key.length<32)fail('ENTITLEMENTS_NOT_CONFIGURED',503);
  return createHmac('sha256',key).update('spdecode:commercial:v1\0').update(token).digest('hex');
}
export async function claim(accountId,id,{rotate=false,db=database()}={}){
  return transaction(async client=>{
    const item=(await client.query('SELECT * FROM spdecode_shop.entitlements WHERE id=$1 AND account_id=$2 FOR UPDATE',[id,accountId])).rows[0];
    if(!item||item.status!=='active')fail('PURCHASE_NOT_AVAILABLE',404);
    // Ad-free is a session entitlement, never a transferable offline license.
    if(item.product_id==='ads-free')fail('CLAIM_UNAVAILABLE',409);
    if(item.payment_live!==(process.env.SPDECODE_PAYMENTS_LIVE==='true'))fail('PAYMENT_MODE_MISMATCH',409);
    // Never mint an API key with no network restriction in force.
    if(item.product_id==='api-ip'&&!publicIp(item.allowed_ip))fail('PUBLIC_IP_REQUIRED',409);
    if(item.claimed_at&&!rotate)fail('ALREADY_REVEALED',409);
    if(rotate&&item.product_id!=='api-ip')fail('ROTATION_UNAVAILABLE',409);
    const token=(item.product_id==='api-ip'?'spd_api_':'SPD-OFF-')+randomBytes(32).toString('base64url');
    const hashed=tokenDigest(token);
    const expiry=item.expires_at||(item.days?new Date(Date.now()+item.days*86400000):null);
    if(expiry&&new Date(expiry)<=new Date())fail('ACCESS_EXPIRED',409);
    await client.query(`UPDATE spdecode_shop.entitlements SET token_digest=$3,token_prefix=$4,
      expires_at=$5,claimed_at=now() WHERE id=$1 AND account_id=$2`,[id,accountId,hashed,token.slice(0,12),expiry]);
    await client.query('INSERT INTO spdecode_shop.audit(actor_id,action,resource_id) VALUES($1,$2,$3)',
      [accountId,rotate?'api_key_rotated':'secret_claimed',id]);
    return {token,expiresAt:expiry,product:item.product_id};
  },db);
}
/**
 * Account owner can provision/change the authorized public address after
 * payment. Updates immediately revoke permission for the prior IP. Keys stay
 * server-side hashed; no token is returned by this operation.
 */
export async function updateApiAllowedIp(accountId,id,input,{db=database()}={}){
  if(typeof id!=='string'||!/^[0-9a-f-]{36}$/.test(id))fail('INVALID_REQUEST');
  const allowedIp=publicIp(input);
  if(!allowedIp)fail('INVALID_PUBLIC_IP');
  return transaction(async client=>{
    const e=(await client.query(`SELECT id,account_id,product_id,status,payment_live,expires_at,allowed_ip
      FROM spdecode_shop.entitlements WHERE id=$1 AND account_id=$2 FOR UPDATE`,
      [id,accountId])).rows[0];
    if(!e||e.product_id!=='api-ip'||e.status!=='active')fail('PURCHASE_NOT_AVAILABLE',404);
    if(e.payment_live!==(process.env.SPDECODE_PAYMENTS_LIVE==='true'))fail('PAYMENT_MODE_MISMATCH',409);
    if(e.expires_at && new Date(e.expires_at)<=new Date())fail('ACCESS_EXPIRED',409);
    if(e.allowed_ip!==allowedIp){
      await client.query('UPDATE spdecode_shop.entitlements SET allowed_ip=$2 WHERE id=$1',[id,allowedIp]);
      await client.query("INSERT INTO spdecode_shop.audit(actor_id,action,resource_id) VALUES($1,'api_ip_updated',$2)",
        [accountId,id]);
    }
    return {id,allowedIp,configured:true};
  },db);
}
export async function useApiKey(token,originIp,{db=database()}={}){
  if(!/^spd_api_[A-Za-z0-9_-]{43}$/.test(token||''))fail('UNAUTHORIZED',401);
  const hashed=tokenDigest(token),ip=publicIp(originIp);
  return transaction(async client=>{
    const item=(await client.query(`SELECT e.* FROM spdecode_shop.entitlements e JOIN shop_user u ON u.id=e.account_id
      WHERE e.token_digest=$1 AND e.product_id='api-ip' AND e.status='active' AND e.payment_live=$2 FOR UPDATE OF e`,[hashed,process.env.SPDECODE_PAYMENTS_LIVE==='true'])).rows[0];
    if(!item||!item.expires_at||new Date(item.expires_at)<=new Date())fail('UNAUTHORIZED',401);
    if(!ip||ip!==item.allowed_ip)fail('IP_NOT_ALLOWED',403);
    await client.query(`WITH released AS (
      UPDATE spdecode_shop.usage_reservations SET state='released'
      WHERE entitlement_id=$1 AND state='held' AND created_at<now()-interval '5 minutes' RETURNING period
    ), totals AS (SELECT period,count(*) AS n FROM released GROUP BY period)
    UPDATE spdecode_shop.usage u SET accepted=GREATEST(0,u.accepted-totals.n::integer)
    FROM totals WHERE u.entitlement_id=$1 AND u.period=totals.period`,[item.id]);
    const counter=await client.query(`INSERT INTO spdecode_shop.usage(entitlement_id,period,accepted) VALUES($1,CURRENT_DATE,1)
      ON CONFLICT(entitlement_id,period) DO UPDATE SET accepted=spdecode_shop.usage.accepted+1
      WHERE spdecode_shop.usage.accepted<$2 RETURNING accepted,period::text AS period`,[item.id,item.quota]);
    if(!counter.rowCount)fail('QUOTA_EXCEEDED',429);
    const reservationId=randomUUID();
    await client.query(`INSERT INTO spdecode_shop.usage_reservations(id,entitlement_id,period,state) VALUES($1,$2,CURRENT_DATE,'held')`,[reservationId,item.id]);
    return {id:item.id,reservationId,period:counter.rows[0].period,remaining:item.quota-counter.rows[0].accepted};
  },db);
}
export async function checkApiKey(token,originIp,{db=database()}={}){
  if(!/^spd_api_[A-Za-z0-9_-]{43}$/.test(token||''))fail('UNAUTHORIZED',401);
  const item=(await db.query(`SELECT e.id,e.allowed_ip,e.expires_at FROM spdecode_shop.entitlements e
    JOIN shop_user u ON u.id=e.account_id WHERE e.token_digest=$1 AND e.product_id='api-ip' AND e.status='active' AND e.payment_live=$2`,[tokenDigest(token),process.env.SPDECODE_PAYMENTS_LIVE==='true'])).rows[0];
  if(!item||!item.expires_at||new Date(item.expires_at)<=new Date())fail('UNAUTHORIZED',401);
  const ip=publicIp(originIp);if(!ip||ip!==item.allowed_ip)fail('IP_NOT_ALLOWED',403);
  return item.id;
}
export async function releaseApiUsage(reservation,db=database()){
  await transaction(async client=>{
    const row=await client.query(`UPDATE spdecode_shop.usage_reservations SET state='released'
      WHERE id=$1 AND entitlement_id=$2 AND state='held' RETURNING id`,[reservation.reservationId,reservation.id]);
    if(row.rowCount)await client.query('UPDATE spdecode_shop.usage SET accepted=GREATEST(accepted-1,0) WHERE entitlement_id=$1 AND period=$2',
      [reservation.id,reservation.period]);
  },db);
}
export async function completeApiUsage(reservation,db=database()){
  await db.query("UPDATE spdecode_shop.usage_reservations SET state='completed' WHERE id=$1 AND state='held'",[reservation.reservationId]);
}
