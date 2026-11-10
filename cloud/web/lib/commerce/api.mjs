import {randomUUID} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {safe,reply,fail,ShopError,authReady,paymentReady,requireOrigin,jsonBody,boundedBody} from './config.mjs';
import {accountAuth,requireAccount} from './auth.mjs';
import {catalog,taxRules,checkout,settle,claim,useApiKey,checkApiKey,releaseApiUsage,completeApiUsage} from './orders.mjs';
import {publicProduct,taxQuote,validateProduct} from './catalog.mjs';
import {profile,editProfile} from './profile.mjs';
import {creditBalance} from './credits.mjs';
import {capturePaypal,paymentEvent} from './providers.mjs';
import {adminSettings,authenticateAdmin,validMutation} from '../c6-admin-auth.mjs';
import {opsStore,serviceMaintenanceEnabled} from '../c6-ops-store.mjs';
import {reserveSlot,releaseSlot} from '../c3-store.mjs';

export const publicCatalog=()=>safe(async()=>{
  const configured=authReady(),rows=configured?await catalog():[
    {version:1,settings:{id:'offline-3',enabled:false,prices:{USD:499},maxDevices:3,days:null,quota:null}},
    {version:1,settings:{id:'api-ip',enabled:false,prices:{},maxDevices:null,days:null,quota:null}},
    {version:1,settings:{id:'analysis-credits',enabled:false,prices:{},bundles:{}}}];
  return reply({authEnabled:configured,products:rows.map(row=>publicProduct(row)),
    live:process.env.SPDECODE_PAYMENTS_LIVE==='true'});
});
export const accountSnapshot=request=>safe(async()=>{
  if(!authReady())return reply({user:null,authEnabled:false});
  const session=await accountAuth().api.getSession({headers:request.headers});
  if(!session)return reply({user:null,authEnabled:true});
  const user=session.user,p=await profile(user.id),db=database();
  const [orders,entitlements,credits]=await Promise.all([
    db.query(`SELECT id,product_id,provider,status,quote,created_at,paid_at,payment_live,product_snapshot->>'term' AS term,product_snapshot->>'days' AS days FROM spdecode_shop.orders WHERE account_id=$1 ORDER BY created_at DESC LIMIT 50`,[user.id]),
    db.query(`SELECT id,order_id,product_id,status,token_prefix,allowed_ip,quota,days,expires_at,claimed_at,payment_live FROM spdecode_shop.entitlements WHERE account_id=$1 ORDER BY created_at DESC`,[user.id]),
    creditBalance(user.id,{db})]);
  const googleAvatar=typeof user.image==='string'&&/^https:\/\/lh[3-6]\.googleusercontent\.com\//.test(user.image)?user.image:null;
  return reply({authEnabled:true,live:process.env.SPDECODE_PAYMENTS_LIVE==='true',user:{id:user.id,name:user.name,email:user.email,avatar:p.avatar_data||googleAvatar,googleAvatar,username:p.username,bio:p.bio||'',
    privacyVersion:user.privacyVersion,termsVersion:user.termsVersion},
    orders:orders.rows,entitlements:entitlements.rows,credits});
});
export const profileMutation=request=>safe(async()=>{
  requireOrigin(request);const session=await requireAccount(request,{fresh:true});
  return reply(await editProfile(session.user.id,await jsonBody(request,120000)));
});
export const quoteRequest=request=>safe(async()=>{
  requireOrigin(request);await requireAccount(request);
  const body=await jsonBody(request,2048),row=(await catalog()).find(x=>x.id===body.product);
  if(!row)fail('INVALID_PRODUCT');
  const q=taxQuote(row.settings,body.currency,body.country,body.region||'',await taxRules(),body.term||'base');
  return reply({...q,version:row.version,automaticTax:body.provider==='stripe'&&process.env.STRIPE_AUTOMATIC_TAX==='true'});
});
export const checkoutRequest=request=>safe(async()=>{
  requireOrigin(request);const session=await requireAccount(request);
  return reply(await checkout(session.user.id,await jsonBody(request,4096)));
});
export const claimRequest=request=>safe(async()=>{
  requireOrigin(request);const session=await requireAccount(request,{fresh:true}),body=await jsonBody(request,2048);
  if(!/^[0-9a-f-]{36}$/.test(body.id||'')||typeof body.rotate!=='boolean')fail('INVALID_REQUEST');
  return reply(await claim(session.user.id,body.id,{rotate:body.rotate}));
});
export const captureRequest=request=>safe(async()=>{
  requireOrigin(request);const session=await requireAccount(request),body=await jsonBody(request,2048);
  if(!/^[0-9a-f-]{36}$/.test(body.orderId||''))fail('INVALID_REQUEST');
  const row=(await database().query('SELECT * FROM spdecode_shop.orders WHERE id=$1 AND account_id=$2',[body.orderId,session.user.id])).rows[0];
  if(!row||row.provider!=='paypal')fail('ORDER_NOT_FOUND',404);
  if(row.status!=='pending')return reply({status:row.status});
  await capturePaypal(row);
  // Delivery still waits for the verified, independently re-read webhook.
  return reply({status:'pending'});
});
export const webhookRequest=(request,provider)=>safe(async()=>{
  if(!['stripe','paypal','mercadopago'].includes(provider))fail('NOT_FOUND',404);
  const event=await paymentEvent(provider,request,await boundedBody(request,256*1024));
  return reply(await settle(provider,event));
});
async function admin(request,mutation=false){
  const cfg=adminSettings(),redis=await opsStore();
  const session=await authenticateAdmin(redis,request,cfg);
  if(!session)fail('UNAUTHORIZED',401);
  if(mutation&&!validMutation(request,cfg))fail('CSRF_REJECTED',403);
  return session.sub;
}
export const adminStore=request=>safe(async()=>{
  const actor=await admin(request,request.method==='POST');
  if(request.method==='GET')return reply({products:await catalog(),taxRules:await taxRules(),
    providers:Object.fromEntries(['stripe','paypal','mercadopago'].map(id=>[id,paymentReady(id)])),authEnabled:authReady(),
    live:process.env.SPDECODE_PAYMENTS_LIVE==='true'});
  const body=await jsonBody(request,16*1024),db=database();
  if(body.action==='product'){
    const product=validateProduct(body.product);
    if(!Number.isSafeInteger(body.version))fail('INVALID_VERSION');
    await transaction(async client=>{
      const result=await client.query(`UPDATE spdecode_shop.products SET settings=$2,version=version+1,updated_at=now() WHERE id=$1 AND version=$3 RETURNING id`,
        [product.id,product,body.version]);if(!result.rowCount)fail('PRODUCT_CHANGED',409);
      await client.query('INSERT INTO spdecode_shop.audit(actor_id,action,resource_id) VALUES($1,$2,$3)',[actor,'product_updated',product.id]);
    },db);
  }else if(body.action==='tax-rules'){
    if(!Array.isArray(body.rules)||body.rules.length>100||body.rules.some(r=>
      !/^[A-Z]{2}$/.test(r.country||'')||!/^([A-Z0-9-]{1,12}|\*)$/.test(r.region||'')||r.reviewed!==true||
      !Number.isInteger(r.rateBps)||r.rateBps<0||r.rateBps>3000||typeof r.label!=='string'||r.label.length>48||
      (r.stripeTaxRate!==undefined&&!/^txr_[A-Za-z0-9]+$/.test(r.stripeTaxRate))))fail('INVALID_TAX_RULES');
    if(new Set(body.rules.map(r=>r.country+':'+r.region)).size!==body.rules.length)fail('DUPLICATE_TAX_RULE');
    await transaction(async client=>{
      await client.query("UPDATE spdecode_shop.settings SET value=$1,updated_at=now() WHERE id='tax-rules'",[JSON.stringify(body.rules)]);
      await client.query('INSERT INTO spdecode_shop.audit(actor_id,action,resource_id) VALUES($1,$2,$3)',[actor,'tax_rules_updated','tax-rules']);
    },db);
  }else fail('INVALID_REQUEST');
  return reply({saved:true});
});
export const commercialDecode=request=>safe(async()=>{
  if(process.env.SPDECODE_COMMERCIAL_API_ENABLED!=='true'||process.env.CLOUD_TRUST_PROXY!=='true')fail('SERVICE_UNAVAILABLE',503);
  const auth=request.headers.get('authorization')||'';
  if(!/^Bearer spd_api_[A-Za-z0-9_-]{43}$/.test(auth))fail('UNAUTHORIZED',401);
  await checkApiKey(auth.slice(7),request.headers.get('x-real-ip'));
  const body=await jsonBody(request,12*1024*1024);
  if(!body||Object.keys(body).some(k=>!['format','dataBase64','credentials'].includes(k))||
     typeof body.format!=='string'||! /^[\p{L}\p{N}][\p{L}\p{N}._-]{0,63}$/u.test(body.format)||typeof body.dataBase64!=='string'||
     body.dataBase64.length>Math.ceil(8*1024*1024/3)*4||!/^[A-Za-z0-9+/]+={0,2}$/.test(body.dataBase64)||
     Buffer.from(body.dataBase64,'base64').toString('base64')!==body.dataBase64)fail('INVALID_INPUT');
  const {publicFormats}=await import('../file-format-catalog.mjs');
  const format=publicFormats().find(f=>f.suffix===body.format);if(!format)fail('UNSUPPORTED_FORMAT');
  if(body.credentials!==undefined){
    if(!body.credentials||typeof body.credentials!=='object'||Array.isArray(body.credentials)||
      Object.entries(body.credentials).some(([k,v])=>!format.credentialFields?.includes(k)||typeof v!=='string'||v.length>16384))fail('INVALID_CREDENTIALS');
  }
  const reservation=await useApiKey(auth.slice(7),request.headers.get('x-real-ip'));
  let redis,slot=false;const requestId=randomUUID(),slotKey='shop-'+reservation.id;
  try{
    redis=await opsStore();slot=await reserveSlot(redis,slotKey,requestId);
    if(!slot)fail('SERVICE_BUSY',429);
    if(await serviceMaintenanceEnabled(redis,'files'))fail('SERVICE_MAINTENANCE',503);
    const {fetchWorker}=await import('../c3-gateway.mjs');
    const result=await fetchWorker('file',body,{workerToken:process.env.CLOUD_WORKER_TOKEN});
    if(result.status!==200)await releaseApiUsage(reservation);else await completeApiUsage(reservation);
    result.headers.set('X-SPDecode-Quota-Remaining',String(reservation.remaining));return result;
  }catch(e){await releaseApiUsage(reservation);throw e;}
  finally{if(slot)await releaseSlot(redis,slotKey,requestId).catch(()=>{});}
});
