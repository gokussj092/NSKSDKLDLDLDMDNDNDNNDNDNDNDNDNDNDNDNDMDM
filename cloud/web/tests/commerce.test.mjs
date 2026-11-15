import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomUUID,createHmac} from 'node:crypto';
import {getMigrations} from 'better-auth/db/migration';
import {PGlite} from '@electric-sql/pglite';
import {Pool} from 'pg';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {taxQuote,validatePurchase} from '../lib/commerce/catalog.mjs';
import {publicIp,paymentReady} from '../lib/commerce/config.mjs';
import {editProfile} from '../lib/commerce/profile.mjs';
import {checkout,settle,claim,useApiKey,releaseApiUsage} from '../lib/commerce/orders.mjs';
import {creditBalance,reserveCredit,completeCredit,releaseCredit} from '../lib/commerce/credits.mjs';
import {verifyMpSignature,allowedCheckout,paymentEvent} from '../lib/commerce/providers.mjs';
import {estimateRetail} from '../lib/commerce/pricing.mjs';
import Stripe from 'stripe';
let db,embedded,auth,apiVersion;const user=randomUUID(),other=randomUUID();
const env={...process.env,NODE_ENV:'test',SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_STORE_ENABLED:'true',
  SPDECODE_COMMERCIAL_API_ENABLED:'true',SPDECODE_OFFLINE_LICENSE_READY:'true',
  CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',SPDECODE_DATABASE_URL:'postgres://test-only',
  SPDECODE_PAYMENTS_LIVE:'false',
  BETTER_AUTH_SECRET:'synthetic-test-secret-'.repeat(3),GOOGLE_CLIENT_ID:'synthetic.apps.googleusercontent.com',
  GOOGLE_CLIENT_SECRET:'synthetic-test-only',STRIPE_SECRET_KEY:'sk_test_synthetic',STRIPE_WEBHOOK_SECRET:'whsec_synthetic',
  SPDECODE_SHOP_TOKEN_KEY:'synthetic-token-key-'.repeat(3)};
Object.assign(env,{PAYPAL_CLIENT_ID:'synthetic-client',PAYPAL_CLIENT_SECRET:'synthetic-secret',PAYPAL_WEBHOOK_ID:'synthetic-webhook',
  MERCADOPAGO_ACCESS_TOKEN:'TEST-synthetic',MERCADOPAGO_WEBHOOK_SECRET:'synthetic-mp-webhook'});
Object.assign(process.env,env);
before(async()=>{
  if(process.env.SPDECODE_SHOP_TEST_DATABASE_URL){
    const target=new URL(process.env.SPDECODE_SHOP_TEST_DATABASE_URL);
    if(!/(^test_|_test$)/.test(target.pathname.slice(1)))throw Error('Use a dedicated *_test or test_* database');
    db=new Pool({connectionString:process.env.SPDECODE_SHOP_TEST_DATABASE_URL,max:6});
  }
  else{
    embedded=new PGlite();
    const query=async(sql,params=[])=>{const result=await embedded.query(sql,params);return {rows:result.rows,rowCount:result.affectedRows??result.rows.length};};
    db={query,connect:async()=>({query,release(){}})};
  }
  auth=makeAuth(db,env);const migration=await getMigrations(auth.options);await migration.runMigrations();
  const sql=await readFile(new URL('../sql/002_shop.sql',import.meta.url),'utf8');
  if(embedded)await embedded.exec(sql);else await db.query(sql);
  const notices=await readFile(new URL('../sql/008_account_notifications.sql',import.meta.url),'utf8');
  if(embedded)await embedded.exec(notices);else await db.query(notices);
  for(const id of [user,other])await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
    VALUES($1,'Synthetic buyer',$2,true,now(),now())`,[id,id+'@example.invalid']);
  await db.query(`UPDATE spdecode_shop.settings SET value=$1 WHERE id='tax-rules'`,[JSON.stringify([{country:'MX',region:'*',rateBps:1600,label:'IVA',reviewed:true}])]);
  await db.query(`UPDATE spdecode_shop.products SET settings=$1 WHERE id='api-ip'`,[JSON.stringify({id:'api-ip',enabled:true,prices:{USD:499,MXN:9900},quota:2,days:30})]);
  apiVersion=(await db.query("SELECT version FROM spdecode_shop.products WHERE id='api-ip'")).rows[0].version;
});
after(async()=>{if(embedded)await embedded.close();else await db?.end();});
test('checkout amounts are integer cents, taxes are separate, and currency/country require configured rules',()=>{
 const p={prices:{USD:499}},rules=[{country:'MX',region:'*',rateBps:1600,label:'IVA',reviewed:true}];
 const q=taxQuote(p,'USD','MX','BC',rules);assert.equal(q.subtotal,499);assert.equal(q.tax,80);assert.equal(q.total,579);
 assert.throws(()=>taxQuote(p,'USD','US','',rules),/TAX_NOT_CONFIGURED/);
 assert.throws(()=>taxQuote(p,'EUR','MX','',rules),/CURRENCY_UNAVAILABLE/);
 assert.equal(publicIp('127.0.0.1'),null);assert.equal(publicIp('10.0.0.1'),null);
 assert.equal(publicIp('2001:db8::1'),null);assert.equal(publicIp('1.1.1.1'),'1.1.1.1');
 assert.equal(allowedCheckout('stripe','https://checkout.stripe.com/c/pay/test'),true);
 assert.equal(allowedCheckout('stripe','https://checkout.stripe.com.evil.invalid/test'),false);
});
test('unique usernames are canonical, transactional and reserved after a change',async()=>{
 const handle='buyer_'+user.slice(0,8);await editProfile(user,{name:'Buyer A',username:handle.toUpperCase()},db);
 await assert.rejects(editProfile(other,{name:'Buyer B',username:handle},db),/USERNAME_TAKEN/);
 await assert.rejects(editProfile(other,{name:'Buyer B',username:'admin'},db),/INVALID_PROFILE/);
 assert.equal((await db.query('SELECT username FROM spdecode_shop.profiles WHERE account_id=$1',[user])).rows[0].username,handle);
});
test('orders use authoritative prices, provider idempotency and verified payment before one entitlement',async()=>{
 const body={product:'api-ip',provider:'stripe',currency:'USD',country:'MX',region:'BC',allowedIp:'1.1.1.1',
   version:apiVersion,idempotencyKey:randomUUID(),acceptedTerms:'2026-11-10'};
 let calls=0;const start=async row=>{calls++;return {id:'cs_test_'+row.id,url:'https://checkout.stripe.com/c/pay/'+row.id};};
 const order=await checkout(user,body,{db,start});
 assert.equal(calls,1);assert.equal((await checkout(user,body,{db,start})).orderId,order.orderId);assert.equal(calls,1);
 assert.equal((await db.query('SELECT * FROM spdecode_shop.entitlements WHERE order_id=$1',[order.orderId])).rowCount,0);
 await assert.rejects(checkout(user,{...body,currency:'MXN'},{db,start}),/IDEMPOTENCY_CONFLICT/);
 const event={eventId:randomUUID(),type:'paid',live:false,orderId:order.orderId,providerId:'cs_test_'+order.orderId,currency:'USD',total:579};
 await assert.rejects(settle('stripe',{...event,total:1},{db}),/PAYMENT_AMOUNT_MISMATCH/);
 await assert.rejects(settle('stripe',{...event,live:true},{db}),/PAYMENT_MODE_MISMATCH/);
 await settle('stripe',event,{db});await settle('stripe',event,{db});await settle('stripe',{...event,eventId:randomUUID()},{db});
 const rows=(await db.query('SELECT * FROM spdecode_shop.entitlements WHERE order_id=$1',[order.orderId])).rows;
 assert.equal(rows.length,1);
 const key=await claim(user,rows[0].id,{db});assert.match(key.token,/^spd_api_/);
 await assert.rejects(claim(user,rows[0].id,{db}),/ALREADY_REVEALED/);
 await assert.rejects(claim(other,rows[0].id,{db}),/PURCHASE_NOT_AVAILABLE/);
 await assert.rejects(useApiKey(key.token,'8.8.8.8',{db}),/IP_NOT_ALLOWED/);
 const first=await useApiKey(key.token,'1.1.1.1',{db});await useApiKey(key.token,'1.1.1.1',{db});
 await assert.rejects(useApiKey(key.token,'1.1.1.1',{db}),/QUOTA_EXCEEDED/);
 await releaseApiUsage(first,db);await releaseApiUsage(first,db);await useApiKey(key.token,'1.1.1.1',{db});
 await assert.rejects(useApiKey(key.token,'1.1.1.1',{db}),/QUOTA_EXCEEDED/);
 process.env.SPDECODE_PAYMENTS_LIVE='true';
 try{await assert.rejects(useApiKey(key.token,'1.1.1.1',{db}),/UNAUTHORIZED/);
  await assert.rejects(claim(user,rows[0].id,{rotate:true,db}),/PAYMENT_MODE_MISMATCH/);
 }finally{process.env.SPDECODE_PAYMENTS_LIVE='false';}
 const rotated=await claim(user,rows[0].id,{rotate:true,db});assert.notEqual(rotated.token,key.token);
 await assert.rejects(useApiKey(key.token,'1.1.1.1',{db}),/UNAUTHORIZED/);
 await settle('stripe',{...event,eventId:randomUUID(),type:'refunded'},{db});
 await settle('stripe',{...event,eventId:randomUUID()},{db});
 assert.equal((await db.query('SELECT status FROM spdecode_shop.entitlements WHERE id=$1',[rows[0].id])).rows[0].status,'revoked');
 await assert.rejects(useApiKey(rotated.token,'1.1.1.1',{db}),/UNAUTHORIZED/);
});
test('Mercado Pago validates exact signature, ID binding, freshness and constant provider origin',()=>{
 const now=Date.now(),ts=String(now),id='123456789',secret='synthetic-mp-webhook',requestId='test-request';
 const signature=createHmac('sha256',secret).update(`id:${id};request-id:${requestId};ts:${ts};`).digest('hex');
 const req=new Request('http://localhost/api/store/webhooks/mercadopago?data.id='+id,{headers:{'x-signature':`ts=${ts},v1=${signature}`,'x-request-id':requestId}});
 const raw=JSON.stringify({type:'payment',data:{id}});
 assert.equal(verifyMpSignature(req,raw,{now,secret}),id);
 assert.throws(()=>verifyMpSignature(req,raw,{now:now+600000,secret}),/WEBHOOK_REJECTED/);
 assert.throws(()=>verifyMpSignature(req,raw,{now,secret:'wrong'}),/WEBHOOK_REJECTED/);
 assert.throws(()=>verifyMpSignature(req,JSON.stringify({type:'payment',data:{id:'wrong'}}),{now,secret}),/WEBHOOK_REJECTED/);
});
test('Google OAuth uses bound state and rejects foreign callbacks and password registration',async()=>{
 const request=body=>new Request('http://localhost:3000/api/auth/sign-in/social',{method:'POST',
   headers:{Origin:'http://localhost:3000','Content-Type':'application/json'},body:JSON.stringify(body)});
 const start=await auth.handler(request({provider:'google',callbackURL:'/account'}));
 assert.equal(start.status,200);const data=await start.json(),url=new URL(data.url);
 assert.equal(url.origin,'https://accounts.google.com');assert.equal(url.searchParams.get('client_id'),env.GOOGLE_CLIENT_ID);
 assert.ok(url.searchParams.get('state')?.length>20);
 const invalid=await auth.handler(request({provider:'google',callbackURL:'https://evil.invalid/steal'}));
 assert.ok(invalid.status>=400);
 const password=await auth.handler(new Request('http://localhost:3000/api/auth/sign-up/email',{method:'POST',
   headers:{Origin:'http://localhost:3000','Content-Type':'application/json'},body:JSON.stringify({email:'x@example.invalid',password:'synthetic-password-only',name:'Test'})}));
 assert.ok(password.status>=400);
});
test('retail planning uses configured fee estimates without a payment-specific surcharge',()=>{
 const v=estimateRetail(400,{rateBps:400,fixedCents:100,feeTaxBps:1600,salesTaxBps:1600});
 assert.ok(v.retailCents>500);assert.ok(v.estimatedNetCents>=400);
 assert.throws(()=>estimateRetail(400,{rateBps:10000,fixedCents:100}),/INVALID_FEE_ESTIMATE/);
});
test('Stripe webhook signature and independently fetched session bind the paid amount',async()=>{
 const client=new Stripe('sk_test_synthetic');const orderId=randomUUID();
 const payload=JSON.stringify({id:'evt_synthetic',type:'checkout.session.completed',data:{object:{id:'cs_synthetic'}}});
 const header=client.webhooks.generateTestHeaderString({payload,secret:env.STRIPE_WEBHOOK_SECRET});
 const request=signature=>new Request('http://localhost/api/store/webhooks/stripe',{headers:{'stripe-signature':signature}});
 let reads=0;const sdk={webhooks:client.webhooks,checkout:{sessions:{retrieve:async()=>{reads++;return {id:'cs_synthetic',livemode:false,
   payment_status:'paid',client_reference_id:orderId,currency:'usd',amount_subtotal:499,amount_total:579,total_details:{amount_tax:80}};}}}};
 const event=await paymentEvent('stripe',request(header),Buffer.from(payload),{stripeClient:sdk});
 assert.equal(event.orderId,orderId);assert.equal(event.total,579);assert.equal(reads,1);
 await assert.rejects(paymentEvent('stripe',request(header+'bad'),Buffer.from(payload),{stripeClient:sdk}),/WEBHOOK_REJECTED/);
 assert.equal(reads,1);
});
test('PayPal requires remote signature confirmation and re-reads its own order',async()=>{
 const orderId=randomUUID(),raw=Buffer.from(JSON.stringify({id:'WH-SYNTHETIC',event_type:'PAYMENT.CAPTURE.COMPLETED',
  resource:{supplementary_data:{related_ids:{order_id:'PAYPALORDER1234567'}}}}));
 let verified=false,read=false;
 const mock=async(url,opts)=>{
  assert.equal(new URL(url).origin,'https://api-m.sandbox.paypal.com');
  if(url.endsWith('/oauth2/token'))return Response.json({access_token:'synthetic-token'});
  if(url.endsWith('/verify-webhook-signature')){verified=true;return Response.json({verification_status:'SUCCESS'});}
  assert.equal(verified,true);read=true;
  return Response.json({id:'PAYPALORDER1234567',purchase_units:[{custom_id:orderId,payments:{captures:[{status:'COMPLETED',amount:{currency_code:'USD',value:'5.79'}}]}}]});
 };
 const event=await paymentEvent('paypal',new Request('http://localhost/webhook'),raw,{fetchImpl:mock});
 assert.equal(read,true);assert.equal(event.orderId,orderId);assert.equal(event.total,579);
 const rejected=async url=>Response.json(url.endsWith('/oauth2/token')?{access_token:'synthetic'}:{verification_status:'FAILURE'});
 await assert.rejects(paymentEvent('paypal',new Request('http://localhost/webhook'),raw,{fetchImpl:rejected}),/WEBHOOK_REJECTED/);
});
test('PostgreSQL concurrent delivery and key claims remain unique',async t=>{
 if(!process.env.SPDECODE_SHOP_TEST_DATABASE_URL){t.skip('Full concurrency runs against PostgreSQL service in CI; PGlite serializes one connection.');return;}
 const order=await checkout(user,{product:'api-ip',provider:'stripe',currency:'USD',country:'MX',region:'BC',allowedIp:'1.1.1.1',
  version:apiVersion,idempotencyKey:randomUUID(),acceptedTerms:'2026-11-10'},{db,start:async row=>({id:'cs_race_'+row.id,url:'https://checkout.stripe.com/c/pay/'+row.id})});
 const event={type:'paid',live:false,orderId:order.orderId,providerId:'cs_race_'+order.orderId,currency:'USD',total:579};
 await Promise.all(Array.from({length:8},()=>settle('stripe',{...event,eventId:randomUUID()},{db})));
 const item=(await db.query('SELECT id FROM spdecode_shop.entitlements WHERE order_id=$1',[order.orderId])).rows;
 assert.equal(item.length,1);
 const claims=await Promise.allSettled(Array.from({length:8},()=>claim(user,item[0].id,{db})));
 assert.equal(claims.filter(x=>x.status==='fulfilled').length,1);
});

test('pausing sales still processes verified provider events',async()=>{
 const previous=process.env.SPDECODE_STORE_ENABLED;process.env.SPDECODE_STORE_ENABLED='false';
 try{
  assert.equal(paymentReady('stripe'),false);
  const client=new Stripe('sk_test_synthetic');
  const payload=JSON.stringify({id:'evt_paused',type:'checkout.session.completed',data:{object:{id:'cs_paused'}}});
  const signature=client.webhooks.generateTestHeaderString({payload,secret:env.STRIPE_WEBHOOK_SECRET});
  const sdk={webhooks:client.webhooks,checkout:{sessions:{retrieve:async()=>({id:'cs_paused',livemode:false,
   payment_status:'paid',client_reference_id:randomUUID(),currency:'usd',amount_total:579,amount_subtotal:499,total_details:{amount_tax:80}})}}};
  const event=await paymentEvent('stripe',new Request('http://localhost/webhook',{headers:{'stripe-signature':signature}}),Buffer.from(payload),{stripeClient:sdk});
  assert.equal(event.type,'paid');
 }finally{process.env.SPDECODE_STORE_ENABLED=previous;}
});
test('a late payment never recreates access after account deletion',async()=>{
 const id=randomUUID();await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
  VALUES($1,'Deleted buyer',$2,true,now(),now())`,[id,id+'@example.invalid']);
 const order=await checkout(id,{product:'api-ip',provider:'stripe',currency:'USD',country:'MX',region:'BC',allowedIp:'1.1.1.1',
  version:apiVersion,idempotencyKey:randomUUID(),acceptedTerms:'2026-11-10'},{db,start:async row=>({id:'cs_deleted_'+row.id,url:'https://checkout.stripe.com/c/pay/'+row.id})});
 await db.query('DELETE FROM shop_user WHERE id=$1',[id]);
 await settle('stripe',{eventId:randomUUID(),type:'paid',live:false,orderId:order.orderId,providerId:'cs_deleted_'+order.orderId,currency:'USD',total:579},{db});
 const item=(await db.query('SELECT * FROM spdecode_shop.entitlements WHERE order_id=$1',[order.orderId])).rows[0];
 assert.equal(item.status,'revoked');assert.equal(item.allowed_ip,null);
});

test('analysis credits are granted only once by verified payment and released on server failures',async()=>{
 const oldReady=process.env.SPDECODE_ANALYSIS_CREDITS_READY;
 process.env.SPDECODE_ANALYSIS_CREDITS_READY='true';
 try{
  await db.query("UPDATE spdecode_shop.products SET settings=$1,version=1 WHERE id='analysis-credits'",
    [JSON.stringify({id:'analysis-credits',enabled:true,prices:{},
      bundles:{'1c':{USD:399},'5c':{USD:1795},'10c':{USD:3290},'25c':{USD:7475},'50c':{USD:13450},'100c':{USD:23900}}})]);
  const body={product:'analysis-credits',term:'10c',provider:'stripe',currency:'USD',country:'MX',region:'BC',
    version:1,idempotencyKey:randomUUID(),acceptedTerms:'2026-11-10'};
  const order=await checkout(other,body,{db,start:async row=>({id:'cs_credits_'+row.id,url:'https://checkout.stripe.com/c/pay/'+row.id})});
  assert.equal((await creditBalance(other,{db})).balance,0);
  const ev={eventId:randomUUID(),type:'paid',live:false,orderId:order.orderId,providerId:'cs_credits_'+order.orderId,
    currency:'USD',total:3816};
  // 3290 cents + 16% IVA (526).
  await settle('stripe',ev,{db});await settle('stripe',ev,{db});
  let balance=await creditBalance(other,{db});
  assert.equal(balance.available,10);
  assert.equal((await db.query('SELECT COUNT(*)::int AS n FROM spdecode_shop.credit_ledger WHERE order_id=$1',[order.orderId])).rows[0].n,1);
  assert.equal((await db.query('SELECT COUNT(*)::int AS n FROM spdecode_shop.entitlements WHERE order_id=$1',[order.orderId])).rows[0].n,0);
  const job1=randomUUID(),job2=randomUUID();
  await reserveCredit(other,job1,{db});await reserveCredit(other,job1,{db});
  await reserveCredit(other,job2,{db});
  balance=await creditBalance(other,{db});assert.equal(balance.available,8);
  await releaseCredit(other,job1,{db});await releaseCredit(other,job1,{db});
  balance=await creditBalance(other,{db});assert.equal(balance.available,9);
  await completeCredit(other,job2,{db});await completeCredit(other,job2,{db});
  balance=await creditBalance(other,{db});assert.equal(balance.available,9);
  await settle('stripe',{...ev,eventId:randomUUID(),type:'refunded'},{db});
  assert.equal((await creditBalance(other,{db})).available,-1);
  await assert.rejects(reserveCredit(other,randomUUID(),{db}),/INSUFFICIENT_CREDITS/);
  await settle('stripe',{...ev,eventId:randomUUID(),type:'paid'},{db});
  assert.equal((await creditBalance(other,{db})).available,-1);
 }finally{
   if(oldReady===undefined)delete process.env.SPDECODE_ANALYSIS_CREDITS_READY;
   else process.env.SPDECODE_ANALYSIS_CREDITS_READY=oldReady;
 }
});
