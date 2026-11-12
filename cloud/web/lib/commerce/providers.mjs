import Stripe from 'stripe';
import {createHmac,timingSafeEqual} from 'node:crypto';
import {siteOrigin,fail,paymentReady,providerConfigured} from './config.mjs';
const paypalBase=()=>process.env.SPDECODE_PAYMENTS_LIVE==='true'?'https://api-m.paypal.com':'https://api-m.sandbox.paypal.com';
const money=n=>(n/100).toFixed(2);
const cents=value=>{
  if(typeof value!=='string'||!/^\d{1,8}(\.\d{1,2})?$/.test(value))fail('PAYMENT_AMOUNT_INVALID');
  return Number(value.split('.')[0])*100+Number((value.split('.')[1]||'').padEnd(2,'0'));
};
export async function providerJSON(url,options={},fetchImpl=fetch){
  const origin=new URL(url).origin;
  if(!['https://api-m.paypal.com','https://api-m.sandbox.paypal.com','https://api.mercadopago.com'].includes(origin))fail('UNSAFE_PAYMENT_ORIGIN',503);
  const response=await fetchImpl(url,{...options,redirect:'error',signal:AbortSignal.timeout(15000)});
  if(!response.ok)fail('PAYMENT_PROVIDER_UNAVAILABLE',502);
  const reader=response.body?.getReader();let raw='',size=0;
  if(reader){const chunks=[];try{for(;;){const {done,value}=await reader.read();if(done)break;
    size+=value.byteLength;if(size>1024*1024){await reader.cancel();fail('INVALID_PAYMENT_RESPONSE',502);}chunks.push(value);}}
    finally{reader.releaseLock();}raw=Buffer.concat(chunks).toString('utf8');}
  else raw=await response.text();
  if(Buffer.byteLength(raw)>1024*1024)fail('INVALID_PAYMENT_RESPONSE',502);
  try{return JSON.parse(raw);}catch{fail('INVALID_PAYMENT_RESPONSE',502);}
}
async function paypalToken(fetchImpl){
  const data=await providerJSON(paypalBase()+'/v1/oauth2/token',{method:'POST',
    headers:{Authorization:'Basic '+Buffer.from(process.env.PAYPAL_CLIENT_ID+':'+process.env.PAYPAL_CLIENT_SECRET).toString('base64'),
      'Content-Type':'application/x-www-form-urlencoded'},body:'grant_type=client_credentials'},fetchImpl);
  if(typeof data.access_token!=='string')fail('INVALID_PAYMENT_RESPONSE',502);return data.access_token;
}
async function paypal(path,body,fetchImpl,requestId){
  const token=await paypalToken(fetchImpl);
  return providerJSON(paypalBase()+path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+token,
    'Content-Type':'application/json',...(requestId?{'PayPal-Request-Id':requestId}:{})},...(body?{body:JSON.stringify(body)}:{})},fetchImpl);
}
const mp=(path,body,fetchImpl,requestId)=>providerJSON('https://api.mercadopago.com'+path,{
  method:body?'POST':'GET',headers:{Authorization:'Bearer '+process.env.MERCADOPAGO_ACCESS_TOKEN,
    'Content-Type':'application/json',...(requestId?{'X-Idempotency-Key':requestId}:{})},...(body?{body:JSON.stringify(body)}:{})},fetchImpl);
const stripe=()=>new Stripe(process.env.STRIPE_SECRET_KEY,{timeout:15000,maxNetworkRetries:1});
export function allowedCheckout(id,value){
  try{const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password)return false;
    return ({stripe:['checkout.stripe.com'],paypal:['www.paypal.com','www.sandbox.paypal.com'],
      mercadopago:['www.mercadopago.com.mx','www.mercadopago.com','sandbox.mercadopago.com.mx']})[id]?.includes(u.hostname)===true;
  }catch{return false;}
}
export async function startPayment(order,{fetchImpl=fetch,stripeClient}={}){
  if(!paymentReady(order.provider))fail('PAYMENT_METHOD_UNAVAILABLE',409);
  if(order.provider==='stripe'&&!new RegExp('^(sk|rk)_'+
    (process.env.SPDECODE_PAYMENTS_LIVE==='true'?'live':'test')+'_').test(process.env.STRIPE_SECRET_KEY))fail('PAYMENT_MODE_MISMATCH',503);
  const origin=siteOrigin(),success=origin+'/orders?order='+order.id,
    cancel=origin+'/store?cancelled='+order.id;
  const name=order.product_id==='analysis-credits'?'SP-DECODE · Créditos de análisis ('+order.product_snapshot.credits+')':order.product_id==='offline-3'?'SP-DECODE Offline · 3 dispositivos':'SP-DECODE API';
  const q=order.quote;let id,url;
  if(order.provider==='stripe'){
    const automatic=process.env.STRIPE_AUTOMATIC_TAX==='true';
    if(!automatic&&q.tax>0&&!q.stripeTaxRate)fail('TAX_NOT_CONFIGURED',409);
    const session=await (stripeClient||stripe()).checkout.sessions.create({mode:'payment',
      client_reference_id:order.id,metadata:{orderId:order.id},
      line_items:[{price_data:{currency:q.currency.toLowerCase(),unit_amount:q.subtotal,
        product_data:{name}},quantity:1,...(!automatic&&q.stripeTaxRate?{tax_rates:[q.stripeTaxRate]}:{})}],
      automatic_tax:{enabled:automatic},billing_address_collection:'required',
      success_url:success,cancel_url:cancel}, {idempotencyKey:order.id});
    id=session.id;url=session.url;
  }else if(order.provider==='paypal'){
    const data=await paypal('/v2/checkout/orders',{intent:'CAPTURE',purchase_units:[{reference_id:order.id,
      custom_id:order.id,description:name,amount:{currency_code:q.currency,value:money(q.total),
        breakdown:{item_total:{currency_code:q.currency,value:money(q.subtotal)},tax_total:{currency_code:q.currency,value:money(q.tax)}}},
      items:[{name,quantity:'1',category:'DIGITAL_GOODS',unit_amount:{currency_code:q.currency,value:money(q.subtotal)},
        tax:{currency_code:q.currency,value:money(q.tax)}}]}],
      payment_source:{paypal:{experience_context:{return_url:success+'&provider=paypal',cancel_url:cancel,
        user_action:'PAY_NOW',shipping_preference:'NO_SHIPPING'}}}},fetchImpl,order.id);
    id=data.id;url=data.links?.find(x=>['payer-action','approve'].includes(x.rel))?.href;
  }else{
    if(q.currency!=='MXN')fail('CURRENCY_UNAVAILABLE');
    const data=await mp('/checkout/preferences',{external_reference:order.id,
      items:[{id:order.product_id,title:name,quantity:1,currency_id:q.currency,unit_price:q.total/100}],
      back_urls:{success,pending:success,failure:cancel},auto_return:'approved',
      notification_url:origin+'/api/store/webhooks/mercadopago',metadata:{order_id:order.id},
      statement_descriptor:'SPDECODE'},fetchImpl,order.id);
    id=data.id;url=process.env.SPDECODE_PAYMENTS_LIVE==='true'?data.init_point:data.sandbox_init_point;
  }
  if(typeof id!=='string'||id.length>180||!allowedCheckout(order.provider,url))fail('INVALID_PAYMENT_RESPONSE',502);
  return {id,url};
}
export async function capturePaypal(order,{fetchImpl=fetch}={}){
  if(!/^[A-Za-z0-9-]{8,180}$/.test(order.provider_id||''))fail('INVALID_PAYMENT');
  // This server-to-server capture never treats a browser return as proof.
  return paypal('/v2/checkout/orders/'+order.provider_id+'/capture',{},fetchImpl,'capture-'+order.id);
}
export function verifyMpSignature(request,raw,{now=Date.now(),secret=process.env.MERCADOPAGO_WEBHOOK_SECRET}={}){
  const signature=request.headers.get('x-signature')||'',requestId=request.headers.get('x-request-id')||'';
  const parts=Object.fromEntries(signature.split(',').map(x=>x.trim().split('=')));
  const id=new URL(request.url).searchParams.get('data.id');
  if(!secret||!id||!/^\d{1,20}$/.test(id)||!requestId||requestId.length>200||
    !/^\d{10,13}$/.test(parts.ts||'')||!/^[a-f0-9]{64}$/.test(parts.v1||''))fail('WEBHOOK_REJECTED',401);
  const stamp=Number(parts.ts)*(parts.ts.length===10?1000:1);
  if(Math.abs(now-stamp)>300000)fail('WEBHOOK_REJECTED',401);
  const expected=createHmac('sha256',secret).update(`id:${id.toLowerCase()};request-id:${requestId};ts:${parts.ts};`).digest();
  if(!timingSafeEqual(expected,Buffer.from(parts.v1,'hex')))fail('WEBHOOK_REJECTED',401);
  const body=JSON.parse(raw);if(String(body.data?.id)!==id||body.type!=='payment')fail('WEBHOOK_REJECTED',401);
  return id;
}
export async function paymentEvent(provider,request,raw,{fetchImpl=fetch,stripeClient}={}){
  // Pausing new sales must not prevent refunds/disputes or pending payments
  // from being processed for purchases already made.
  if(!providerConfigured(provider))fail('PAYMENT_METHOD_UNAVAILABLE',503);
  if(provider==='stripe'){
    const client=stripeClient||stripe();let event;
    try{event=client.webhooks.constructEvent(raw,request.headers.get('stripe-signature'),process.env.STRIPE_WEBHOOK_SECRET,300);}
    catch{fail('WEBHOOK_REJECTED',401);}
    if(!['checkout.session.completed','checkout.session.async_payment_succeeded','charge.refunded','charge.dispute.created'].includes(event.type))return null;
    if(event.type.startsWith('checkout.session.')){
      const session=await client.checkout.sessions.retrieve(event.data.object.id);
      if(session.livemode!==(process.env.SPDECODE_PAYMENTS_LIVE==='true'))fail('PAYMENT_MODE_MISMATCH',409);
      if(session.payment_status!=='paid')return null;
      return {eventId:event.id,type:'paid',live:session.livemode,orderId:session.client_reference_id,providerId:session.id,
        currency:session.currency?.toUpperCase(),subtotal:session.amount_subtotal,total:session.amount_total,
        tax:session.total_details?.amount_tax||0,automaticTax:session.automatic_tax?.enabled===true,
        country:session.customer_details?.address?.country,region:session.customer_details?.address?.state};
    }
    const charge=event.type==='charge.refunded'?event.data.object:await client.charges.retrieve(event.data.object.charge);
    const sessions=await client.checkout.sessions.list({payment_intent:charge.payment_intent,limit:1});
    const session=sessions.data[0];if(!session)return null;
    return {eventId:event.id,type:event.type==='charge.refunded'?'refunded':'disputed',live:session.livemode,
      orderId:session.client_reference_id,providerId:session.id};
  }
  if(provider==='paypal'){
    let event;try{event=JSON.parse(raw);}catch{fail('WEBHOOK_REJECTED',401);}
    const verdict=await paypal('/v1/notifications/verify-webhook-signature',{
      auth_algo:request.headers.get('paypal-auth-algo'),cert_url:request.headers.get('paypal-cert-url'),
      transmission_id:request.headers.get('paypal-transmission-id'),transmission_sig:request.headers.get('paypal-transmission-sig'),
      transmission_time:request.headers.get('paypal-transmission-time'),webhook_id:process.env.PAYPAL_WEBHOOK_ID,webhook_event:event},fetchImpl);
    if(verdict.verification_status!=='SUCCESS')fail('WEBHOOK_REJECTED',401);
    if(!['PAYMENT.CAPTURE.COMPLETED','PAYMENT.CAPTURE.REFUNDED','CUSTOMER.DISPUTE.CREATED'].includes(event.event_type))return null;
    let orderId=event.resource?.supplementary_data?.related_ids?.order_id;
    if(!orderId&&event.event_type!=='PAYMENT.CAPTURE.COMPLETED'){
      let captureId=event.resource?.disputed_transactions?.[0]?.seller_transaction_id;
      if(!captureId){
        const up=event.resource?.links?.find(link=>link.rel==='up')?.href;
        try{const u=new URL(up),hosts=process.env.SPDECODE_PAYMENTS_LIVE==='true'?
          ['https://api-m.paypal.com','https://api.paypal.com']:['https://api-m.sandbox.paypal.com','https://api.sandbox.paypal.com'];
          if(hosts.includes(u.origin))captureId=/^\/v2\/payments\/captures\/([A-Za-z0-9-]{8,180})$/.exec(u.pathname)?.[1];}catch{}
      }
      if(/^[A-Za-z0-9-]{8,180}$/.test(captureId||'')){
        const capture=await paypal('/v2/payments/captures/'+captureId,null,fetchImpl);
        orderId=capture.supplementary_data?.related_ids?.order_id;
      }
    }
    if(!/^[A-Za-z0-9-]{8,180}$/.test(orderId||''))return null;
    const data=await paypal('/v2/checkout/orders/'+orderId,null,fetchImpl);
    const unit=data.purchase_units?.[0],capture=unit?.payments?.captures?.find(x=>x.status==='COMPLETED');
    if(event.event_type==='PAYMENT.CAPTURE.COMPLETED'&&!capture)return null;
    return {eventId:event.id,live:process.env.SPDECODE_PAYMENTS_LIVE==='true',type:event.event_type==='PAYMENT.CAPTURE.COMPLETED'?'paid':
      event.event_type==='PAYMENT.CAPTURE.REFUNDED'?'refunded':'disputed',orderId:unit?.custom_id,
      providerId:data.id,currency:capture?.amount?.currency_code,total:capture?cents(capture.amount.value):null};
  }
  const id=verifyMpSignature(request,raw),data=await mp('/v1/payments/'+id,null,fetchImpl);
  if(!['approved','refunded','charged_back'].includes(data.status))return null;
  if(data.live_mode!==(process.env.SPDECODE_PAYMENTS_LIVE==='true'))fail('PAYMENT_MODE_MISMATCH',409);
  const merchantOrderId=String(data.order?.id||'');
  if(!/^\d{1,20}$/.test(merchantOrderId))fail('INVALID_PAYMENT_RESPONSE',502);
  const merchantOrder=await mp('/merchant_orders/'+merchantOrderId,null,fetchImpl);
  // The payment ID is the final object; preference_id is not an authentication token.
  const type=data.status==='approved'&&Number(data.transaction_amount_refunded)>0?'refunded':
    ({approved:'paid',refunded:'refunded',charged_back:'disputed'})[data.status];
  return {eventId:id+':'+type,type,live:data.live_mode,
    orderId:data.external_reference,providerId:String(merchantOrder.preference_id||''),paymentId:id,
    currency:data.currency_id,total:cents(Number(data.transaction_amount).toFixed(2))};
}
