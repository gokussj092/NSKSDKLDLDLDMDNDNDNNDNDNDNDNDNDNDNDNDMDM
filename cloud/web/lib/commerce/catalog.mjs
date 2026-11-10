import {fail,publicIp,paymentReady} from './config.mjs';
export const PRODUCT_IDS=['offline-3','api-ip'];
export function validateProduct(value){
  if(!value||!PRODUCT_IDS.includes(value.id)||typeof value.enabled!=='boolean')fail('INVALID_PRODUCT');
  const prices=value.prices;
  if(!prices||typeof prices!=='object'||Array.isArray(prices)||Object.keys(prices).some(k=>!['USD','MXN','EUR'].includes(k))||
     Object.values(prices).some(n=>!Number.isSafeInteger(n)||n<100||n>1000000))fail('INVALID_PRICE');
  if(value.enabled&&!Object.keys(prices).length)fail('PRICE_REQUIRED');
  if(value.id==='api-ip'&&(!Number.isInteger(value.quota)||value.quota<1||value.quota>1000000||
     !Number.isInteger(value.days)||value.days<1||value.days>3650))fail('INVALID_API_PLAN');
  return {id:value.id,enabled:value.enabled,prices,quota:value.id==='api-ip'?value.quota:null,
    days:value.id==='api-ip'?value.days:null,maxDevices:value.id==='offline-3'?3:null};
}
export function productAvailable(product,env=process.env){
  return product.enabled&&env.SPDECODE_STORE_ENABLED==='true'&&
    (product.id==='api-ip'?env.SPDECODE_COMMERCIAL_API_ENABLED==='true':env.SPDECODE_OFFLINE_LICENSE_READY==='true');
}
export function publicProduct(row,env=process.env){
  const data=typeof row.settings==='string'?JSON.parse(row.settings):row.settings;
  const providers=['stripe','paypal','mercadopago'].filter(id=>paymentReady(id,env));
  return {...data,version:row.version,available:productAvailable(data,env)&&providers.length>0,providers};
}
export function taxQuote(product,currency,country,region,rules){
  if(!/^[A-Z]{2}$/.test(country)||typeof region!=='string'||!/^[A-Z0-9-]{0,12}$/.test(region))fail('INVALID_LOCATION');
  const subtotal=product.prices[currency];if(!subtotal)fail('CURRENCY_UNAVAILABLE');
  const rule=rules.find(r=>r.country===country&&r.region===region)||rules.find(r=>r.country===country&&r.region==='*');
  if(!rule||!rule.reviewed||!Number.isInteger(rule.rateBps)||rule.rateBps<0||rule.rateBps>3000)fail('TAX_NOT_CONFIGURED',409);
  const tax=Math.round(subtotal*rule.rateBps/10000);
  return {currency,subtotal,tax,total:subtotal+tax,country,region,taxLabel:rule.label||'Tax',taxRateBps:rule.rateBps,
    ...(rule.stripeTaxRate?{stripeTaxRate:rule.stripeTaxRate}:{})};
}
export function validatePurchase(body){
  if(!body||!PRODUCT_IDS.includes(body.product)||!['stripe','paypal','mercadopago'].includes(body.provider)||
    !['USD','MXN','EUR'].includes(body.currency)||!Number.isSafeInteger(body.version)||
    !/^[0-9a-f-]{36}$/.test(body.idempotencyKey||'')||body.acceptedTerms!=='2026-11-10')fail('INVALID_REQUEST');
  const ip=body.product==='api-ip'?publicIp(body.allowedIp):null;
  if(body.product==='api-ip'&&!ip)fail('PUBLIC_IP_REQUIRED');
  if(body.provider==='mercadopago'&&body.currency!=='MXN')fail('CURRENCY_UNAVAILABLE');
  return {...body,allowedIp:ip};
}
