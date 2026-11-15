import {isIP,BlockList} from "node:net";
const nonPublicV4=new BlockList();
for(const [ip,prefix] of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],
  ['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.88.99.0',24],
  ['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]])nonPublicV4.addSubnet(ip,prefix,'ipv4');
export class ShopError extends Error {
  constructor(code,status=400){super(code);this.code=code;this.status=status;}
}
export const fail=(code,status=400)=>{throw new ShopError(code,status);};
export function siteOrigin(env=process.env){
  const value=env.CLOUD_SITE_PUBLIC_ORIGIN||"https://spdecode.xyz";
  const u=new URL(value);
  if(u.origin!==value||u.username||u.password||
     (u.protocol!=="https:"&&!(env.NODE_ENV!=="production"&&u.hostname==="localhost")))fail("SITE_NOT_CONFIGURED",503);
  return value;
}
export const authReady=(e=process.env)=>e.SPDECODE_ACCOUNTS_ENABLED==="true"&&
  !!e.SPDECODE_DATABASE_URL&&e.BETTER_AUTH_SECRET?.length>=32&&
  !!e.GOOGLE_CLIENT_ID&&!!e.GOOGLE_CLIENT_SECRET;
export function providerConfigured(id,e=process.env){
  const live=e.SPDECODE_PAYMENTS_LIVE==='true';
  return ({stripe:new RegExp('^(sk|rk)_'+(live?'live':'test')+'_').test(e.STRIPE_SECRET_KEY||'')&&!!e.STRIPE_WEBHOOK_SECRET,
    paypal:!!e.PAYPAL_CLIENT_ID&&!!e.PAYPAL_CLIENT_SECRET&&!!e.PAYPAL_WEBHOOK_ID,
    mercadopago:(e.MERCADOPAGO_ACCESS_TOKEN||'').startsWith(live?'APP_USR-':'TEST-')&&!!e.MERCADOPAGO_WEBHOOK_SECRET})[id]===true;
}
export function paymentReady(id,e=process.env){
  return e.SPDECODE_STORE_ENABLED==='true'&&authReady(e)&&e.SPDECODE_SHOP_TOKEN_KEY?.length>=32&&providerConfigured(id,e);
}
export function publicIp(value){
  if(typeof value!=="string"||!isIP(value)||value.includes("%"))return null;
  const lower=value.toLowerCase();
  if(isIP(value)===4){
    if(nonPublicV4.check(value,'ipv4'))return null;
    return value;
  }
  // Commercial IPv6 must be global unicast; reject mapped IPv4 and local ranges.
  if(!/^[23]/.test(lower)||lower.startsWith('2001:db8:'))return null;
  return new URL('http://['+lower+']/').hostname.slice(1,-1);
}
export async function boundedBody(request,maximum=16*1024){
  const reader=request.body?.getReader();if(!reader)fail("INVALID_REQUEST");
  let size=0;const parts=[];
  try{for(;;){const item=await reader.read();if(item.done)break;
    size+=item.value.byteLength;if(size>maximum){await reader.cancel();fail("INPUT_TOO_LARGE",413);}
    parts.push(Buffer.from(item.value));}}
  finally{reader.releaseLock();}
  return Buffer.concat(parts);
}
export async function jsonBody(request,maximum){
  if(request.headers.get('content-type')?.split(';')[0]!=="application/json")fail("INVALID_REQUEST");
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await boundedBody(request,maximum)));}
  catch(e){if(e instanceof ShopError)throw e;fail("INVALID_REQUEST");}
}
export function requireOrigin(request){
  if(request.headers.get('origin')!==siteOrigin()||
     ![null,'same-origin'].includes(request.headers.get('sec-fetch-site')))fail("CSRF_REJECTED",403);
}
export function reply(body,status=200){return Response.json(body,{status,headers:{
  'Cache-Control':'private, no-store, max-age=0','X-Content-Type-Options':'nosniff'}});}
export async function safe(action){try{return await action();}
  catch(e){return reply({error:{code:e instanceof ShopError?e.code:'SERVICE_UNAVAILABLE'}},e instanceof ShopError?e.status:503);}}
