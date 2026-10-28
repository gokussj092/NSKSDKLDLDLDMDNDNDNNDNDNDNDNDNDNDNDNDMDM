import {randomUUID} from 'node:crypto';
import {adminSettings,authenticateAdmin,validMutation} from './c6-admin-auth.mjs';
import {opsStore} from './c6-ops-store.mjs';
import {store,throttle} from './c3-store.mjs';
import {boundRequestClaims} from './v2-bound-request.mjs';
import {pushAccount,pushNotice} from './notice-push.mjs';
const KEY='spnotice:feed:v1',LOCK='spnotice:publish-lock';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const reply=(body,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}});
const clean=(s,max)=>typeof s==='string'&&s.trim().length>0&&s===s.trim()&&s.length<=max&&!/[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(s);
export function validNotice(n,now=Date.now()) {
  return n && UUID.test(n.id) && clean(n.title,80) && clean(n.body,500) &&
    Number.isSafeInteger(n.createdAt) && n.createdAt<=now+5000 && n.createdAt>=now-7*86400000 &&
    Number.isSafeInteger(n.expiresAt) && n.expiresAt>now && n.expiresAt<=n.createdAt+7*86400000;
}
async function notices(redis,now=Date.now()) {
  const raw=await redis.get(KEY);if(!raw)return [];
  if(raw.length>100000)throw Error('FEED_INVALID');
  const list=JSON.parse(raw);if(!Array.isArray(list)||list.length>20)throw Error('FEED_INVALID');
  return list.filter(n=>validNotice(n,now));
}
export async function notificationFeedRequest(request,{storeProvider=store}={}) {
  if(!boundRequestClaims(request))return reply({error:{code:'UNAUTHORIZED'}},401);
  try {
    const text=await request.text();if(text.length>16 || text.trim()!=='{}')return reply({error:{code:'INVALID_REQUEST'}},400);
    return reply({notices:await notices(await storeProvider())});
  }catch{return reply({error:{code:'SERVICE_UNAVAILABLE'}},503);}
}
export async function adminNotices(request,{storeProvider=opsStore,push=pushNotice}={}) {
  const cfg=adminSettings();if(!cfg.enabled)return reply({code:'ADMIN_DISABLED'},503);
  if(request.method==='POST'&&!validMutation(request,cfg))return reply({code:'CSRF_REJECTED'},403);
  let redis,lock;
  try {
    redis=await storeProvider();
    if(!await authenticateAdmin(redis,request,cfg))return reply({code:'UNAUTHORIZED'},401);
    if(request.method==='GET')return reply({notices:await notices(redis),pushConfigured:!!pushAccount()});
    if(request.method!=='POST')return reply({code:'METHOD_NOT_ALLOWED'},405);
    // Bounded stream even when Content-Length is absent or dishonest.
    const reader=request.body?.getReader();if(!reader)return reply({code:'INVALID_REQUEST'},400);
    const parts=[];let size=0;
    try {for(;;){const {value,done}=await reader.read();if(done)break;
      size+=value.length;if(size>4096){await reader.cancel();return reply({code:'INVALID_REQUEST'},400);}parts.push(Buffer.from(value));}}
    finally{reader.releaseLock();}
    let input;try{input=JSON.parse(Buffer.concat(parts).toString('utf8'));}catch{return reply({code:'INVALID_REQUEST'},400);}
    if(!input||Object.keys(input).sort().join(',')!=='body,id,title'||!UUID.test(input.id)||!clean(input.title,80)||!clean(input.body,500))
      return reply({code:'INVALID_REQUEST'},400);
    if(!await throttle(redis,'spnotice:publish-rate',5,60))return reply({code:'RATE_LIMITED'},429);
    lock=randomUUID();if(await redis.set(LOCK,lock,{NX:true,EX:30})!=='OK'){lock=null;return reply({code:'BUSY'},409);}
    const current=await notices(redis);
    if(current.some(n=>n.id===input.id))return reply({status:'already-published'});
    const now=Date.now(),notice={...input,createdAt:now,expiresAt:now+7*86400000};
    await redis.set(KEY,JSON.stringify([...current,notice].slice(-20)),{EX:8*86400});
    // Commit the feed first. FCM failure never discards a published notice.
    let delivery;try{delivery=await push(notice.id);}catch{delivery='periodic-push-failed';}
    return reply({status:'published',delivery,id:notice.id},201);
  }catch{return reply({code:'SERVICE_UNAVAILABLE'},503);}
  finally {if(redis&&lock)await redis.eval("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",{keys:[LOCK],arguments:[lock]}).catch(()=>{});}
}
