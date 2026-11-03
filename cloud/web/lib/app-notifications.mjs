import {randomUUID} from 'node:crypto';
import {adminSettings,authenticateAdmin,validMutation} from './c6-admin-auth.mjs';
import {opsStore} from './c6-ops-store.mjs';
import {store,throttle} from './c3-store.mjs';
import {boundRequestClaims} from './v2-bound-request.mjs';
import {pushAccount,pushNotice} from './notice-push.mjs';
import {noticeStorageEnabled,transactStoredFeed,validStoredNotice,
 NOTICE_TYPES,NOTICE_IMPORTANCE,NOTICE_DELIVERY,NOTICE_TTL_HOURS} from './notice-store.mjs';
const KEY='spnotice:feed:v1',LOCK='spnotice:publish-lock';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const reply=(body,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}});
const clean=(s,max)=>typeof s==='string'&&s.trim().length>0&&s===s.trim()&&s.length<=max&&!/[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(s);
export function validNotice(n,now=Date.now()) {
  return validStoredNotice(n) && UUID.test(n.id) && clean(n.title,80) && clean(n.body,500) &&
    Number.isSafeInteger(n.createdAt) && n.createdAt<=now+5000 && n.createdAt>=now-7*86400000 &&
    Number.isSafeInteger(n.expiresAt) && n.expiresAt>now && n.expiresAt<=n.createdAt+7*86400000;
}
async function legacyFeed(redis) {
 const raw=await redis.get(KEY);if(!raw)return [];
 if(raw.length>100000)throw Error('FEED_INVALID');
 const list=JSON.parse(raw);
 if(!Array.isArray(list)||list.length>20||!list.every(validStoredNotice))throw Error('FEED_INVALID');
 return list;
}
async function notices(redis,options={}) {
 const saved=await transactStoredFeed(null,{...options,legacy:()=>legacyFeed(redis)});
 return (saved?.feed||await legacyFeed(redis)).filter(n=>validNotice(n));
}
export async function notificationFeedRequest(request,{storeProvider=store,storageOptions={}}={}) {
  if(!boundRequestClaims(request))return reply({error:{code:'UNAUTHORIZED'}},401);
  try {
    const text=await request.text();if(text.length>16 || text.trim()!=='{}')return reply({error:{code:'INVALID_REQUEST'}},400);
    const feed=await notices(await storeProvider(),storageOptions);
    // Trusted server clock lets Android establish a subscription cutoff without
    // relying on the device clock being in sync with the VPS.
    return reply({notices:feed,serverTime:Date.now()});
  }catch{return reply({error:{code:'SERVICE_UNAVAILABLE'}},503);}
}
export async function adminNotices(request,{storeProvider=opsStore,push=pushNotice,storageOptions={}}={}) {
  const cfg=adminSettings();if(!cfg.enabled)return reply({code:'ADMIN_DISABLED'},503);
  if(request.method==='POST'&&!validMutation(request,cfg))return reply({code:'CSRF_REJECTED'},403);
  let redis,lock;
  try {
    redis=await storeProvider();
    if(!await authenticateAdmin(redis,request,cfg))return reply({code:'UNAUTHORIZED'},401);
    if(request.method==='GET')return reply({notices:await notices(redis,storageOptions),pushConfigured:!!pushAccount()});
    if(request.method!=='POST')return reply({code:'METHOD_NOT_ALLOWED'},405);
    // Bounded stream even when Content-Length is absent or dishonest.
    const reader=request.body?.getReader();if(!reader)return reply({code:'INVALID_REQUEST'},400);
    const parts=[];let size=0;
    try {for(;;){const {value,done}=await reader.read();if(done)break;
      size+=value.length;if(size>4096){await reader.cancel();return reply({code:'INVALID_REQUEST'},400);}parts.push(Buffer.from(value));}}
    finally{reader.releaseLock();}
    let input;try{input=JSON.parse(Buffer.concat(parts).toString('utf8'));}catch{return reply({code:'INVALID_REQUEST'},400);}
    const keys=input&&typeof input==='object'&&!Array.isArray(input)
      ?Object.keys(input).sort().join(','):'';
    const legacy=keys==='body,id,title';
    const modern=keys==='body,delivery,id,importance,title,ttlHours,type';
    if(!(legacy||modern)||!UUID.test(input.id)||!clean(input.title,80)||!clean(input.body,500)||
      (modern&&(!NOTICE_TYPES.includes(input.type)||!NOTICE_IMPORTANCE.includes(input.importance)||
        !NOTICE_DELIVERY.includes(input.delivery)||!NOTICE_TTL_HOURS.includes(input.ttlHours))))
      return reply({code:'INVALID_REQUEST'},400);
    if(!await throttle(redis,'spnotice:publish-rate',5,60))return reply({code:'RATE_LIMITED'},429);
    const now=Date.now();
    const notice={id:input.id,title:input.title,body:input.body,
      createdAt:now,expiresAt:now+(modern?input.ttlHours:168)*3600000,
      ...(modern?{type:input.type,importance:input.importance,delivery:input.delivery}:{})};
    if(noticeStorageEnabled(storageOptions.env||process.env)) {
      const saved=await transactStoredFeed(notice,{...storageOptions,legacy:()=>legacyFeed(redis)});
      if(saved.duplicate)return reply({status:'already-published'});
    }else {
      // Historical test fixtures; production rejects an unconfigured durable store.
      lock=randomUUID();if(await redis.set(LOCK,lock,{NX:true,EX:30})!=='OK'){lock=null;return reply({code:'BUSY'},409);}
      const current=await notices(redis,storageOptions);
      if(current.some(n=>n.id===input.id))return reply({status:'already-published'});
      await redis.set(KEY,JSON.stringify([...current,notice].slice(-20)),{EX:8*86400});
    }
    // Commit the feed first. FCM failure never discards a published notice.
    let delivery='periodic';
    if(notice.delivery!=='poll') {
      try {
        delivery=await push(notice.id,{
          priority:notice.importance==='important'?'high':'normal',
          ttlSeconds:Math.min(86400,Math.max(0,Math.ceil((notice.expiresAt-Date.now())/1000))),
        });
      }catch{delivery='periodic-push-failed';}
    }
    return reply({status:'published',delivery,id:notice.id},201);
  }catch{return reply({code:'SERVICE_UNAVAILABLE'},503);}
  finally {if(redis&&lock)await redis.eval("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",{keys:[LOCK],arguments:[lock]}).catch(()=>{});}
}

/** FCM validate_only checks credentials and payload without notifying a device/topic. */
export async function verifyPushRequest(request,{storeProvider=opsStore,push=pushNotice}={}) {
 const cfg=adminSettings();if(!cfg.enabled)return reply({code:'ADMIN_DISABLED'},503);
 if(!validMutation(request,cfg))return reply({code:'CSRF_REJECTED'},403);
 try {
  const redis=await storeProvider();if(!await authenticateAdmin(redis,request,cfg))return reply({code:'UNAUTHORIZED'},401);
  if(!await throttle(redis,'spnotice:verify-rate',3,60))return reply({code:'RATE_LIMITED'},429);
  const reader=request.body?.getReader();if(!reader)return reply({code:'INVALID_REQUEST'},400);
  let size=0;const parts=[];
  try {for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;
   if(size>16){await reader.cancel();return reply({code:'INVALID_REQUEST'},400);}parts.push(Buffer.from(value));}}
  finally{reader.releaseLock();}
  if(Buffer.concat(parts).toString('utf8').trim()!=='{}')return reply({code:'INVALID_REQUEST'},400);
  const status=await push(randomUUID(),{validateOnly:true});
  if(status!=='push')return reply({code:'PUSH_NOT_CONFIGURED'},503);
  return reply({status:'validated',sent:false,deviceReceived:false});
 }catch{return reply({code:'PUSH_VALIDATION_FAILED'},503);}
}
