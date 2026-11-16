/**
 * App analysis over the V2 transport (ops 25-30). Same auth model as the
 * apk-qa gateway (f7-apk-qa-gateway.mjs): bound V2 session claims (HPKE +
 * device key + scope decode) PLUS a commercial account token inside the
 * JSON body, verified with verifyApkAccount. requireAccount (Better Auth
 * cookie/session) is NOT used here: the V2 client has no browser session,
 * it carries the account Bearer token in the body.
 *
 * No enabled-gate here by design (the V1 preflight had none either):
 * startJob and reserveCredit apply their own APP_ANALYSIS_DISABLED /
 * credit gates (503). The device binding is never trusted from the
 * client: deviceKeyHash is always derived server-side as
 * sha256(claims.key), and any client-supplied accountToken/accountId/
 * deviceKeyHash is deleted before dispatch.
 */
import {createHash} from 'node:crypto';
import {boundRequestClaims} from './v2-bound-request.mjs';
import {jsonReply} from './responses.mjs';
import {verifyApkAccount} from './f7-apk-qa-gateway.mjs';
import {ShopError} from './commerce/config.mjs';
import {preflight,startJob,appendChunk,finishJob,getJob,listJobs} from './app-analysis.mjs';

const METHODS=Object.freeze({25:'preflight',26:'start',27:'chunk',28:'finish',29:'status',30:'history'});
const MAX_BODY=3*1024*1024;
const reply=(code,status)=>jsonReply({error:{code}},status);

async function readJSON(request,limit){
 if(request.headers.get('content-type')?.split(';')[0]?.trim()!=='application/json'||
    !request.body||request.headers.has('content-encoding'))throw Error('INVALID_REQUEST');
 const length=Number(request.headers.get('content-length'));
 if(Number.isFinite(length)&&length>limit)throw Error('INPUT_TOO_LARGE');
 const reader=request.body.getReader(),chunks=[];let size=0;
 try{for(;;){
   const {done,value}=await reader.read();if(done)break;
   size+=value.length;if(size>limit){await reader.cancel();throw Error('INPUT_TOO_LARGE');}
   chunks.push(value);
 }}finally{reader.releaseLock();}
 const data=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
 if(!data||typeof data!=='object'||Array.isArray(data))throw Error('INVALID_REQUEST');
 return data;
}

export async function appAnalysisRequest(request,operation,
 {env=process.env,authenticate=verifyApkAccount,db,root}={}){
 const action=METHODS[operation];
 if(!action)return reply('INVALID_REQUEST',400);
 const claims=boundRequestClaims(request);
 if(!claims||claims.hpke!==true||typeof claims.key!=='string'||
    claims.key.length<32||claims.scope!=='decode')return reply('UNAUTHORIZED',401);
 if(request.method!=='POST')return reply('INVALID_REQUEST',405);
 let payload;
 try{payload=await readJSON(request,operation===27?MAX_BODY:4096);}
 catch(e){const over=e?.message==='INPUT_TOO_LARGE';
   return reply(over?'INPUT_TOO_LARGE':'INVALID_REQUEST',over?413:400);}
 const token=payload.accountToken;
 delete payload.accountToken;delete payload.accountId;delete payload.deviceKeyHash;
 const owner=createHash('sha256').update(claims.key,'utf8').digest('hex');
 let accountId;
 try{
  // A valid device session is NEVER sufficient to initiate commercial work.
  accountId=await authenticate(token);
 }catch(e){
  return reply(e instanceof ShopError?e.code:'ACCOUNT_AUTH_UNAVAILABLE',
    e instanceof ShopError?e.status:503);
 }
 payload.deviceKeyHash=owner;
 try{
  switch(operation){
   case 25:return jsonReply(await preflight(accountId,{db}),200);
   case 26:return jsonReply(await startJob(accountId,payload,{db,env,root}),201);
   case 27:return jsonReply(await appendChunk(accountId,payload,{db,env,root}),200);
   case 28:return jsonReply(await finishJob(accountId,payload,{db,env,root}),200);
   case 29:return jsonReply(await getJob(accountId,payload.jobId,{db,env,deviceKeyHash:owner}),200);
   case 30:return jsonReply(await listJobs(accountId,{db,env}),200);
   default:return reply('INVALID_REQUEST',400);
  }
 }catch(e){
  if(e instanceof ShopError)return reply(e.code,e.status);
  return reply('APP_ANALYSIS_UNAVAILABLE',503);
 }
}
