/**
 * App analysis (SP-DECODE Arnes, fase 1): server-side jobs for deep APK
 * analysis by Yamada. Client operations travel over the V2 transport
 * (ops 25-30, lib/app-analysis-v2.mjs); bot/download routes live under
 * /api/v2/app-analysis/*. The old /api/v1/app-analysis/* routes were
 * removed with the V2 migration (2026-11-16).
 *
 * Rules enforced here (Pedro, 2026-11-15):
 * - 1 credit = 1 analysis, $4 USD (price always from the server, never
 *   hard-coded in the client). Reserve on start, charge on completion,
 *   release on failure. Re-analysis is ALWAYS charged.
 * - No consent checkbox: start never requires consent (no 403
 *   CONSENT_REQUIRED). No polling for Yamada: webhook on create/terminal.
 * - Progress lives ONLY in the analysis section: events are stored (cap 64)
 *   but the client renders ONE status card, never a list/timeline. Nothing
 *   about the analysis is ever written to a support thread.
 * - Immediate rejection (no analysis, credit released): HTTP Custom
 *   (xyz.easypro.httpcustom) and Flex Net (com.flexnet.tunnel) with
 *   error_code METHOD_UNAVAILABLE; non-VPN apps (manifest check) with
 *   NOT_VPN_APP ("esta aplicación no es una aplicación VPN").
 * - Deliverable: result.zip (scripts only) in private storage (0o700, never
 *   under public/), signed 24 h download link, 30-day retention. The icon
 *   (icon_ref) and catalog refs NEVER appear in a job view or a download.
 * - Concurrency: queue is FIFO; ANALYZING is capped by
 *   SPDECODE_APP_ANALYSIS_MAX_CONCURRENT (default 1: the standard 3 GiB
 *   profile does not fit 2-3 at once on a 6 GB VM — 2-3 needs a lighter
 *   profile or more RAM; the cap is configurable, not assumed).
 * - The analysis itself runs on Yamada's VM (D2/D3, 2026-11-15 ~21:01). No
 *   Meta Model API in fase 1. The live VPS (12 GB) is NOT the analysis host.
 */
import {createHash,createHmac,timingSafeEqual,randomBytes,randomUUID} from 'node:crypto';
import {inflateRawSync} from 'node:zlib';
import {mkdir,open,readFile,rename,rm,stat,writeFile} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {join} from 'node:path';
import {database,transaction} from './commerce/db.mjs';
import {ShopError,fail} from './commerce/config.mjs';
import {creditBalance,reserveCredit,completeCredit,releaseCredit} from './commerce/credits.mjs';
import {recordAccountNotice,pushAccountNotice} from './commerce/account-notices.mjs';
import {emitAnalysisWebhook} from './app-analysis-webhook.mjs';

export const MAX_APK_BYTES=150*1000*1000;
export const CHUNK_BYTES=2*1024*1024;
export const MAX_RESULT_BYTES=32*1024*1024;
export const DOWNLOAD_TTL_SECONDS=24*3600;
export const RETENTION_DAYS=30;
export const MAX_EVENTS_PER_JOB=64;
export const MAX_CONCURRENT_DEFAULT=1;
export const CREDIT_PRICE_CENTS_FALLBACK=399;

export const STATUSES=new Set(['UPLOADING','UPLOADED','QUEUED_FOR_ANALYSIS','ANALYZING',
 'AWAITING_HUMAN','COMPLETED','COMPLETED_PARTIAL','FAILED','REJECTED','EXPIRED']);
export const TERMINAL_STATUSES=new Set(['COMPLETED','COMPLETED_PARTIAL','FAILED','REJECTED','EXPIRED']);
export const ACTIVE_STATUSES=new Set(['UPLOADING','UPLOADED','QUEUED_FOR_ANALYSIS','ANALYZING','AWAITING_HUMAN']);
export const EVENT_CODES=new Set(['UPLOAD_STARTED','UPLOAD_RECEIVED','UPLOAD_REJECTED',
 'PACKAGE_VALIDATION','PACKAGE_VALIDATED','COMPONENT_INSPECTION','COMPONENTS_INSPECTED',
 'REPORT_PREPARATION','REPORT_READY','ANALYSIS_FAILED','ANALYSIS_RESUMED',
 'APK_METADATA_INSPECTION','DEX_BYTECODE_INSPECTION','NATIVE_LIBRARY_INSPECTION',
 'CODE_DECOMPILATION','DEX_RECOVERY','CRYPTO_EVIDENCE_CORRELATION','ADVANCED_HEARTBEAT',
 'ADVANCED_ANALYSIS','ADVANCED_ANALYSIS_COMPLETE','ADVANCED_ANALYSIS_PARTIAL',
 'ADVANCED_ANALYSIS_SKIPPED','ANALYSIS_STARTED','ANALYSIS_HEARTBEAT','BINARY_ANALYSIS','METHOD_DECODING',
 'CATALOG_BUILDING','CATALOG_CANDIDATE_FOUND','RESULT_PREPARATION']);
export const ERROR_CODES=new Set(['METHOD_UNAVAILABLE','NOT_VPN_APP','INVALID_APK',
 'ANALYSIS_FAILED','UPLOAD_FAILED','INPUT_TOO_LARGE','JOB_EXPIRED','ANALYSIS_TIMEOUT',
 'PLAY_PROTECTION_BLOCKED','INTERNAL_ERROR']);
// Package names verified against the real APK manifests on 2026-11-15:
// HTTP Custom base.apk -> xyz.easypro.httpcustom (classes dev.epro.httpcustom,
// service dev.epro.httpcustom.service.CustomVpnService); Flex Net
// Flex_Net_V_2.4_4.apk -> com.flexnet.tunnel.
export const BLOCKED_PACKAGES=new Map([
 ['xyz.easypro.httpcustom','HTTP_CUSTOM'],
 ['com.flexnet.tunnel','FLEX_NET'],
]);
export const UUID_RE=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64=/^[a-f0-9]{64}$/;
const FILENAME_RE=/^[A-Za-z0-9_.\- ]{1,88}\.(apk|apks)$/;
const PROVIDER_RE=/^[a-z0-9][a-z0-9_-]{0,63}$/;

export function settings(env=process.env){
 const maxRaw=Number.parseInt(env.SPDECODE_APP_ANALYSIS_MAX_CONCURRENT||'',10);
 return {
  enabled:env.SPDECODE_APP_ANALYSIS_ENABLED==='true',
  root:env.SPDECODE_APP_ANALYSIS_ROOT||'/var/lib/spdecode/app-analysis',
  maxConcurrent:Number.isInteger(maxRaw)?Math.min(3,Math.max(1,maxRaw)):MAX_CONCURRENT_DEFAULT,
  downloadSecret:env.SPDECODE_APP_ANALYSIS_DOWNLOAD_SECRET||'',
  botToken:env.SPDECODE_APP_ANALYSIS_BOT_TOKEN||'',
 };
}
const jobDir=(root,jobId)=>join(root,jobId);
const hex=value=>createHash('sha256').update(value,'utf8').digest('hex');
const safeEqual=(a,b)=>{
 const x=Buffer.from(String(a),'utf8'),y=Buffer.from(String(b),'utf8');
 return x.length===y.length&&timingSafeEqual(x,y);
};

export function verifyBotToken(request,env=process.env){
 const cfg=settings(env);
 const presented=request.headers.get('authorization')?.replace(/^Bearer /,'')||
   request.headers.get('x-sp-analysis-bot-token')||'';
 if(!cfg.botToken||cfg.botToken.length<32||!presented||!safeEqual(presented,cfg.botToken))
  fail('APP_ANALYSIS_BOT_UNAUTHORIZED',401);
}

/** Signed 24 h download link: HMAC-SHA256(secret, jobId|accountId|exp). */
export function signDownload(jobId,accountId,env=process.env,nowSeconds=Math.floor(Date.now()/1000)){
 const cfg=settings(env);
 if(!cfg.downloadSecret||cfg.downloadSecret.length<32)fail('APP_ANALYSIS_DOWNLOAD_NOT_CONFIGURED',503);
 const exp=nowSeconds+DOWNLOAD_TTL_SECONDS;
 const sig=createHmac('sha256',cfg.downloadSecret)
   .update(jobId+'|'+accountId+'|'+exp,'utf8').digest('hex');
 return {url:'/api/v2/app-analysis/'+jobId+'/download?exp='+exp+'&sig='+sig,exp};
}
export function verifyDownloadSignature(jobId,accountId,exp,sig,env=process.env){
 const cfg=settings(env);
 const now=Math.floor(Date.now()/1000);
 if(!cfg.downloadSecret||cfg.downloadSecret.length<32||!Number.isInteger(exp)||
    !/^[a-f0-9]{64}$/.test(sig||'')||exp<=now||exp>now+DOWNLOAD_TTL_SECONDS+300)return false;
 const expected=createHmac('sha256',cfg.downloadSecret)
   .update(jobId+'|'+accountId+'|'+exp,'utf8').digest('hex');
 return safeEqual(sig,expected);
}

// ---------------------------------------------------------------------------
// Binary AndroidManifest.xml parsing (port of cloud/apk_analysis/qa_identity.py
// _strings/_parse, extended to collect permissions and services). Never
// executes APK content; bounds follow the Python originals (8 MB manifest).
// ---------------------------------------------------------------------------
const MAX_MANIFEST_BYTES=8*1024*1024;
function u16(buf,off){
 if(off<0||off+2>buf.length)throw Error('AXML_BOUNDS');
 return buf.readUInt16LE(off);
}
function u32(buf,off){
 if(off<0||off+4>buf.length)throw Error('AXML_BOUNDS');
 return buf.readUInt32LE(off);
}
function axmlLength(buf,off,utf8){
 if(utf8){
  if(off>=buf.length)throw Error('AXML_BOUNDS');
  let value=buf[off];off+=1;
  if(value&0x80){
   if(off>=buf.length)throw Error('AXML_BOUNDS');
   value=((value&0x7f)<<8)|buf[off];off+=1;
  }
  return [value,off];
 }
 const first=u16(buf,off);off+=2;
 if(first&0x8000)return [((first&0x7fff)<<16)|u16(buf,off),off+2];
 return [first,off];
}
function axmlStrings(buf,off,size){
 const header=u16(buf,off+2),count=u32(buf,off+8),flags=u32(buf,off+16),
   base=off+u32(buf,off+20);
 if(header<28||count>150000||off+header+count*4>off+size)throw Error('AXML_STRINGS');
 const utf8=Boolean(flags&0x100),out=[];
 for(let i=0;i<count;i++){
  let pos=base+u32(buf,off+header+i*4);
  if(pos<off||pos>=off+size)throw Error('AXML_STRING_OFFSET');
  const [len,afterLen]=axmlLength(buf,pos,utf8);
  pos=afterLen;
  let sizeBytes;
  if(utf8)[sizeBytes,pos]=axmlLength(buf,pos,true);
  else sizeBytes=len*2;
  if(sizeBytes>65536||pos+sizeBytes>off+size)throw Error('AXML_STRING_LENGTH');
  out.push(buf.subarray(pos,pos+sizeBytes).toString(utf8?'utf8':'utf16le'));
 }
 return out;
}
export function parseAndroidManifest(axml){
 if(!Buffer.isBuffer(axml)||axml.length<8||u16(axml,0)!==3||u16(axml,2)!==8)
  throw Error('AXML_INVALID');
 const limit=Math.min(axml.length,u32(axml,4));
 if(limit<8)throw Error('AXML_INVALID');
 let pool=[],packageName=null,appName=null;
 const permissions=new Set(),services=[],values=new Set();
 let off=8;
 while(off+8<=limit){
  const kind=u16(axml,off),head=u16(axml,off+2),length=u32(axml,off+4);
  if(head<8||length<head||off+length>limit)throw Error('AXML_CHUNK');
  if(kind===1)pool=axmlStrings(axml,off,length);
  if(kind===0x0102&&pool.length&&head>=16&&length>=36){
   const ext=off+16,tagIdx=u32(axml,ext+4),
     tag=tagIdx<pool.length?pool[tagIdx]:'';
   if(['manifest','application','uses-permission','service','action'].includes(tag)){
    const attrStart=u16(axml,ext+8),attrSize=u16(axml,ext+10),
      attrCount=u16(axml,ext+12);
    if(attrSize<20||attrCount>128||ext+attrStart+attrCount*attrSize>off+length)
     throw Error('AXML_ATTRIBUTES');
    const attrs={};
    for(let n=0;n<attrCount;n++){
     const a=ext+attrStart+n*attrSize,
       nameIdx=u32(axml,a+4),rawIdx=u32(axml,a+8),
       dataType=axml[a+15],dataIdx=u32(axml,a+16),
       valueIdx=rawIdx!==0xffffffff?rawIdx:dataType===3?dataIdx:0xffffffff,
       value=valueIdx<pool.length?pool[valueIdx]:null,
       name=nameIdx<pool.length?pool[nameIdx]:'';
     if(value!==null){attrs[name]=value;values.add(value);}
    }
    if(tag==='manifest'&&attrs.package)packageName=attrs.package;
    if(tag==='application'&&attrs.label&&attrs.label.length<=100)appName=attrs.label;
    if(tag==='uses-permission'&&attrs.name)permissions.add(attrs.name);
    if(tag==='service')services.push({name:attrs.name||null,permission:attrs.permission||null});
   }
  }
  off+=length;
 }
 // VPN criterion (Pedro, P1): the manifest asks for a VPN connection
 // (BIND_VPN_SERVICE on a service, or a VpnService declaration / bind action)
 // and declares tunnel entry points (at least one service). A bare
 // uses-permission without any service does not count.
 const serviceVpn=services.some(s=>s.permission==='android.permission.BIND_VPN_SERVICE'||
   (typeof s.name==='string'&&s.name.includes('VpnService')));
 const actionVpn=values.has('android.net.VpnService');
 const permissionWithService=permissions.has('android.permission.BIND_VPN_SERVICE')&&services.length>0;
 return {packageName,appName,permissions:[...permissions],services,
  hasVpn:serviceVpn||actionVpn||permissionWithService};
}

async function readEntryBytes(handle,entry){
 const {method,compressedSize,offset}=entry;
 if(compressedSize>MAX_APK_BYTES)throw Error('ENTRY_TOO_LARGE');
 const buf=Buffer.alloc(compressedSize);
 await handle.read(buf,0,compressedSize,offset);
 if(method===0)return buf;
 if(method===8)return inflateRawSync(buf,{maxOutputLength:MAX_MANIFEST_BYTES*4});
 throw Error('UNSUPPORTED_ENTRY_METHOD');
}
async function findManifestEntry(handle,tmpDir){
 const size=(await handle.stat()).size,probe=Math.min(size,65536+22);
 const tail=Buffer.alloc(probe);
 await handle.read(tail,0,probe,Math.max(0,size-probe));
 let eocd=-1;
 for(let i=tail.length-22;i>=0;i--){
  if(tail.readUInt32LE(i)===0x06054b50){eocd=i;break;}
 }
 if(eocd<0)throw Error('NOT_A_ZIP');
 const count=tail.readUInt16LE(eocd+10),cdSize=tail.readUInt32LE(eocd+12),
   cdOffset=tail.readUInt32LE(eocd+16);
 if(count>20000||cdSize>64*1024*1024)throw Error('ZIP_TOO_LARGE');
 const cd=Buffer.alloc(cdSize);
 await handle.read(cd,0,cdSize,cdOffset);
 const entries=[];
 let off=0;
 for(let n=0;n<count&&off+46<=cd.length;n++){
  if(cd.readUInt32LE(off)!==0x02014b50)break;
  const method=cd.readUInt16LE(off+10),compressedSize=cd.readUInt32LE(off+20),
    nameLen=cd.readUInt16LE(off+28),extraLen=cd.readUInt16LE(off+30),
    commentLen=cd.readUInt16LE(off+32),localOffset=cd.readUInt32LE(off+42),
    name=cd.toString('utf8',off+46,off+46+nameLen);
  entries.push({name,method,compressedSize,localOffset});
  off+=46+nameLen+extraLen+commentLen;
 }
 const localHeader=async entry=>{
  const head=Buffer.alloc(30);
  await handle.read(head,0,30,entry.localOffset);
  if(head.readUInt32LE(0)!==0x04034b50)throw Error('BAD_LOCAL_HEADER');
  return entry.localOffset+30+head.readUInt16LE(26)+head.readUInt16LE(28);
 };
 for(const entry of entries){
  if(entry.name==='AndroidManifest.xml'){
   const dataOff=await localHeader(entry);
   const raw=await readEntryBytes(handle,{...entry,offset:dataOff});
   if(raw.length>MAX_MANIFEST_BYTES)throw Error('MANIFEST_TOO_LARGE');
   return raw;
  }
 }
 const base=entries.find(e=>e.name==='base.apk');
 if(base){
  const dataOff=await localHeader(base);
  const raw=await readEntryBytes(handle,{...base,offset:dataOff});
  const tmp=join(tmpDir,'base.apk');
  await writeFile(tmp,raw,{mode:0o600});
  try{return await extractManifestBytes(tmp,tmpDir);}finally{await rm(tmp,{force:true});}
 }
 throw Error('MANIFEST_NOT_FOUND');
}
export async function extractManifestBytes(apkPath,tmpDir='/tmp'){
 const handle=await open(apkPath,'r');
 try{return await findManifestEntry(handle,tmpDir);}finally{await handle.close();}
}
export function verifyVpnGate(manifest){
 const blocked=manifest.packageName?BLOCKED_PACKAGES.get(manifest.packageName):undefined;
 if(blocked)return {ok:false,errorCode:'METHOD_UNAVAILABLE',blocked};
 if(!manifest.hasVpn)return {ok:false,errorCode:'NOT_VPN_APP'};
 return {ok:true};
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------
async function auditCredit(client,actorId,action,jobId){
 await client.query(`INSERT INTO spdecode_shop.audit(actor_id,action,resource_id)
   VALUES($1,$2,$3)`,[actorId,action,jobId]).catch(()=>{});
}
async function appendEvent(client,jobId,code,status,detailKey=null){
 const max=(await client.query(
   'SELECT COALESCE(MAX(sequence),0) AS m FROM spdecode_shop.app_analysis_events WHERE job_id=$1',
   [jobId])).rows[0].m;
 const count=(await client.query(
   'SELECT COUNT(*)::integer AS n FROM spdecode_shop.app_analysis_events WHERE job_id=$1',
   [jobId])).rows[0].n;
 if(count>=MAX_EVENTS_PER_JOB){
  await client.query(`DELETE FROM spdecode_shop.app_analysis_events WHERE id=(
    SELECT id FROM spdecode_shop.app_analysis_events
    WHERE job_id=$1 ORDER BY sequence ASC LIMIT 1)`,[jobId]);
 }
 await client.query(`INSERT INTO spdecode_shop.app_analysis_events
   (job_id,sequence,code,status,detail_key) VALUES($1,$2,$3,$4,$5)`,
  [jobId,max+1,code,status,detailKey]);
}
async function notifyAccount(client,accountId,jobId,kind,eventKey,{db=database(),env=process.env}={}){
 const id=await recordAccountNotice(client,accountId,eventKey,kind,jobId).catch(()=>null);
 if(id)await pushAccountNotice(accountId,id,kind,{db,env}).catch(()=>{});
}
function publicJob(row,events=[],env=process.env){
 const out={jobId:row.job_id,status:row.status,phaseCode:row.phase_code,
  progressPercent:row.progress_percent,receivedBytes:Number(row.received_bytes),
  totalBytes:Number(row.input_bytes),filename:row.filename,
  packageName:row.package_name,appName:row.app_name,
  creditState:row.credit_state,errorCode:row.error_code,
  needsToken:row.needs_token,isNewCatalogCandidate:row.is_new_catalog_candidate,
  resultBytes:row.result_bytes===null?null:Number(row.result_bytes),
  resultSha256:row.result_sha256,downloadUrl:null,
  expiresAt:row.expires_at,createdAt:row.created_at,updatedAt:row.updated_at};
 if(events.length)out.events=events.map(e=>({sequence:e.sequence,code:e.code,status:e.status}));
 if((row.status==='COMPLETED'||row.status==='COMPLETED_PARTIAL')&&row.result_sha256){
  try{out.downloadUrl=signDownload(row.job_id,row.account_id,env).url;}catch{out.downloadUrl=null;}
 }
 return out;
}
async function loadJobForUpdate(client,jobId){
 const row=(await client.query(
   'SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1 FOR UPDATE',[jobId])).rows[0];
 if(!row)fail('APP_ANALYSIS_JOB_NOT_FOUND',404);
 return row;
}
function requireOwned(row,accountId,deviceKeyHash){
 if(row.account_id!==accountId||row.device_key_hash!==deviceKeyHash)
  fail('APP_ANALYSIS_ACCESS_DENIED',403);
}
async function creditPriceCents({db=database()}={}){
 try{
  const row=(await db.query(
   "SELECT settings FROM spdecode_shop.products WHERE id='analysis-credits'")).rows[0];
  const bundles=typeof row?.settings==='string'?JSON.parse(row.settings):row?.settings;
  const cents=bundles?.bundles?.['1c']?.USD;
  if(Number.isInteger(cents))return cents;
 }catch{}
 return CREDIT_PRICE_CENTS_FALLBACK;
}

export async function preflight(accountId,{db=database(),env=process.env}={}){
 const row=(await db.query('SELECT id FROM shop_user WHERE id=$1',[accountId])).rows[0];
 if(!row)fail('SIGN_IN_REQUIRED',401);
 const credits=await creditBalance(accountId,{db});
 // A balance read is valid at zero; reserving a job still enforces payment.
 let avatar=null;
 try{
  const {findAutoAssignStaffId}=await import('./commerce/support.mjs');
  const id=await findAutoAssignStaffId(db,env);
  if(id)avatar=(await db.query(
   'SELECT avatar FROM spdecode_shop.staff_accounts WHERE id=$1',[id])).rows[0]?.avatar??null;
 }catch{ /* An optional staff profile must never hide the credit balance. */ }
 return {creditsAvailable:credits.available,balance:credits.balance,held:credits.held,
  creditPriceCents:await creditPriceCents({db}),currency:'USD',creditsPerAnalysis:1,
  agent:{name:'Yamada',role:'support_ai',avatar}};
}

export async function startJob(accountId,input,{db=database(),env=process.env,root}={}){
 const cfg=settings(env);
 if(!cfg.enabled)fail('APP_ANALYSIS_DISABLED',503);
 const {filename,totalBytes,sha256,deviceKeyHash}=input||{};
 if(typeof filename!=='string'||!FILENAME_RE.test(filename)||
    !Number.isSafeInteger(totalBytes)||totalBytes<1||totalBytes>MAX_APK_BYTES||
    typeof sha256!=='string'||!HEX64.test(sha256)||
    typeof deviceKeyHash!=='string'||!HEX64.test(deviceKeyHash))
  fail('INVALID_REQUEST');
 const availability=await preflight(accountId,{db,env});
 if(availability.creditsAvailable<1)fail('INSUFFICIENT_CREDITS',402);
 const jobId=randomUUID();
 const uploadToken=randomBytes(32).toString('base64url');
 // Reserve first: a failed start must never leave a job without a held credit,
 // and a held credit without a job. reserveCredit is idempotent per jobId.
 await reserveCredit(accountId,jobId,{db});
 const dir=jobDir(root||cfg.root,jobId);
 try{
  await db.query(`UPDATE spdecode_shop.credit_reservations SET expires_at=now()+interval '24 hours'
    WHERE job_id=$1`,[jobId]);
  await transaction(async client=>{
   await client.query(`INSERT INTO spdecode_shop.app_analysis_jobs
     (job_id,account_id,device_key_hash,upload_token_hash,filename,input_sha256,input_bytes,chunk_bytes)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
    [jobId,accountId,deviceKeyHash,hex(uploadToken),filename,sha256,totalBytes,CHUNK_BYTES]);
   await appendEvent(client,jobId,'UPLOAD_STARTED','RUNNING');
   await auditCredit(client,accountId,'app_analysis_credit_reserved',jobId);
  },db);
  await mkdir(dir,{recursive:true,mode:0o700});
  await writeFile(join(dir,'input.part'),Buffer.alloc(0),{mode:0o600});
 }catch(e){
  await releaseCredit(accountId,jobId,{db}).catch(()=>{});
  await db.query('DELETE FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[jobId]).catch(()=>{});
  await rm(dir,{recursive:true,force:true}).catch(()=>{});
  if(e instanceof ShopError)throw e;
  fail('APP_ANALYSIS_STORAGE_UNAVAILABLE',503);
 }
 return {jobId,uploadToken,chunkBytes:CHUNK_BYTES,receivedBytes:0,status:'UPLOADING'};
}

export async function appendChunk(accountId,input,{db=database(),root,env=process.env}={}){
 const cfg=settings(env);
 const {jobId,uploadToken,index,chunkSha256,dataBase64,deviceKeyHash}=input||{};
 if(!UUID_RE.test(jobId||'')||typeof uploadToken!=='string'||!uploadToken||
    !Number.isSafeInteger(index)||index<0||
    typeof chunkSha256!=='string'||!HEX64.test(chunkSha256)||
    typeof dataBase64!=='string'||!dataBase64||
    typeof deviceKeyHash!=='string'||!HEX64.test(deviceKeyHash))
  fail('INVALID_REQUEST');
 let bytes;
 try{bytes=Buffer.from(dataBase64,'base64');}catch{fail('INVALID_REQUEST');}
 if(bytes.length<1||bytes.length>CHUNK_BYTES||!HEX64.test(hex(bytes))||
    hex(bytes)!==chunkSha256)fail('INVALID_REQUEST');
 const dir=jobDir(root||cfg.root,jobId);
 return transaction(async client=>{
  const row=await loadJobForUpdate(client,jobId);
  requireOwned(row,accountId,deviceKeyHash);
  if(row.status!=='UPLOADING')fail('APP_ANALYSIS_JOB_NOT_UPLOADING',409);
  if(!safeEqual(hex(uploadToken),row.upload_token_hash))fail('APP_ANALYSIS_ACCESS_DENIED',403);
  const expectedIndex=Math.floor(Number(row.received_bytes)/CHUNK_BYTES);
  if(index!==expectedIndex)fail('APP_ANALYSIS_CHUNK_OUT_OF_ORDER',409);
  if(Number(row.received_bytes)+bytes.length>Number(row.input_bytes))fail('INPUT_TOO_LARGE',413);
  const path=join(dir,'input.part');
  const handle=await open(path,'a');
  try{
   const size=(await handle.stat()).size;
   if(size!==Number(row.received_bytes))fail('APP_ANALYSIS_CHUNK_OUT_OF_ORDER',409);
   await handle.writeFile(bytes);
   await handle.sync();
  }finally{await handle.close();}
  const received=Number(row.received_bytes)+bytes.length;
  await client.query(`UPDATE spdecode_shop.app_analysis_jobs
    SET received_bytes=$2,updated_at=now() WHERE job_id=$1`,[jobId,received]);
  return {jobId,receivedBytes:received,nextChunk:index+1,status:'UPLOADING'};
 },db);
}

async function rejectJob(client,jobId,accountId,errorCode,{db=database(),env=process.env,send}={}){
 await releaseCredit(accountId,jobId,{db}).catch(()=>{});
 await client.query(`UPDATE spdecode_shop.app_analysis_jobs
   SET status='REJECTED',error_code=$2,credit_state='released',updated_at=now()
   WHERE job_id=$1`,[jobId,errorCode]);
 await appendEvent(client,jobId,'ANALYSIS_FAILED','FAILED');
 await auditCredit(client,accountId,'app_analysis_credit_released',jobId);
 const row=(await client.query(
   'SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[jobId])).rows[0];
 await notifyAccount(client,accountId,jobId,'service','app-analysis:rejected:'+jobId,{db,env});
 await emitAnalysisWebhook('analysis.failed',
   {jobId,accountId,status:'REJECTED',errorCode},{db,env,send}).catch(()=>{});
 return publicJob(row);
}

export async function finishJob(accountId,input,{db=database(),env=process.env,root,emit=true,send}={}){
 const cfg=settings(env);
 const {jobId,uploadToken,deviceKeyHash}=input||{};
 if(!UUID_RE.test(jobId||'')||typeof uploadToken!=='string'||!uploadToken||
    typeof deviceKeyHash!=='string'||!HEX64.test(deviceKeyHash))
  fail('INVALID_REQUEST');
 const dir=jobDir(root||cfg.root,jobId);
 const part=join(dir,'input.part'),apk=join(dir,'input.apk');
 const outcome=await transaction(async client=>{
  const row=await loadJobForUpdate(client,jobId);
  requireOwned(row,accountId,deviceKeyHash);
  if(row.status!=='UPLOADING')fail('APP_ANALYSIS_JOB_NOT_UPLOADING',409);
  if(!safeEqual(hex(uploadToken),row.upload_token_hash))fail('APP_ANALYSIS_ACCESS_DENIED',403);
  if(Number(row.received_bytes)!==Number(row.input_bytes))fail('APP_ANALYSIS_UPLOAD_INCOMPLETE',409);
  const digest=createHash('sha256');
  await new Promise((resolve,reject)=>{
   const stream=createReadStream(part);
   stream.on('data',chunk=>digest.update(chunk));
   stream.on('error',reject);
   stream.on('end',resolve);
  });
  if(digest.digest('hex')!==row.input_sha256){
   // Commit the rejection first, then report the mismatch: throwing inside
   // the transaction would roll the REJECTED update back.
   await releaseCredit(accountId,jobId,{db}).catch(()=>{});
   await client.query(`UPDATE spdecode_shop.app_analysis_jobs
     SET status='REJECTED',error_code='INVALID_APK',credit_state='released',updated_at=now()
     WHERE job_id=$1`,[jobId]);
   await appendEvent(client,jobId,'ANALYSIS_FAILED','FAILED');
   return {shaMismatch:true};
  }
  await rename(part,apk);
  await client.query(`UPDATE spdecode_shop.app_analysis_jobs
    SET status='UPLOADED',updated_at=now() WHERE job_id=$1`,[jobId]);
  await appendEvent(client,jobId,'UPLOAD_RECEIVED','DONE');
  // Pre-analysis gate, BEFORE any deep analysis (Pedro, P1/P3).
  let manifest;
  try{manifest=parseAndroidManifest(await extractManifestBytes(apk,dir));}
  catch{return rejectJob(client,jobId,accountId,'INVALID_APK',{db,env,send});}
  const gate=verifyVpnGate(manifest);
  if(!gate.ok)return rejectJob(client,jobId,accountId,gate.errorCode,{db,env,send});
  await client.query(`UPDATE spdecode_shop.app_analysis_jobs
    SET status='QUEUED_FOR_ANALYSIS',package_name=$2,app_name=$3,updated_at=now()
    WHERE job_id=$1`,[jobId,manifest.packageName,manifest.appName]);
  const updated=(await client.query(
    'SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[jobId])).rows[0];
  if(emit)await emitAnalysisWebhook('analysis.created',
    {jobId,accountId,status:'QUEUED_FOR_ANALYSIS'},{db,env,send}).catch(()=>{});
  return publicJob(updated);
 },db);
 if(outcome?.shaMismatch)fail('APP_ANALYSIS_SHA_MISMATCH',400);
 return outcome;
}

export async function getJob(accountId,jobId,{db=database(),env=process.env,deviceKeyHash=null}={}){
 if(!UUID_RE.test(jobId||''))fail('INVALID_REQUEST');
 const row=(await db.query(
   'SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[jobId])).rows[0];
 if(!row)fail('APP_ANALYSIS_JOB_NOT_FOUND',404);
 if(row.account_id!==accountId)fail('APP_ANALYSIS_ACCESS_DENIED',403);
 if(deviceKeyHash!==null&&row.device_key_hash!==deviceKeyHash)
  fail('APP_ANALYSIS_ACCESS_DENIED',403);
 const events=(await db.query(
   `SELECT sequence,code,status FROM spdecode_shop.app_analysis_events
    WHERE job_id=$1 ORDER BY sequence ASC LIMIT $2`,[jobId,MAX_EVENTS_PER_JOB])).rows;
 return publicJob(row,events,env);
}

export async function listJobs(accountId,{db=database(),env=process.env,limit=50}={}){
 const rows=(await db.query(
   `SELECT * FROM spdecode_shop.app_analysis_jobs WHERE account_id=$1
    ORDER BY created_at DESC LIMIT $2`,[accountId,Math.min(100,Math.max(1,limit))])).rows;
 return {jobs:rows.map(row=>publicJob(row,[],env))};
}

export async function recordEvent(jobId,input,{db=database(),env=process.env}={}){
 const cfg=settings(env);
 const {code,status,progressPercent,detailKey}=input||{};
 if(!UUID_RE.test(jobId||'')||!EVENT_CODES.has(code)||
    !['RUNNING','DONE','FAILED','PARTIAL'].includes(status)||
    (progressPercent!==undefined&&(!Number.isInteger(progressPercent)||
      progressPercent<0||progressPercent>100))||
    (detailKey!==undefined&&(typeof detailKey!=='string'||!/^[a-z0-9_]{1,80}$/.test(detailKey))))
  fail('INVALID_REQUEST');
 return transaction(async client=>{
  const row=await loadJobForUpdate(client,jobId);
  if(TERMINAL_STATUSES.has(row.status))fail('APP_ANALYSIS_JOB_TERMINAL',409);
  let nextStatus=row.status;
  if(code==='ANALYSIS_STARTED'){
   if(row.status==='QUEUED_FOR_ANALYSIS'){
    const active=(await client.query(
      "SELECT COUNT(*)::integer AS n FROM spdecode_shop.app_analysis_jobs WHERE status='ANALYZING'")).rows[0].n;
    if(active>=cfg.maxConcurrent)fail('APP_ANALYSIS_BUSY',429);
    nextStatus='ANALYZING';
   }else if(row.status!=='ANALYZING')fail('APP_ANALYSIS_JOB_NOT_QUEUED',409);
  }
  await appendEvent(client,jobId,code,status,detailKey??null);
  await client.query(`UPDATE spdecode_shop.app_analysis_jobs
    SET status=$2,phase_code=$3,progress_percent=COALESCE($4,progress_percent),updated_at=now()
    WHERE job_id=$1`,
   [jobId,nextStatus,code,progressPercent??null]);
  const updated=(await client.query(
    'SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[jobId])).rows[0];
  return publicJob(updated);
 },db);
}

export async function completeJob(jobId,input,{db=database(),env=process.env,root,send}={}){
 const cfg=settings(env);
 const {resultBase64,resultSha256,verdict,needsToken,isNewCatalogCandidate,
   providerId,iconRef,catalogRef,textsRef,dossierRef}=input||{};
 if(!UUID_RE.test(jobId||'')||typeof resultBase64!=='string'||!resultBase64||
    typeof resultSha256!=='string'||!HEX64.test(resultSha256)||
    !['completed','partial'].includes(verdict)||
    (needsToken!==undefined&&typeof needsToken!=='boolean')||
    (isNewCatalogCandidate!==undefined&&typeof isNewCatalogCandidate!=='boolean')||
    (providerId!==undefined&&!PROVIDER_RE.test(providerId))||
    [iconRef,catalogRef,textsRef,dossierRef].some(v=>v!==undefined&&
      (typeof v!=='string'||v.length>512)))
  fail('INVALID_REQUEST');
 let bytes;
 try{bytes=Buffer.from(resultBase64,'base64');}catch{fail('INVALID_REQUEST');}
 if(bytes.length<1||bytes.length>MAX_RESULT_BYTES||hex(bytes)!==resultSha256)
  fail('INVALID_REQUEST');
 const dir=jobDir(root||cfg.root,jobId);
 const row0=(await db.query(
   'SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[jobId])).rows[0];
 if(!row0)fail('APP_ANALYSIS_JOB_NOT_FOUND',404);
 if(TERMINAL_STATUSES.has(row0.status))fail('APP_ANALYSIS_JOB_TERMINAL',409);
 if(!['QUEUED_FOR_ANALYSIS','ANALYZING','AWAITING_HUMAN'].includes(row0.status))
  fail('APP_ANALYSIS_JOB_NOT_QUEUED',409);
 if(isNewCatalogCandidate&&!providerId)fail('INVALID_REQUEST');
 // Charge first (idempotent): if the job update below fails, a retry of
 // complete reuses the same 'completed' reservation instead of double-charging.
 await completeCredit(row0.account_id,jobId,{db});
 try{
  await writeFile(join(dir,'result.zip.tmp'),bytes,{mode:0o600});
  await rename(join(dir,'result.zip.tmp'),join(dir,'result.zip'));
 }catch{
  // The credit is spent, but no deliverable exists: surface 503 so the bot
  // retries complete with the same result instead of silently losing it.
  fail('APP_ANALYSIS_STORAGE_UNAVAILABLE',503);
 }
 const status=verdict==='partial'?'COMPLETED_PARTIAL':'COMPLETED';
 const out=await transaction(async client=>{
  const row=await loadJobForUpdate(client,jobId);
  await client.query(`UPDATE spdecode_shop.app_analysis_jobs
    SET status=$2,result_sha256=$3,result_bytes=$4,needs_token=$5,
      is_new_catalog_candidate=$6,credit_state='completed',updated_at=now()
    WHERE job_id=$1`,
   [jobId,status,resultSha256,bytes.length,needsToken===true,isNewCatalogCandidate===true]);
  await appendEvent(client,jobId,'REPORT_READY','DONE');
  await auditCredit(client,row.account_id,'app_analysis_credit_spent',jobId);
  let candidate=null;
  if(isNewCatalogCandidate){
   candidate=(await client.query(`INSERT INTO spdecode_shop.app_analysis_catalog_candidates
     (job_id,provider_id,icon_ref,catalog_ref,texts_ref,dossier_ref)
     VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
    [jobId,providerId,iconRef??null,catalogRef??null,textsRef??null,dossierRef??null])).rows[0];
  }
  await notifyAccount(client,row.account_id,jobId,'service',
    'app-analysis:completed:'+jobId,{db,env});
  const updated=(await client.query(
    'SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[jobId])).rows[0];
  return {job:publicJob(updated),candidateId:candidate?.id??null};
 },db);
 await emitAnalysisWebhook('analysis.completed',
   {jobId,accountId:row0.account_id,status},{db,env,send}).catch(()=>{});
 return out.job;
}

export async function failJob(jobId,input,{db=database(),env=process.env,send}={}){
 const {errorCode}=input||{};
 if(!UUID_RE.test(jobId||'')||!ERROR_CODES.has(errorCode))fail('INVALID_REQUEST');
 const row0=(await db.query(
   'SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[jobId])).rows[0];
 if(!row0)fail('APP_ANALYSIS_JOB_NOT_FOUND',404);
 if(TERMINAL_STATUSES.has(row0.status))fail('APP_ANALYSIS_JOB_TERMINAL',409);
 await releaseCredit(row0.account_id,jobId,{db}).catch(()=>{});
 const out=await transaction(async client=>{
  const row=await loadJobForUpdate(client,jobId);
  await client.query(`UPDATE spdecode_shop.app_analysis_jobs
    SET status='FAILED',error_code=$2,credit_state='released',updated_at=now()
    WHERE job_id=$1`,[jobId,errorCode]);
  await appendEvent(client,jobId,'ANALYSIS_FAILED','FAILED');
  await auditCredit(client,row.account_id,'app_analysis_credit_released',jobId);
  await notifyAccount(client,row.account_id,jobId,'service',
    'app-analysis:failed:'+jobId,{db,env});
  const updated=(await client.query(
    'SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[jobId])).rows[0];
  return publicJob(updated);
 },db);
 await emitAnalysisWebhook('analysis.failed',
   {jobId,accountId:row0.account_id,status:'FAILED',errorCode},{db,env,send}).catch(()=>{});
 return out;
}

// ---------------------------------------------------------------------------
// Admin (panel) + sweeps
// ---------------------------------------------------------------------------

// Public queue signal for Yamada's instant watcher (hook): how many jobs are
// waiting for analysis. Returns a bare count — never job ids, account ids
// or package names. Used by GET /api/app-analysis/queue-status.
export async function countQueuedJobs({db=database()}={}){
 const rows=(await db.query(
  `SELECT COUNT(*)::integer AS n FROM spdecode_shop.app_analysis_jobs
   WHERE status='QUEUED_FOR_ANALYSIS'`)).rows;
 return rows[0]?.n??0;
}
export async function listAdminJobs({db=database(),status=null,limit=100}={}){
 const rows=(await db.query(
   status&&STATUSES.has(status)
    ?`SELECT * FROM spdecode_shop.app_analysis_jobs WHERE status=$1 ORDER BY created_at DESC LIMIT $2`
    :`SELECT * FROM spdecode_shop.app_analysis_jobs ORDER BY created_at DESC LIMIT $1`,
   status&&STATUSES.has(status)?[status,Math.min(200,limit)]:[Math.min(200,limit)])).rows;
 return {jobs:rows.map(row=>{
   // Admin sees ownership and credit state, but never a signed download URL
   // for another account's deliverable.
   const view=publicJob(row);view.downloadUrl=null;
   return {...view,accountId:row.account_id};
 })};
}
export async function listCandidates({db=database()}={}){
 const rows=(await db.query(
   `SELECT c.*,j.package_name,j.app_name,j.status AS job_status
    FROM spdecode_shop.app_analysis_catalog_candidates c
    JOIN spdecode_shop.app_analysis_jobs j ON j.job_id=c.job_id
    ORDER BY c.created_at DESC LIMIT 100`)).rows;
 // icon_ref/catalog_ref are internal: the panel shows only that they exist.
 return {candidates:rows.map(r=>({id:r.id,jobId:r.job_id,providerId:r.provider_id,
   status:r.status,packageName:r.package_name,appName:r.app_name,
   jobStatus:r.job_status,hasIcon:!!r.icon_ref,hasCatalog:!!r.catalog_ref,
   hasTexts:!!r.texts_ref,reviewedBy:r.reviewed_by,reviewedAt:r.reviewed_at,
   createdAt:r.created_at}))};
}
export async function reviewCandidate(principal,input,{db=database()}={}){
 const {candidateId,decision}=input||{};
 if(!UUID_RE.test(candidateId||'')||!['approved','rejected'].includes(decision))
  fail('INVALID_REQUEST');
 return transaction(async client=>{
  const row=(await client.query(
   `SELECT * FROM spdecode_shop.app_analysis_catalog_candidates WHERE id=$1 FOR UPDATE`,
   [candidateId])).rows[0];
  if(!row)fail('APP_ANALYSIS_CANDIDATE_NOT_FOUND',404);
  if(row.status!=='pending')fail('APP_ANALYSIS_CANDIDATE_REVIEWED',409);
  await client.query(`UPDATE spdecode_shop.app_analysis_catalog_candidates
    SET status=$2,reviewed_by=$3,reviewed_at=now() WHERE id=$1`,
   [candidateId,decision,principal.id]);
  await client.query(`INSERT INTO spdecode_shop.staff_audit
    (id,actor_id,actor_role,action,target_id,details) VALUES($1,$2,$3,$4,$5,$6)`,
   [randomUUID(),principal.id,principal.role||'support',
    'app_analysis_candidate_'+decision,row.job_id,
    JSON.stringify({candidateId,providerId:row.provider_id})]);
  return {reviewed:true,candidateId,status:decision};
 },db);
}

/** Release held reservations past expires_at whose job is not in progress. */
export async function releaseExpiredReservations({db=database()}={}){
 const rows=(await db.query(
   `SELECT r.* FROM spdecode_shop.credit_reservations r
    JOIN spdecode_shop.app_analysis_jobs j ON j.job_id=r.job_id
    WHERE r.state='held' AND r.expires_at IS NOT NULL AND r.expires_at<now()`)).rows;
 let released=0;
 for(const r of rows){
  const job=(await db.query(
   'SELECT status FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[r.job_id])).rows[0];
  if(job&&ACTIVE_STATUSES.has(job.status))continue;
  await releaseCredit(r.account_id,r.job_id,{db}).catch(()=>{});
  await db.query(`UPDATE spdecode_shop.app_analysis_jobs
    SET credit_state='released' WHERE job_id=$1`,[r.job_id]).catch(()=>{});
  released++;
 }
 return {released};
}

/** Expire jobs past the 30-day retention and delete their private files. */
export async function sweepExpiredJobs({db=database(),env=process.env,root}={}){
 const cfg=settings(env);
 const rows=(await db.query(
   `SELECT job_id FROM spdecode_shop.app_analysis_jobs
    WHERE expires_at<now() AND status IN
    ('COMPLETED','COMPLETED_PARTIAL','FAILED','REJECTED','UPLOADING')`)).rows;
 for(const r of rows){
  await db.query(`UPDATE spdecode_shop.app_analysis_jobs SET status='EXPIRED',
    updated_at=now() WHERE job_id=$1`,[r.job_id]);
  await rm(jobDir(root||cfg.root,r.job_id),{recursive:true,force:true}).catch(()=>{});
 }
 return {expired:rows.length};
}
export function resultPath(jobId,{env=process.env,root}={}){
 const cfg=settings(env);
 return join(jobDir(root||cfg.root,jobId),'result.zip');
}
