import test from 'node:test';
import assert from 'node:assert/strict';
import {before,after} from 'node:test';
import {readFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID,createHash,randomBytes} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {creditBalance} from '../lib/commerce/credits.mjs';
import {parseAndroidManifest,verifyVpnGate,preflight,startJob,appendChunk,
 finishJob,getJob,listJobs,recordEvent,completeJob,failJob,listAdminJobs,
 listCandidates,reviewCandidate,releaseExpiredReservations,sweepExpiredJobs,
 signDownload,verifyDownloadSignature,verifyBotToken,
 MAX_APK_BYTES} from '../lib/app-analysis.mjs';
import {signWebhook,verifyWebhookSignature} from '../lib/app-analysis-webhook.mjs';
import {appAnalysisRequest} from '../lib/app-analysis-v2.mjs';
import {bindVerifiedRequest} from '../lib/v2-bound-request.mjs';
import {routes,bodyLimit} from '../lib/v2-routes.mjs';
import {protectedActions} from '../lib/action-integrity.mjs';
import {ShopError} from '../lib/commerce/config.mjs';
import {unpackHpkeBody} from '../lib/v2-hpke.mjs';
import {GET as v2DownloadGet} from '../app/api/v2/app-analysis/[jobId]/download/route.js';
import {POST as v2EventsPost} from '../app/api/v2/app-analysis/[jobId]/events/route.js';
import {POST as v2CompletePost} from '../app/api/v2/app-analysis/[jobId]/complete/route.js';
import {POST as v2FailPost} from '../app/api/v2/app-analysis/[jobId]/fail/route.js';

let pg,db,auth,root;
const env={...process.env,NODE_ENV:'test',
 CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgres://synthetic',
BETTER_AUTH_SECRET:randomBytes(32).toString('hex'),
 GOOGLE_CLIENT_ID:'synthetic.apps.googleusercontent.com',GOOGLE_CLIENT_SECRET:'synthetic',
 SPDECODE_ANALYSIS_CREDITS_READY:'true',SPDECODE_APP_ANALYSIS_ENABLED:'true',
 SPDECODE_APP_ANALYSIS_DOWNLOAD_SECRET:'download-secret-'.repeat(3),
 SPDECODE_APP_ANALYSIS_BOT_TOKEN:'bot-token-'.repeat(5)};
Object.assign(process.env,env);

// --- Minimal binary AndroidManifest.xml builder (string pool + elements) ---
function buildManifest({packageName,label='Test App',permissions=[],services=[]}){
 const strings=[];
 const idx=s=>{let i=strings.indexOf(s);if(i<0){strings.push(s);i=strings.length-1;}return i;};
 for(const s of ['manifest','application','uses-permission','service','package','label','name','permission'])
  idx(s);
 idx(packageName);idx(label);
 for(const p of permissions)idx(p);
 for(const s of services){idx(s.name);if(s.permission)idx(s.permission);}
 const chunks=[];
 const poolSize=28+strings.length*4+strings.reduce((n,s)=>n+2+s.length*2+2,0);
 const pool=Buffer.alloc(poolSize);
 pool.writeUInt16LE(0x0001,0);pool.writeUInt16LE(28,2);
 pool.writeUInt32LE(poolSize,4);
 pool.writeUInt32LE(strings.length,8);pool.writeUInt32LE(0,12);
 pool.writeUInt32LE(0,16);pool.writeUInt32LE(28+strings.length*4,20);pool.writeUInt32LE(0,24);
 let pos=28+strings.length*4;
 for(const [i,s] of strings.entries()){
  pool.writeUInt32LE(pos-(28+strings.length*4),28+i*4);
  pool.writeUInt16LE(s.length,pos);pos+=2;
  pool.write(s,pos,'utf16le');pos+=s.length*2;
  pool.writeUInt16LE(0,pos);pos+=2;
 }
 chunks.push(pool);
 const element=(tag,attrs)=>{
  const size=36+attrs.length*20,buf=Buffer.alloc(size);
  buf.writeUInt16LE(0x0102,0);buf.writeUInt16LE(16,2);buf.writeUInt32LE(size,4);
  buf.writeUInt32LE(0,8);buf.writeUInt32LE(0xffffffff,12);
  buf.writeUInt32LE(0xffffffff,16);buf.writeUInt32LE(idx(tag),20);
  buf.writeUInt16LE(20,24);buf.writeUInt16LE(20,26);buf.writeUInt16LE(attrs.length,28);
  buf.writeUInt16LE(0xffff,30);buf.writeUInt16LE(0xffff,32);buf.writeUInt16LE(0xffff,34);
  attrs.forEach(([name,value],n)=>{
   const a=36+n*20;
   buf.writeUInt32LE(0xffffffff,a);buf.writeUInt32LE(idx(name),a+4);
   buf.writeUInt32LE(idx(value),a+8);buf.writeUInt16LE(8,a+12);
   buf.writeUInt8(0,a+14);buf.writeUInt8(3,a+15);buf.writeUInt32LE(idx(value),a+16);
  });
  chunks.push(buf);
 };
 element('manifest',[['package',packageName]]);
 element('application',[['label',label]]);
 for(const p of permissions)element('uses-permission',[['name',p]]);
 for(const s of services)
  element('service',s.permission?[['name',s.name],['permission',s.permission]]:[['name',s.name]]);
 const total=8+chunks.reduce((n,c)=>n+c.length,0);
 const out=Buffer.alloc(total);
 out.writeUInt16LE(0x0003,0);out.writeUInt16LE(8,2);out.writeUInt32LE(total,4);
 let off=8;
 for(const c of chunks){c.copy(out,off);off+=c.length;}
 return out;
}
// --- Minimal stored ZIP builder ---
function buildZip(entries){
 const local=[],central=[];
 let off=0;
 for(const {name,data} of entries){
  const nb=Buffer.from(name,'utf8');
  const lh=Buffer.alloc(30);
  lh.writeUInt32LE(0x04034b50,0);lh.writeUInt16LE(20,4);lh.writeUInt16LE(0,6);
  lh.writeUInt16LE(0,8);lh.writeUInt16LE(0,10);lh.writeUInt16LE(0,12);
  lh.writeUInt32LE(data.length,14);lh.writeUInt32LE(data.length,18);
  lh.writeUInt16LE(nb.length,26);lh.writeUInt16LE(0,28);
  local.push(lh,nb,data);
  const ch=Buffer.alloc(46);
  ch.writeUInt32LE(0x02014b50,0);ch.writeUInt16LE(20,6);ch.writeUInt16LE(20,8);
  ch.writeUInt16LE(0,10);ch.writeUInt16LE(0,12);ch.writeUInt16LE(0,14);
  ch.writeUInt32LE(data.length,16);ch.writeUInt32LE(data.length,20);
  ch.writeUInt16LE(nb.length,28);ch.writeUInt16LE(0,30);ch.writeUInt16LE(0,32);
  ch.writeUInt16LE(0,34);ch.writeUInt16LE(0,36);ch.writeUInt32LE(0,38);
  ch.writeUInt32LE(off,42);
  central.push(ch,nb);
  off+=30+nb.length+data.length;
 }
 const cdSize=central.reduce((n,c)=>n+c.length,0);
 const end=Buffer.alloc(22);
 end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(0,8);end.writeUInt16LE(entries.length,10);
 end.writeUInt32LE(cdSize,12);end.writeUInt32LE(off,16);
 return Buffer.concat([...local,...central,end]);
}
const vpnManifest=()=>buildManifest({packageName:'com.example.vpnapp',
 permissions:['android.permission.BIND_VPN_SERVICE'],
 services:[{name:'com.example.vpnapp.TunnelService',
   permission:'android.permission.BIND_VPN_SERVICE'}]});
const plainManifest=()=>buildManifest({packageName:'com.example.plainapp'});
const httpCustomManifest=()=>buildManifest({packageName:'xyz.easypro.httpcustom',
 services:[{name:'dev.epro.httpcustom.service.CustomVpnService',
   permission:'android.permission.BIND_VPN_SERVICE'}]});
const flexNetManifest=()=>buildManifest({packageName:'com.flexnet.tunnel',
 services:[{name:'com.flexnet.tunnel.TunnelService',
   permission:'android.permission.BIND_VPN_SERVICE'}]});
const apkBytes=manifest=>buildZip([{name:'AndroidManifest.xml',data:manifest}]);
const apksBytes=manifest=>buildZip([{name:'base.apk',data:apkBytes(manifest)}]);
const sha256=buf=>createHash('sha256').update(buf).digest('hex');
const deviceHash=sha256('test-device-key');

async function newAccount(credits=5){
 const id=randomUUID();
 await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
   VALUES($1,$2,$3,true,now(),now())`,[id,'Analysis User',id+'@example.invalid']);
 if(credits>0)
  await db.query(`INSERT INTO spdecode_shop.credit_ledger
    (id,account_id,movement_kind,delta,payment_live)
    VALUES($1,$2,'grant',$3,false)`,[randomUUID(),id,credits]);
 return id;
}
async function uploadJob(accountId,apk,{filename='sample.apk'}={}){
 const started=await startJob(accountId,{filename,totalBytes:apk.length,
   sha256:sha256(apk),deviceKeyHash:deviceHash},{db,env,root});
 const data=apk.toString('base64');
 await appendChunk(accountId,{jobId:started.jobId,uploadToken:started.uploadToken,
   index:0,chunkSha256:sha256(apk),dataBase64:data,deviceKeyHash:deviceHash},
  {db,env,root});
 return started;
}
async function finishUploaded(accountId,started,opts={}){
 return finishJob(accountId,{jobId:started.jobId,uploadToken:started.uploadToken,
   deviceKeyHash:deviceHash},{db,env,root,...opts});
}

before(async()=>{
 root=await mkdtemp(join(tmpdir(),'spdecode-app-analysis-'));
 pg=new PGlite();
 const query=async(sql,params=[])=>{
  const r=await pg.query(sql,params);
  return {rows:r.rows,rowCount:r.rows.length||r.affectedRows||0};
 };
 db={query,connect:async()=>({query,release(){}})};
 auth=makeAuth(db,env);
 await (await getMigrations(auth.options)).runMigrations();
 for(const name of ['002_shop.sql','005_account_support_apk.sql','007_staff_permissions.sql','008_account_notifications.sql','009_staff_custom_roles.sql','010_support_reads_avatar.sql','012_app_analysis.sql']){
  const sql=await readFile(new URL('../sql/'+name,import.meta.url),'utf8');
  await pg.exec(sql);
 }
});
after(async()=>{await pg?.close();await rm(root,{recursive:true,force:true});});

test('manifest parser: VPN service is detected, plain apps are not',()=>{
 const vpn=parseAndroidManifest(vpnManifest());
 assert.equal(vpn.packageName,'com.example.vpnapp');
 assert.equal(vpn.hasVpn,true);
 assert.equal(verifyVpnGate(vpn).ok,true);
 const plain=parseAndroidManifest(plainManifest());
 assert.equal(plain.hasVpn,false);
 assert.deepEqual(verifyVpnGate(plain),{ok:false,errorCode:'NOT_VPN_APP'});
 assert.deepEqual(verifyVpnGate(parseAndroidManifest(httpCustomManifest())),
   {ok:false,errorCode:'METHOD_UNAVAILABLE',blocked:'HTTP_CUSTOM'});
 assert.deepEqual(verifyVpnGate(parseAndroidManifest(flexNetManifest())),
   {ok:false,errorCode:'METHOD_UNAVAILABLE',blocked:'FLEX_NET'});
});

test('preflight returns zero balance; start still enforces credits',async()=>{
 const poor=await newAccount(0);
 assert.equal((await preflight(poor,{db})).creditsAvailable,0);
 await assert.rejects(startJob(poor,{filename:'zero.apk',totalBytes:100,sha256:'a'.repeat(64),deviceKeyHash:deviceHash},{db,env,root}),/INSUFFICIENT_CREDITS/);
 assert.equal((await db.query('SELECT job_id FROM spdecode_shop.app_analysis_jobs WHERE account_id=$1',[poor])).rows.length,0);
 const rich=await newAccount(5);
 const ok=await preflight(rich,{db});
 assert.equal(ok.creditsAvailable,5);
 assert.equal(ok.creditPriceCents,399);
 assert.equal(ok.currency,'USD');
 assert.equal(ok.creditsPerAnalysis,1);
});

test('start reserves 1 credit, audits, and enforces the 150 MB cap',async()=>{
 const account=await newAccount(5);
 const started=await startJob(account,{filename:'sample.apk',totalBytes:1000,
   sha256:'a'.repeat(64),deviceKeyHash:deviceHash},{db,env,root});
 assert.match(started.jobId,/^[0-9a-f-]{36}$/);
 assert.equal(started.chunkBytes,2*1024*1024);
 assert.equal((await creditBalance(account,{db})).available,4);
 const audit=(await db.query(
   "SELECT * FROM spdecode_shop.audit WHERE resource_id=$1 AND action='app_analysis_credit_reserved'",
   [started.jobId])).rows;
 assert.equal(audit.length,1);
 await assert.rejects(startJob(account,{filename:'big.apk',
   totalBytes:MAX_APK_BYTES+1,sha256:'a'.repeat(64),deviceKeyHash:deviceHash},
  {db,env,root}),/INVALID_REQUEST/);
 await assert.rejects(startJob(account,{filename:'evil.exe',totalBytes:10,
   sha256:'a'.repeat(64),deviceKeyHash:deviceHash},{db,env,root}),/INVALID_REQUEST/);
});

test('chunk + finish queues a VPN app and records a skipped webhook (no URL)',async()=>{
 const account=await newAccount(5);
 const apk=apkBytes(vpnManifest());
 const started=await uploadJob(account,apk);
 const done=await finishUploaded(account,started);
 assert.equal(done.status,'QUEUED_FOR_ANALYSIS');
 assert.equal(done.packageName,'com.example.vpnapp');
 assert.equal(done.creditState,'held');
 const deliveries=(await db.query(
   `SELECT * FROM spdecode_shop.app_analysis_webhook_deliveries WHERE job_id=$1`,
   [started.jobId])).rows;
 assert.equal(deliveries.length,1);
 assert.equal(deliveries[0].status,'skipped');
 assert.equal(deliveries[0].event,'analysis.created');
});

test('finish rejects a non-VPN app and releases the credit',async()=>{
 const account=await newAccount(5);
 const started=await uploadJob(account,apkBytes(plainManifest()));
 const done=await finishUploaded(account,started);
 assert.equal(done.status,'REJECTED');
 assert.equal(done.errorCode,'NOT_VPN_APP');
 assert.equal((await creditBalance(account,{db})).available,5);
});

test('finish rejects HTTP Custom and Flex Net immediately (METHOD_UNAVAILABLE)',async()=>{
 for(const manifest of [httpCustomManifest,flexNetManifest]){
  const account=await newAccount(5);
  const started=await uploadJob(account,apkBytes(manifest()));
  const done=await finishUploaded(account,started);
  assert.equal(done.status,'REJECTED');
  assert.equal(done.errorCode,'METHOD_UNAVAILABLE');
  assert.equal((await creditBalance(account,{db})).available,5);
 }
});

test('finish reads the manifest out of an .apks (base.apk split)',async()=>{
 const account=await newAccount(5);
 const started=await uploadJob(account,apksBytes(vpnManifest()),{filename:'sample.apks'});
 const done=await finishUploaded(account,started);
 assert.equal(done.status,'QUEUED_FOR_ANALYSIS');
 assert.equal(done.packageName,'com.example.vpnapp');
});

test('webhook carries only opaque identifiers and verifies HMAC',async()=>{
 const account=await newAccount(5);
 const captured=[];
 const send=async(url,options)=>{captured.push({url,options});return {ok:true,status:200};};
 const webhookEnv={...env,SPDECODE_APP_ANALYSIS_WEBHOOK_URL:'https://yamada.example.invalid/hook',
   SPDECODE_APP_ANALYSIS_WEBHOOK_SECRET:'webhook-secret-'.repeat(3)};
 const apk=apkBytes(vpnManifest());
 const started=await uploadJob(account,apk);
 await finishUploaded(account,started,{send,env:webhookEnv});
 assert.equal(captured.length,1);
 const body=JSON.parse(captured[0].options.body);
 assert.deepEqual(Object.keys(body).sort(),['accountId','event','jobId','status']);
 assert.equal(body.event,'analysis.created');
 assert.equal(verifyWebhookSignature(webhookEnv.SPDECODE_APP_ANALYSIS_WEBHOOK_SECRET,
   body.event,body,Number(captured[0].options.headers['x-spdecode-timestamp']),
   captured[0].options.headers['x-spdecode-signature']),true);
 const signed=signWebhook('s'.repeat(32),'analysis.created',{jobId:'x'});
 assert.equal(verifyWebhookSignature('s'.repeat(32),'analysis.created',{jobId:'x'},
   signed.timestamp,signed.signature),true);
 assert.equal(verifyWebhookSignature('s'.repeat(32),'analysis.created',{jobId:'x'},
   signed.timestamp-3600,signed.signature),false);
});

test('events enforce the ANALYZING cap (default 1) and the 64-event cap',async()=>{
 const account=await newAccount(5);
 const job1=await finishUploaded(account,
   await uploadJob(account,apkBytes(vpnManifest())));
 assert.equal(job1.status,'QUEUED_FOR_ANALYSIS');
 const started=await recordEvent(job1.jobId,{code:'ANALYSIS_STARTED',status:'RUNNING'},{db,env});
 assert.equal(started.status,'ANALYZING');
 const job2=await finishUploaded(account,
   await uploadJob(account,apkBytes(vpnManifest())));
 await assert.rejects(recordEvent(job2.jobId,{code:'ANALYSIS_STARTED',status:'RUNNING'},{db,env}),
   /APP_ANALYSIS_BUSY/);
 await assert.rejects(recordEvent(job2.jobId,{code:'NOT_A_CODE',status:'RUNNING'},{db,env}),
   /INVALID_REQUEST/);
 for(let i=0;i<70;i++)
  await recordEvent(job1.jobId,{code:'ANALYSIS_HEARTBEAT',status:'RUNNING'},{db,env});
 const events=(await db.query(
   'SELECT COUNT(*)::integer AS n FROM spdecode_shop.app_analysis_events WHERE job_id=$1',
   [job1.jobId])).rows[0].n;
 assert.equal(events,64);
 // Free the ANALYZING slot for the tests below (cap is global, default 1).
 await failJob(job1.jobId,{errorCode:'ANALYSIS_FAILED'},{db,env});
});

test('complete charges the credit, serves a signed 24 h download, hides icon_ref',async()=>{
 const account=await newAccount(5);
 const job=await finishUploaded(account,await uploadJob(account,apkBytes(vpnManifest())));
 await recordEvent(job.jobId,{code:'ANALYSIS_STARTED',status:'RUNNING'},{db,env});
 const result=Buffer.from('PK\x03\x04fake-zip-scripts-only');
 const done=await completeJob(job.jobId,{resultBase64:result.toString('base64'),
   resultSha256:sha256(result),verdict:'completed',needsToken:false,
   isNewCatalogCandidate:true,providerId:'example-vpn',
   iconRef:'internal/catalog/example-vpn/icon.png',catalogRef:'internal/catalog/example-vpn/catalog.json'},
  {db,env,root});
 assert.equal(done.status,'COMPLETED');
 assert.equal(done.resultSha256,sha256(result));
 assert.equal((await creditBalance(account,{db})).available,4);
 assert.ok(done.downloadUrl?.includes('/download?exp='));
 assert.ok(done.downloadUrl?.startsWith('/api/v2/app-analysis/'+job.jobId+'/download'),
   'signed download must point at the V2 route, got '+done.downloadUrl);
 assert.equal(done.downloadUrl?.includes('/api/v1/'),false);
 assert.equal(JSON.stringify(done).includes('icon_ref'),false);
 assert.equal(JSON.stringify(done).includes('iconRef'),false);
 const view=await getJob(account,job.jobId,{db,env});
 assert.equal(view.status,'COMPLETED');
 assert.equal('iconRef' in view,false);
 const url=new URL('https://spdecode.xyz'+view.downloadUrl);
 assert.equal(verifyDownloadSignature(job.jobId,account,
   Number(url.searchParams.get('exp')),url.searchParams.get('sig'),env),true);
 assert.equal(verifyDownloadSignature(job.jobId,account,
   Number(url.searchParams.get('exp')),'0'.repeat(64),env),false);
 const candidates=await listCandidates({db});
 assert.equal(candidates.candidates.length,1);
 assert.equal(candidates.candidates[0].status,'pending');
 assert.equal(candidates.candidates[0].hasIcon,true);
 assert.equal('iconRef' in candidates.candidates[0],false);
 const other=await newAccount(0);
 await assert.rejects(getJob(other,job.jobId,{db,env}),/APP_ANALYSIS_ACCESS_DENIED/);
});

test('partial completion charges too; fail releases; candidate review is manual',async()=>{
 const account=await newAccount(5);
 const partial=await finishUploaded(account,await uploadJob(account,apkBytes(vpnManifest())));
 await recordEvent(partial.jobId,{code:'ANALYSIS_STARTED',status:'RUNNING'},{db,env});
 const result=Buffer.from('partial-result');
 const done=await completeJob(partial.jobId,{resultBase64:result.toString('base64'),
   resultSha256:sha256(result),verdict:'partial'},{db,env,root});
 assert.equal(done.status,'COMPLETED_PARTIAL');
 assert.equal((await creditBalance(account,{db})).available,4);
 const failing=await finishUploaded(account,await uploadJob(account,apkBytes(vpnManifest())));
 await recordEvent(failing.jobId,{code:'ANALYSIS_STARTED',status:'RUNNING'},{db,env});
 const failed=await failJob(failing.jobId,{errorCode:'ANALYSIS_FAILED'},{db,env});
 assert.equal(failed.status,'FAILED');
 assert.equal((await creditBalance(account,{db})).available,4);
 const admin=await listAdminJobs({db});
 assert.ok(admin.jobs.some(j=>j.jobId===partial.jobId&&j.accountId===account));
 assert.equal(admin.jobs.find(j=>j.jobId===partial.jobId).downloadUrl,null);
 const reviewed=await reviewCandidate({id:'owner-test',role:'owner'},
   {candidateId:(await listCandidates({db})).candidates[0].id,decision:'approved'},{db});
 assert.equal(reviewed.status,'approved');
 await assert.rejects(reviewCandidate({id:'owner-test',role:'owner'},
   {candidateId:(await listCandidates({db})).candidates[0].id,decision:'rejected'},{db}),
  /APP_ANALYSIS_CANDIDATE_REVIEWED/);
});

test('expired held reservations are released, but never for an active job',async()=>{
 const account=await newAccount(5);
 const active=await finishUploaded(account,await uploadJob(account,apkBytes(vpnManifest())));
 await recordEvent(active.jobId,{code:'ANALYSIS_STARTED',status:'RUNNING'},{db,env});
 await db.query(`UPDATE spdecode_shop.credit_reservations SET expires_at=now()-interval '1 hour'
   WHERE job_id=$1`,[active.jobId]);
 const stale=await finishUploaded(account,await uploadJob(account,apkBytes(vpnManifest())));
 await failJob(stale.jobId,{errorCode:'ANALYSIS_FAILED'},{db,env});
 // Re-hold the stale reservation on the failed (terminal) job to simulate an
 // abandoned held reservation, then sweep it.
 await db.query(`UPDATE spdecode_shop.credit_reservations
   SET state='held',expires_at=now()-interval '1 hour' WHERE job_id=$1`,
  [stale.jobId]);
 const out=await releaseExpiredReservations({db});
 assert.equal(out.released,1);
 const held=(await db.query(
   "SELECT state FROM spdecode_shop.credit_reservations WHERE job_id=$1 AND state='held'",
   [active.jobId])).rows;
 assert.equal(held.length,1);
 // Free the ANALYZING slot for the tests below (cap is global, default 1).
 await failJob(active.jobId,{errorCode:'ANALYSIS_FAILED'},{db,env});
});

test('sweep expires retained jobs past 30 days and deletes their files',async()=>{
 const account=await newAccount(5);
 const job=await finishUploaded(account,await uploadJob(account,apkBytes(vpnManifest())));
 await recordEvent(job.jobId,{code:'ANALYSIS_STARTED',status:'RUNNING'},{db,env});
 const result=Buffer.from('sweep-me');
 await completeJob(job.jobId,{resultBase64:result.toString('base64'),
   resultSha256:sha256(result),verdict:'completed'},{db,env,root});
 await db.query(`UPDATE spdecode_shop.app_analysis_jobs SET expires_at=now()-interval '1 day'
   WHERE job_id=$1`,[job.jobId]);
 const out=await sweepExpiredJobs({db,env,root});
 assert.equal(out.expired,1);
 assert.equal((await getJob(account,job.jobId,{db,env})).status,'EXPIRED');
});

test('bot token is required for bot routes; list shows only own jobs',async()=>{
 const req=new Request('https://spdecode.xyz/api/v2/app-analysis/x/events',
   {method:'POST',headers:{authorization:'Bearer wrong-token'}});
 assert.throws(()=>verifyBotToken(req,env),/APP_ANALYSIS_BOT_UNAUTHORIZED/);
 const ok=new Request('https://spdecode.xyz/api/v2/app-analysis/x/events',
   {method:'POST',headers:{authorization:'Bearer '+env.SPDECODE_APP_ANALYSIS_BOT_TOKEN}});
 verifyBotToken(ok,env);
 const a=await newAccount(5),b=await newAccount(5);
 await finishUploaded(a,await uploadJob(a,apkBytes(vpnManifest())));
 await finishUploaded(b,await uploadJob(b,apkBytes(vpnManifest())));
 assert.equal((await listJobs(a,{db,env})).jobs.length,1);
 assert.equal((await listJobs(b,{db,env})).jobs.length,1);
});

// ---------------------------------------------------------------------------
// V2 transport (ops 25-30): the client operations moved off /api/v1/*.
// Same auth model as apk-qa: bound V2 claims + accountToken in the body.
// The stub below mirrors verifyApkAccount (token 'token-<accountId>').
// ---------------------------------------------------------------------------
const V2_DEVICE_KEY='device-p256-public-key-verifiable-app-analysis-test';
async function stubAuthenticate(token){
 if(typeof token!=='string'||!token.startsWith('token-'))
  throw new ShopError('SIGN_IN_REQUIRED',401);
 return token.slice(6);
}
function v2Request(body,op,{bound=true,key=V2_DEVICE_KEY,hpke=true}={}){
 const req=new Request('https://spdecode.xyz/api/v2/transport',{method:'POST',
  headers:{'content-type':'application/json'},body:JSON.stringify(body)});
 if(bound)bindVerifiedRequest(req,{hpke,key,scope:'decode',versionCode:42});
 return req;
}
async function v2(op,body,accountId,opts={}){
 const req=v2Request({...body,accountToken:'token-'+accountId},op,opts);
 return appAnalysisRequest(req,op,{env,authenticate:stubAuthenticate,db,root});
}
async function v2UploadJob(accountId,apk,{filename='sample.apk'}={}){
 const started=await v2(26,{filename,totalBytes:apk.length,sha256:sha256(apk)},accountId);
 assert.equal(started.status,201);
 const {jobId,uploadToken}=await started.json();
 const data=apk.toString('base64');
 const chunk=await v2(27,{jobId,uploadToken,index:0,chunkSha256:sha256(apk),
   dataBase64:data},accountId);
 assert.equal(chunk.status,200);
 return {jobId,uploadToken};
}

test('V2 routing: ops 25-30 map to app-analysis, limits and integrity mirror apk-qa',()=>{
 for(const [op,route] of [[25,'app-analysis/preflight'],[26,'app-analysis/start'],
   [27,'app-analysis/chunk'],[28,'app-analysis/finish'],[29,'app-analysis/status'],
   [30,'app-analysis/history']])assert.equal(routes[op],route);
 assert.equal(bodyLimit(27),3*1024*1024);
 for(const op of [25,26,28,29,30])assert.equal(bodyLimit(op),4096);
 assert.equal(protectedActions.has(26),true);
 assert.equal(protectedActions.has(28),true);
 for(const op of [25,27,29,30])assert.equal(protectedActions.has(op),false);
 assert.equal(routes[5],'decode/file');
});

test('V2 preflight: real balance at zero and positive credits',async()=>{
 const poor=await newAccount(0);
 const denied=await v2(25,{},poor);
 assert.equal(denied.status,200);
 assert.equal((await denied.json()).creditsAvailable,0);
 const rich=await newAccount(5);
 const ok=await v2(25,{},rich);
 assert.equal(ok.status,200);
 const body=await ok.json();
 assert.equal(body.creditsAvailable,5);
 assert.equal(body.creditPriceCents,399);
 assert.equal(body.currency,'USD');
});

test('V2 start reserves 1 credit and ignores a client-supplied deviceKeyHash',async()=>{
 const account=await newAccount(5);
 const res=await v2(26,{filename:'sample.apk',totalBytes:1000,sha256:'a'.repeat(64),
   deviceKeyHash:'f'.repeat(64)},account);
 assert.equal(res.status,201);
 const started=await res.json();
 assert.match(started.jobId,/^[0-9a-f-]{36}$/);
 assert.equal(started.chunkBytes,2*1024*1024);
 assert.equal(started.status,'UPLOADING');
 assert.equal(started.uploadToken.length,43);
 assert.equal((await creditBalance(account,{db})).available,4);
 const row=(await db.query(
   'SELECT device_key_hash FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',
   [started.jobId])).rows[0];
 assert.equal(row.device_key_hash,sha256(V2_DEVICE_KEY));
 assert.notEqual(row.device_key_hash,'f'.repeat(64));
});

test('V2 chunk 2 MB + finish queues, status and history follow',async()=>{
 const account=await newAccount(5);
 const apk=buildZip([{name:'AndroidManifest.xml',data:vpnManifest()},
   {name:'assets/pad.bin',data:Buffer.alloc(2*1024*1024)}]);
 assert.ok(apk.length>2*1024*1024);
 const started=await v2(26,{filename:'sample.apk',totalBytes:apk.length,
   sha256:sha256(apk)},account);
 assert.equal(started.status,201);
 const {jobId,uploadToken}=await started.json();
 const first=apk.subarray(0,2*1024*1024),rest=apk.subarray(2*1024*1024);
 const c0=await v2(27,{jobId,uploadToken,index:0,chunkSha256:sha256(first),
   dataBase64:first.toString('base64')},account);
 assert.equal(c0.status,200);
 assert.deepEqual(await c0.json(),{jobId,receivedBytes:2*1024*1024,nextChunk:1,
   status:'UPLOADING'});
 const c1=await v2(27,{jobId,uploadToken,index:1,chunkSha256:sha256(rest),
   dataBase64:rest.toString('base64')},account);
 assert.equal(c1.status,200);
 assert.equal((await c1.json()).receivedBytes,apk.length);
 const fin=await v2(28,{jobId,uploadToken},account);
 assert.equal(fin.status,200);
 const done=await fin.json();
 assert.equal(done.status,'QUEUED_FOR_ANALYSIS');
 assert.equal(done.packageName,'com.example.vpnapp');
 const st=await v2(29,{jobId},account);
 assert.equal(st.status,200);
 assert.equal((await st.json()).status,'QUEUED_FOR_ANALYSIS');
 const hist=await v2(30,{},account);
 assert.equal(hist.status,200);
 const jobs=(await hist.json()).jobs;
 assert.equal(jobs.length,1);
 assert.equal(jobs[0].jobId,jobId);
});

test('V2 rejects unbound callers, bad account tokens, non-POST and unknown ops',async()=>{
 const account=await newAccount(5);
 const unbound=await appAnalysisRequest(v2Request({accountToken:'token-'+account},25,
   {bound:false}),25,{env,authenticate:stubAuthenticate,db,root});
 assert.equal(unbound.status,401);
 const noHpke=await appAnalysisRequest(v2Request({accountToken:'token-'+account},25,
   {hpke:false}),25,{env,authenticate:stubAuthenticate,db,root});
 assert.equal(noHpke.status,401);
 const shortKey=await appAnalysisRequest(v2Request({accountToken:'token-'+account},25,
   {key:'short'}),25,{env,authenticate:stubAuthenticate,db,root});
 assert.equal(shortKey.status,401);
 const badTokenReq=v2Request({accountToken:'bogus'},25);
 const badToken=await appAnalysisRequest(badTokenReq,25,
   {env,authenticate:stubAuthenticate,db,root});
 assert.equal(badToken.status,401);
 assert.deepEqual(await badToken.json(),{error:{code:'SIGN_IN_REQUIRED'}});
 const noToken=await appAnalysisRequest(v2Request({},25),25,
   {env,authenticate:stubAuthenticate,db,root});
 assert.equal(noToken.status,401);
 const unknown=await appAnalysisRequest(v2Request({},31),31,
   {env,authenticate:stubAuthenticate,db,root});
 assert.equal(unknown.status,400);
 assert.deepEqual(await unknown.json(),{error:{code:'INVALID_REQUEST'}});
 const getReq=new Request('https://spdecode.xyz/api/v2/transport',{method:'GET',
  headers:{'content-type':'application/json'},body:null});
 bindVerifiedRequest(getReq,{hpke:true,key:V2_DEVICE_KEY,scope:'decode',versionCode:42});
 const get=await appAnalysisRequest(getReq,25,
   {env,authenticate:stubAuthenticate,db,root});
 assert.equal(get.status,405);
 const other=await newAccount(5);
 const started=await v2UploadJob(account,apkBytes(vpnManifest()));
 const foreign=await v2(29,{jobId:started.jobId},other);
 assert.equal(foreign.status,403);
 assert.deepEqual(await foreign.json(),{error:{code:'APP_ANALYSIS_ACCESS_DENIED'}});
});

test('V2 full flow: signed download points at /api/v2 and verifies',async()=>{
 const account=await newAccount(5);
 const {jobId,uploadToken}=await v2UploadJob(account,apkBytes(vpnManifest()));
 const done=await v2(28,{jobId,uploadToken},account);
 assert.equal(done.status,200);
 assert.equal((await done.json()).status,'QUEUED_FOR_ANALYSIS');
 await recordEvent(jobId,{code:'ANALYSIS_STARTED',status:'RUNNING'},{db,env});
 const result=Buffer.from('PK\x03\x04v2-fake-zip-scripts-only');
 const completed=await completeJob(jobId,{resultBase64:result.toString('base64'),
   resultSha256:sha256(result),verdict:'completed'},{db,env,root});
 assert.equal(completed.status,'COMPLETED');
 const view=await v2(29,{jobId},account);
 assert.equal(view.status,200);
 const job=await view.json();
 assert.ok(job.downloadUrl.startsWith('/api/v2/app-analysis/'+jobId+'/download?exp='),
   'download must be V2, got '+job.downloadUrl);
 assert.equal(job.downloadUrl.includes('/api/v1/'),false);
 const url=new URL('https://spdecode.xyz'+job.downloadUrl);
 assert.equal(verifyDownloadSignature(jobId,account,
   Number(url.searchParams.get('exp')),url.searchParams.get('sig'),env),true);
});

test('V2 bot routes reject a bad bot token and bad ids without touching the DB',async()=>{
 const params=async jobId=>({jobId});
 const bad={headers:{authorization:'Bearer wrong-token','content-type':'application/json'}};
 const body=JSON.stringify({code:'ANALYSIS_HEARTBEAT',status:'RUNNING'});
 for(const [handler,name] of [[v2EventsPost,'events'],[v2CompletePost,'complete'],
   [v2FailPost,'fail']]){
  const res=await handler(new Request('https://spdecode.xyz/api/v2/app-analysis/x/'+name,
    {method:'POST',...bad,body}),{params:params('x')});
  assert.equal(res.status,401,name);
  assert.deepEqual(await res.json(),{error:{code:'APP_ANALYSIS_BOT_UNAUTHORIZED'}},name);
 }
 const good={headers:{authorization:'Bearer '+env.SPDECODE_APP_ANALYSIS_BOT_TOKEN,
   'content-type':'application/json'}};
 const badId=await v2EventsPost(new Request(
   'https://spdecode.xyz/api/v2/app-analysis/not-a-uuid/events',
   {method:'POST',...good,body}),{params:params('not-a-uuid')});
 assert.equal(badId.status,400);
 assert.deepEqual(await badId.json(),{error:{code:'INVALID_REQUEST'}});
 const dl=await v2DownloadGet(new Request(
   'https://spdecode.xyz/api/v2/app-analysis/not-a-uuid/download'),
  {params:params('not-a-uuid')});
 assert.equal(dl.status,400);
 assert.deepEqual(await dl.json(),{error:{code:'INVALID_REQUEST'}});
});

test('V1 app-analysis routes no longer exist on disk',()=>{
 assert.equal(existsSync(new URL('../app/api/v1/app-analysis',import.meta.url)),false);
 for(const route of ['route.js','preflight/route.js','start/route.js','chunk/route.js',
   'finish/route.js','[jobId]/route.js','[jobId]/download/route.js',
   '[jobId]/events/route.js','[jobId]/complete/route.js','[jobId]/fail/route.js'])
  assert.equal(existsSync(new URL('../app/api/v1/app-analysis/'+route,import.meta.url)),
   false,route);
 for(const route of ['[jobId]/download/route.js','[jobId]/events/route.js',
   '[jobId]/complete/route.js','[jobId]/fail/route.js'])
  assert.equal(existsSync(new URL('../app/api/v2/app-analysis/'+route,import.meta.url)),
   true,route);
});

test('HPKE binary tail: op 27 synthesizes dataBase64 like op 22',()=>{
 const meta={jobId:'x',uploadToken:'y',index:0,chunkSha256:'a'.repeat(64)};
 const header=Buffer.from(JSON.stringify(meta));
 const tail=Buffer.from([1,2,3,4,5]);
 const pack=(head,body)=>{
  const raw=Buffer.alloc(4+head.length+body.length);
  raw.writeUInt32BE(head.length,0);head.copy(raw,4);body.copy(raw,4+head.length);
  return raw;
 };
 const out=JSON.parse(unpackHpkeBody(pack(header,tail),27));
 assert.equal(out.dataBase64,tail.toString('base64'));
 assert.equal(out.jobId,'x');
 assert.equal(out.index,0);
 // A chunk with no bytes is not a chunk.
 assert.throws(()=>unpackHpkeBody(pack(header,Buffer.alloc(0)),27),/HPKE_INVALID/);
 // dataBase64 already present in the metadata: reject, never trust both.
 const dup=Buffer.from(JSON.stringify({...meta,dataBase64:'AAAA'}));
 assert.throws(()=>unpackHpkeBody(pack(dup,tail),27),/HPKE_INVALID/);
 // Tail over the 2 MB chunk cap: reject.
 assert.throws(()=>unpackHpkeBody(pack(header,Buffer.alloc(2*1024*1024+1)),27),
   /HPKE_INVALID/);
 // op 22 keeps its exact behaviour (regression guard).
 assert.equal(JSON.parse(unpackHpkeBody(pack(header,tail),22)).dataBase64,
   tail.toString('base64'));
 // Any other op with a tail is still rejected.
 assert.throws(()=>unpackHpkeBody(pack(header,tail),25),/HPKE_INVALID/);
 assert.throws(()=>unpackHpkeBody(pack(header,tail),26),/HPKE_INVALID/);
});

test('V2 chunk 27 via HPKE binary tail reaches appendChunk as dataBase64',async()=>{
 const account=await newAccount(5);
 const apk=buildZip([{name:'AndroidManifest.xml',data:vpnManifest()},
   {name:'assets/pad.bin',data:Buffer.alloc(2*1024*1024)}]);
 const started=await v2(26,{filename:'sample.apk',totalBytes:apk.length,
   sha256:sha256(apk)},account);
 assert.equal(started.status,201);
 const {jobId,uploadToken}=await started.json();
 const first=apk.subarray(0,2*1024*1024);
 // What the HPKE transport delivers after decryption: JSON metadata
 // (with the accountToken inside, like the client sends it) + the raw
 // 2 MB tail. unpackHpkeBody turns the tail into dataBase64.
 const meta={jobId,uploadToken,index:0,chunkSha256:sha256(first),
   accountToken:'token-'+account};
 const header=Buffer.from(JSON.stringify(meta));
 const raw=Buffer.alloc(4+header.length+first.length);
 raw.writeUInt32BE(header.length,0);header.copy(raw,4);first.copy(raw,4+header.length);
 const decoded=unpackHpkeBody(raw,27);
 // The decoded JSON (metadata + ~2.8 MB of Base64) must fit the op-27
 // body limit the transport enforces after decryption.
 assert.ok(decoded.length<=bodyLimit(27),
   'decoded chunk is '+decoded.length+' bytes, limit '+bodyLimit(27));
 const req=new Request('https://spdecode.xyz/api/v2/transport',{method:'POST',
  headers:{'content-type':'application/json'},body:decoded});
 bindVerifiedRequest(req,{hpke:true,key:V2_DEVICE_KEY,scope:'decode',versionCode:42});
 const res=await appAnalysisRequest(req,27,{env,authenticate:stubAuthenticate,db,root});
 assert.equal(res.status,200);
 assert.deepEqual(await res.json(),{jobId,receivedBytes:2*1024*1024,nextChunk:1,
   status:'UPLOADING'});
 const row=(await db.query(
   'SELECT received_bytes FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',
   [jobId])).rows[0];
 assert.equal(Number(row.received_bytes),2*1024*1024);
});


test('preflight returns only the enabled support agent public avatar',async()=>{
 const account=await newAccount(1),id=randomUUID();
 const avatar='data:image/jpeg;base64,c3ludGhldGlj';
 await db.query(`INSERT INTO spdecode_shop.staff_accounts(id,username,display_name,role,password_hash,avatar)
 VALUES($1,'synthetic.yamada','Yamada','support',$2,$3)`,[id,'x'.repeat(64),avatar]);
 try{
  const info=await preflight(account,{db,env});
  assert.deepEqual(info.agent,{name:'Yamada',role:'support_ai',avatar});
  assert(!JSON.stringify(info).includes(id));
  assert(!JSON.stringify(info).includes('synthetic.yamada'));
  assert(!JSON.stringify(info).includes('x'.repeat(64)));
  await db.query('UPDATE spdecode_shop.staff_accounts SET enabled=false WHERE id=$1',[id]);
  assert.equal((await preflight(account,{db,env})).agent.avatar,null);
 }finally{await db.query('DELETE FROM spdecode_shop.staff_accounts WHERE id=$1',[id]);}
});
