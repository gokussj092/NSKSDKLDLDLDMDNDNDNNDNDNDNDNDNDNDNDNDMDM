import test from 'node:test';
import assert from 'node:assert/strict';
import {before,after} from 'node:test';
import {readFile} from 'node:fs/promises';
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
 for(const name of ['002_shop.sql','005_account_support_apk.sql','007_staff_permissions.sql','008_account_notifications.sql','012_app_analysis.sql']){
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

test('preflight is server-authoritative: 402 without credits, price from server',async()=>{
 const poor=await newAccount(0);
 await assert.rejects(preflight(poor,{db}),/INSUFFICIENT_CREDITS/);
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
 const req=new Request('https://spdecode.xyz/api/v1/app-analysis/x/events',
   {method:'POST',headers:{authorization:'Bearer wrong-token'}});
 assert.throws(()=>verifyBotToken(req,env),/APP_ANALYSIS_BOT_UNAUTHORIZED/);
 const ok=new Request('https://spdecode.xyz/api/v1/app-analysis/x/events',
   {method:'POST',headers:{authorization:'Bearer '+env.SPDECODE_APP_ANALYSIS_BOT_TOKEN}});
 verifyBotToken(ok,env);
 const a=await newAccount(5),b=await newAccount(5);
 await finishUploaded(a,await uploadJob(a,apkBytes(vpnManifest())));
 await finishUploaded(b,await uploadJob(b,apkBytes(vpnManifest())));
 assert.equal((await listJobs(a,{db,env})).jobs.length,1);
 assert.equal((await listJobs(b,{db,env})).jobs.length,1);
});
