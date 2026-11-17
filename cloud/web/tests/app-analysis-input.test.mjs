import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash,randomUUID,randomBytes} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {creditBalance} from '../lib/commerce/credits.mjs';
import {signDownload} from '../lib/app-analysis.mjs';
import {INPUT_LINK_TTL_SECONDS} from '../lib/app-analysis-input.mjs';
import {GET as download,HEAD as head} from '../app/api/v2/app-analysis/[jobId]/input/route.js';
import {GET as link} from '../app/api/v2/app-analysis/[jobId]/input-link/route.js';
import {GET as queue} from '../app/api/v2/app-analysis/queue/route.js';
import {GET as publicQueue} from '../app/api/app-analysis/queue-status/route.js';

let root,pg,db;
const origin='https://api.spdecode.xyz';
const env={...process.env,NODE_ENV:'test',CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 CLOUD_API_PUBLIC_ORIGIN:origin,SPDECODE_ACCOUNTS_ENABLED:'true',
 SPDECODE_DATABASE_URL:'postgres://synthetic',BETTER_AUTH_SECRET:randomBytes(32).toString('hex'),
 GOOGLE_CLIENT_ID:'synthetic.apps.googleusercontent.com',GOOGLE_CLIENT_SECRET:'synthetic',
 SPDECODE_APP_ANALYSIS_DOWNLOAD_SECRET:randomBytes(32).toString('hex'),
 SPDECODE_APP_ANALYSIS_BOT_TOKEN:randomBytes(32).toString('hex')};
const bot={authorization:'Bearer '+env.SPDECODE_APP_ANALYSIS_BOT_TOKEN};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const url=(id,action='input')=>origin+'/api/v2/app-analysis/'+id+'/'+action;
const context=id=>({params:Promise.resolve({jobId:id}),db,env,root});

before(async()=>{
 root=await mkdtemp(join(tmpdir(),'spdecode-input-access-'));
 pg=new PGlite();
 const query=async(sql,params=[])=>{const r=await pg.query(sql,params);
  return {rows:r.rows,rowCount:r.rows.length||r.affectedRows||0};};
 db={query,connect:async()=>({query,release(){}})};
 const auth=makeAuth(db,env);
 await (await getMigrations(auth.options)).runMigrations();
 for(const name of ['002_shop.sql','005_account_support_apk.sql','007_staff_permissions.sql',
   '008_account_notifications.sql','012_app_analysis.sql'])
  await pg.exec(await readFile(new URL('../sql/'+name,import.meta.url),'utf8'));
});
after(async()=>{await pg?.close();await rm(root,{recursive:true,force:true});});

async function fixture({status='QUEUED_FOR_ANALYSIS',filename='DeepTune-VPN-test.apk',
 expires=new Date(Date.now()+86400000),bytes=Buffer.from('synthetic APK input bytes')}={}){
 const id=randomUUID(),owner=randomUUID();
 await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
  VALUES($1,'Input Test',$2,true,now(),now())`,[owner,owner+'@example.invalid']);
 await db.query(`INSERT INTO spdecode_shop.credit_ledger
  (id,account_id,movement_kind,delta,payment_live) VALUES($1,$2,'grant',3,false)`,[randomUUID(),owner]);
 await db.query(`INSERT INTO spdecode_shop.app_analysis_jobs
  (job_id,account_id,device_key_hash,upload_token_hash,filename,package_name,app_name,
   input_sha256,input_bytes,received_bytes,status,expires_at)
  VALUES($1,$2,$3,$4,$5,'com.example.vpn','Synthetic VPN',$6,$7,$7,$8,$9)`,
  [id,owner,'a'.repeat(64),'b'.repeat(64),filename,sha(bytes),bytes.length,status,expires]);
 await mkdir(join(root,id),{mode:0o700});
 await writeFile(join(root,id,'input.apk'),bytes,{mode:0o600});
 return {id,owner,bytes};
}
async function issue(f,options={}){
 const r=await link(new Request(url(f.id,'input-link'),{headers:bot}),{...context(f.id),...options});
 assert.equal(r.status,200,await r.clone().text());return r.json();
}
async function error(response,status,code){
 assert.equal(response.status,status);
 assert.equal((await response.json()).error.code,code);
}

test('all bot entry points reject anonymous/account-only requests before querying files or DB',async()=>{
 const id=randomUUID(),blockedDb={query(){throw Error('DB must not be touched');}};
 for(const headers of [{},{cookie:'a-panel-or-owner-session=not-a-bot-token'},
   {authorization:'Bearer invalid-service-token'}]){
  await error(await download(new Request(url(id),{headers}),{...context(id),db:blockedDb}),
    401,'APP_ANALYSIS_BOT_UNAUTHORIZED');
  await error(await link(new Request(url(id,'input-link'),{headers}),{...context(id),db:blockedDb}),
    401,'APP_ANALYSIS_BOT_UNAUTHORIZED');
  await error(await queue(new Request(origin+'/api/v2/app-analysis/queue',{headers}),{db:blockedDb,env}),
    401,'APP_ANALYSIS_BOT_UNAUTHORIZED');
 }
});

test('already queued source downloads with the existing bot token, before a result exists',async()=>{
 const f=await fixture();
 const r=await download(new Request(url(f.id),{headers:bot}),context(f.id));
 assert.equal(r.status,200);
 assert.deepEqual(Buffer.from(await r.arrayBuffer()),f.bytes);
 assert.equal(r.headers.get('x-input-sha256'),sha(f.bytes));
 assert.equal(r.headers.get('content-length'),String(f.bytes.length));
 assert.match(r.headers.get('content-disposition'),/DeepTune-VPN-test\.apk/);
 assert.equal(r.headers.get('content-type'),'application/vnd.android.package-archive');
 assert.match(r.headers.get('cache-control'),/no-store/);
 assert.equal(r.headers.get('referrer-policy'),'no-referrer');
 const row=(await db.query('SELECT result_sha256,status FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[f.id])).rows[0];
 assert.equal(row.result_sha256,null);assert.equal(row.status,'QUEUED_FOR_ANALYSIS');
});

test('a bot-issued 15-minute link works without cookies, Authorization, or an owner session',async()=>{
 const f=await fixture({filename:'split-test.apks'}),cap=await issue(f);
 const u=new URL(cap.inputDownloadUrl);
 assert.equal(u.origin,origin);assert.equal(u.pathname,'/api/v2/app-analysis/'+f.id+'/input');
 assert.ok(Number(u.searchParams.get('exp'))<=Math.floor(Date.now()/1000)+INPUT_LINK_TTL_SECONDS);
 assert.equal(cap.sha256,sha(f.bytes));assert.equal(cap.bytes,f.bytes.length);
 const r=await download(new Request(u),context(f.id));
 assert.equal(r.status,200);assert.deepEqual(Buffer.from(await r.arrayBuffer()),f.bytes);
 assert.equal(r.headers.get('content-type'),'application/zip');
 assert.match(r.headers.get('content-disposition'),/split-test\.apks/);
 for(const secret of [env.SPDECODE_APP_ANALYSIS_BOT_TOKEN,env.SPDECODE_APP_ANALYSIS_DOWNLOAD_SECRET,f.owner])
  assert.equal(JSON.stringify(cap).includes(secret),false);
});

test('source capabilities reject changed signatures, expiry, other jobs and result-link replay',async()=>{
 const f=await fixture(),other=await fixture(),cap=await issue(f),u=new URL(cap.inputDownloadUrl);
 const variants=[];
 for(const [key,value] of [['sig','0'.repeat(64)],['exp',String(Math.floor(Date.now()/1000)-1)],
   ['exp',String(Math.floor(Date.now()/1000)+INPUT_LINK_TTL_SECONDS+100)]]){
  const changed=new URL(u);changed.searchParams.set(key,value);variants.push(changed);
 }
 const different=new URL(u);different.pathname='/api/v2/app-analysis/'+other.id+'/input';variants.push(different);
 // Keep the result-link expiry inside the input window: rejection must
 // come from purpose binding, rather than just the shorter TTL.
 const result=new URL(origin+signDownload(f.id,f.owner,env,
   Math.floor(Date.now()/1000)-24*3600+300).url);
 result.pathname=u.pathname;variants.push(result);
 for(const candidate of variants){
  const id=candidate===different?other.id:f.id;
  await error(await download(new Request(candidate),context(id)),401,'APP_ANALYSIS_INPUT_UNAUTHORIZED');
 }
 // Neither input metadata nor another recipient can be substituted after issuance.
 await db.query('UPDATE spdecode_shop.app_analysis_jobs SET input_sha256=$2 WHERE job_id=$1',[f.id,'f'.repeat(64)]);
 await error(await download(new Request(u),context(f.id)),401,'APP_ANALYSIS_INPUT_UNAUTHORIZED');
 const absent=new URL(u);absent.pathname='/api/v2/app-analysis/'+randomUUID()+'/input';
 await error(await download(new Request(absent),context(absent.pathname.split('/')[4])),
   401,'APP_ANALYSIS_INPUT_UNAUTHORIZED');
});

test('HEAD and resumable ranges return exact bytes and reject invalid ranges',async()=>{
 const bytes=Buffer.from(Array.from({length:250},(_,i)=>i)),f=await fixture({bytes});
 const cap=await issue(f),u=new URL(cap.inputDownloadUrl);
 const h=await head(new Request(u,{method:'HEAD'}),context(f.id));
 assert.equal(h.status,200);assert.equal(h.body,null);assert.equal(h.headers.get('content-length'),'250');
 for(const [range,start,end] of [['bytes=10-24',10,24],['bytes=245-',245,249],['bytes=-7',243,249],['bytes=240-999',240,249]]){
  const r=await download(new Request(u,{headers:{range}}),context(f.id));
  assert.equal(r.status,206);assert.equal(r.headers.get('content-range'),`bytes ${start}-${end}/250`);
  assert.deepEqual(Buffer.from(await r.arrayBuffer()),bytes.subarray(start,end+1));
 }
 for(const range of ['bytes=250-','bytes=20-10','bytes=0-1,4-5','bytes=-0','bytes=-','bytes=999999999999999999999-']){
  const r=await download(new Request(u,{headers:{range}}),context(f.id));
  assert.equal(r.status,416);assert.equal(r.headers.get('content-range'),'bytes */250');await r.arrayBuffer();
 }
 const r=await download(new Request(u,{headers:{range:'bytes=1-4','if-range':'"different"'}}),context(f.id));
 assert.equal(r.status,200);assert.deepEqual(Buffer.from(await r.arrayBuffer()),bytes);
});

test('unfinished, rejected, failed and expired inputs cannot be handed off',async()=>{
 for(const status of ['UPLOADING','UPLOADED','REJECTED','FAILED','EXPIRED']){
  const f=await fixture({status}),code=status==='EXPIRED'?'APP_ANALYSIS_JOB_EXPIRED':'APP_ANALYSIS_INPUT_NOT_READY';
  const expected=status==='EXPIRED'?410:409;
  await error(await download(new Request(url(f.id),{headers:bot}),context(f.id)),expected,code);
  await error(await link(new Request(url(f.id,'input-link'),{headers:bot}),context(f.id)),expected,code);
 }
 const f=await fixture({expires:new Date(Date.now()-1000)});
 await error(await download(new Request(url(f.id),{headers:bot}),context(f.id)),410,'APP_ANALYSIS_JOB_EXPIRED');
});

test('missing/truncated files, symlinks and invalid paths never expose another local file',async()=>{
 const missing=await fixture();await rm(join(root,missing.id,'input.apk'));
 await error(await download(new Request(url(missing.id),{headers:bot}),context(missing.id)),503,'APP_ANALYSIS_INPUT_UNAVAILABLE');
 const short=await fixture();await writeFile(join(root,short.id,'input.apk'),'x');
 await error(await download(new Request(url(short.id),{headers:bot}),context(short.id)),503,'APP_ANALYSIS_INPUT_UNAVAILABLE');
 const f=await fixture(),outside=join(root,'private-test-file');await writeFile(outside,f.bytes);
 await rm(join(root,f.id,'input.apk'));await symlink(outside,join(root,f.id,'input.apk'));
 await error(await download(new Request(url(f.id),{headers:bot}),context(f.id)),503,'APP_ANALYSIS_INPUT_UNAVAILABLE');
 await error(await download(new Request(origin+'/api/v2/app-analysis/invalid/input',{headers:bot}),context('../other')),400,'INVALID_REQUEST');
});

test('bot queue discovers queued jobs and creates links; anonymous watcher still returns only a count',async()=>{
 const f=await fixture();
 const r=await queue(new Request(origin+'/api/v2/app-analysis/queue',{headers:bot}),{db,env});
 assert.equal(r.status,200);const payload=await r.json();
 assert.ok(payload.jobs.some(x=>x.jobId===f.id));
 for(const row of payload.jobs){
  assert.ok(['QUEUED_FOR_ANALYSIS','ANALYZING','AWAITING_HUMAN'].includes(row.status));
  assert.ok(row.inputDownloadUrl);assert.equal('accountId' in row,false);
 }
 const count=await publicQueue(new Request('https://spdecode.xyz/api/app-analysis/queue-status'),{db});
 assert.equal(count.status,200);assert.deepEqual(Object.keys(await count.json()),['queued']);
});

test('reading or minting a link never charges credits, starts analysis, emits events or changes ownership',async()=>{
 const f=await fixture(),before=await creditBalance(f.owner,{db});
 const original=(await db.query('SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[f.id])).rows[0];
 const cap=await issue(f);
 const r=await download(new Request(cap.inputDownloadUrl),context(f.id));await r.arrayBuffer();
 assert.deepEqual(await creditBalance(f.owner,{db}),before);
 assert.deepEqual((await db.query('SELECT * FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',[f.id])).rows[0],original);
 assert.equal((await db.query('SELECT COUNT(*)::integer AS n FROM spdecode_shop.app_analysis_events WHERE job_id=$1',[f.id])).rows[0].n,0);
});

test('input link uses the configured API origin, rejects unsafe origins, and never reflects request Host',async()=>{
 const f=await fixture();
 const hostile=await link(new Request('https://untrusted.example/api/v2/app-analysis/'+f.id+'/input-link',
  {headers:{...bot,host:'untrusted.example','x-forwarded-host':'untrusted.example'}}),context(f.id));
 assert.equal(new URL((await hostile.json()).inputDownloadUrl).origin,origin);
 const noOrigin={...env};delete noOrigin.CLOUD_API_PUBLIC_ORIGIN;
 assert.equal(new URL((await issue(f,{env:noOrigin})).inputDownloadUrl).origin,origin);
 for(const raw of ['https://api.spdecode.xyz/path','https://user:pass@api.spdecode.xyz','http://api.spdecode.xyz']){
  const r=await link(new Request(url(f.id,'input-link'),{headers:bot}),
    {...context(f.id),env:{...env,CLOUD_API_PUBLIC_ORIGIN:raw}});
  await error(r,503,'APP_ANALYSIS_INPUT_LINK_NOT_CONFIGURED');
 }
});

test('missing signing configuration fails closed while a configured bot can still download directly',async()=>{
 const f=await fixture(),noSecret={...env,SPDECODE_APP_ANALYSIS_DOWNLOAD_SECRET:''};
 await error(await link(new Request(url(f.id,'input-link'),{headers:bot}),
  {...context(f.id),env:noSecret}),503,'APP_ANALYSIS_DOWNLOAD_NOT_CONFIGURED');
 const r=await download(new Request(url(f.id),{headers:bot}),{...context(f.id),env:noSecret});
 assert.equal(r.status,200);assert.deepEqual(Buffer.from(await r.arrayBuffer()),f.bytes);
 await error(await download(new Request(url(f.id)),{...context(f.id),env:noSecret}),
  401,'APP_ANALYSIS_BOT_UNAUTHORIZED');
});
