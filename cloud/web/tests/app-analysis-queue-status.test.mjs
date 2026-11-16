import test from 'node:test';
import assert from 'node:assert/strict';
import {before,after} from 'node:test';
import {readFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {countQueuedJobs} from '../lib/app-analysis.mjs';
import {GET as queueStatusGet} from '../app/api/app-analysis/queue-status/route.js';

let pg,db,auth,root;
const env={...process.env,NODE_ENV:'test',
 CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgres://synthetic',
 BETTER_AUTH_SECRET:'test-only-secret-not-a-real-credential-0123456789',
 GOOGLE_CLIENT_ID:'synthetic.apps.googleusercontent.com',GOOGLE_CLIENT_SECRET:'synthetic',
 SPDECODE_ANALYSIS_CREDITS_READY:'true',SPDECODE_APP_ANALYSIS_ENABLED:'true',
 SPDECODE_APP_ANALYSIS_DOWNLOAD_SECRET:'test-only-download-secret-0123456789',
 SPDECODE_APP_ANALYSIS_BOT_TOKEN:'test-only-bot-token-0123456789abcdef0123456789'};
Object.assign(process.env,env);

before(async()=>{
 root=await mkdtemp(join(tmpdir(),'spdecode-queue-status-'));
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

async function newAccount(){
 const id=randomUUID();
 await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
   VALUES($1,$2,$3,true,now(),now())`,[id,'Queue User',id+'@example.invalid']);
 return id;
}
async function clearJobs(){
 await db.query(`DELETE FROM spdecode_shop.app_analysis_jobs`);
}
async function insertJob(accountId,status,packageName='com.example.vpnapp'){
 const id=randomUUID();
 await db.query(`INSERT INTO spdecode_shop.app_analysis_jobs
   (job_id,account_id,device_key_hash,upload_token_hash,filename,package_name,
    app_name,input_sha256,input_bytes,status)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
  [id,accountId,'a'.repeat(64),'b'.repeat(64),'sample.apk',packageName,
   'Test App','c'.repeat(64),1000,status]);
 return id;
}
async function getQueued(){
 const res=await queueStatusGet(
  new Request('https://spdecode.xyz/api/app-analysis/queue-status'),{db});
 assert.equal(res.status,200);
 return res;
}

test('countQueuedJobs returns 0 on an empty queue',async()=>{
 await clearJobs();
 assert.equal(await countQueuedJobs({db}),0);
});

test('GET returns {queued:0} with no user data when empty',async()=>{
 await clearJobs();
 const res=await getQueued();
 const text=await res.text();
 assert.deepEqual(JSON.parse(text),{queued:0});
 assert.equal(Object.keys(JSON.parse(text)).join(), 'queued');
 for(const leak of ['jobId','accountId','package','com.example'])
  assert.equal(text.includes(leak),false,leak);
});

test('countQueuedJobs counts only QUEUED_FOR_ANALYSIS',async()=>{
 await clearJobs();
 const account=await newAccount();
 await insertJob(account,'QUEUED_FOR_ANALYSIS');
 await insertJob(account,'QUEUED_FOR_ANALYSIS','com.example.secondapp');
 await insertJob(account,'ANALYZING');
 await insertJob(account,'COMPLETED');
 await insertJob(account,'FAILED');
 await insertJob(account,'UPLOADING');
 assert.equal(await countQueuedJobs({db}),2);
});

test('GET returns the queued count and nothing else',async()=>{
 await clearJobs();
 const account=await newAccount();
 await insertJob(account,'QUEUED_FOR_ANALYSIS');
 await insertJob(account,'QUEUED_FOR_ANALYSIS');
 await insertJob(account,'ANALYZING');
 const res=await getQueued();
 const text=await res.text();
 assert.deepEqual(JSON.parse(text),{queued:2});
 assert.equal(Object.keys(JSON.parse(text)).join(),'queued');
 for(const leak of ['jobId','accountId','package','com.example'])
  assert.equal(text.includes(leak),false,leak);
});

test('route is public: no auth/session code, not under /api/v1',async()=>{
 const src=await readFile(new URL('../app/api/app-analysis/queue-status/route.js',import.meta.url),'utf8');
 for(const leak of ['requirePanel','requireAccount','verifyBotToken','authenticate','cookie','authorization'])
  assert.equal(src.includes(leak),false,leak);
 assert.equal(existsSync(new URL('../app/api/app-analysis/queue-status/route.js',import.meta.url)),true);
 assert.equal(existsSync(new URL('../app/api/v1/app-analysis/queue-status/route.js',import.meta.url)),false);
});
