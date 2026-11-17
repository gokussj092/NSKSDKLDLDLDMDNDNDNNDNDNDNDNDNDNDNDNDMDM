import test from 'node:test';
import assert from 'node:assert/strict';
import {before,after} from 'node:test';
import {readFile,mkdtemp,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID,createHash,randomBytes,generateKeyPairSync} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {creditBalance} from '../lib/commerce/credits.mjs';
import {completeJob} from '../lib/app-analysis.mjs';
import {utcDayString,weekMondayString,weekDayIndex,emptyStreakState,
 deriveStreakState,chestJobId,getAccountStreak,recordDecodeDay,
 recordSuccessfulDecodeForDevice,recordDecodeStreak,configureStreakTimeZone,localDayString,validatedTimeZone} from '../lib/commerce/account-streak.mjs';

import {streakTimeZoneRequest} from '../lib/commerce/streak-route.mjs';
import {ShopError} from '../lib/commerce/config.mjs';

let pg,db,auth,root;
const accountId=randomUUID(),otherId=randomUUID();
const env={...process.env,NODE_ENV:'test',
 CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgres://synthetic',
BETTER_AUTH_SECRET:randomBytes(32).toString('hex'),
 GOOGLE_CLIENT_ID:'synthetic.apps.googleusercontent.com',GOOGLE_CLIENT_SECRET:'synthetic',
 SPDECODE_ANALYSIS_CREDITS_READY:'true',SPDECODE_APP_ANALYSIS_ENABLED:'true',
SPDECODE_APP_ANALYSIS_DOWNLOAD_SECRET:'download-secret-'.repeat(3),
SPDECODE_APP_ANALYSIS_BOT_TOKEN:'bot-token-'.repeat(5)};
Object.assign(process.env,env);
const at=iso=>new Date(iso+'T12:00:00.000Z');
// 2026-11-16 is a Monday; the test week is Mon 2026-11-16 .. Sun 2026-11-22.
const MON='2026-11-16',TUE='2026-11-17',WED='2026-11-18',THU='2026-11-19',
 FRI='2026-11-20',SAT='2026-11-21',SUN='2026-11-22';
const deviceKey=generateKeyPairSync('ec',{namedCurve:'prime256v1'})
 .publicKey.export({type:'spki',format:'der'}).toString('base64url');
before(async()=>{
 root=await mkdtemp(join(tmpdir(),'spdecode-streak-'));
 pg=new PGlite();
 const query=async(sql,params=[])=>{
  const r=await pg.query(sql,params);
  return {rows:r.rows,rowCount:r.rows.length||r.affectedRows||0};
 };
 db={query,connect:async()=>({query,release(){}})};
 auth=makeAuth(db,env);
 await (await getMigrations(auth.options)).runMigrations();
 for(const name of ['002_shop.sql','005_account_support_apk.sql',
   '008_account_notifications.sql','012_app_analysis.sql','014_account_streak.sql','015_streak_calendar.sql']){
  const sql=await readFile(new URL('../sql/'+name,import.meta.url),'utf8');
  await pg.exec(sql);
 }
 for(const [id,i] of [[accountId,0],[otherId,1]]){
  await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
    VALUES($1,$2,$3,true,now(),now())`,
   [id,'Streak Test '+i,'streak-test-'+i+'@example.invalid']);
 }
 await db.query(`INSERT INTO spdecode_shop.account_device_keys(account_id,key_id,public_key)
   VALUES($1,$2,$3)`,[accountId,randomUUID(),deviceKey]);
});
after(async()=>{await pg?.close();await rm(root,{recursive:true,force:true});});
async function resetStreak(id=accountId){
 await db.query('DELETE FROM spdecode_shop.account_streaks WHERE account_id=$1',[id]);
}
async function ledgerGrants(id=accountId){
 return (await db.query(`SELECT * FROM spdecode_shop.credit_ledger
   WHERE account_id=$1 AND movement_kind='grant'`,[id])).rows;
}

test('UTC week helpers: Monday starts the week, Sunday ends it',()=>{
 assert.equal(utcDayString(at(MON)),MON);
 assert.equal(weekDayIndex(at(MON)),0);
 assert.equal(weekDayIndex(at(SUN)),6);
 assert.equal(weekMondayString(at(MON)),MON);
 assert.equal(weekMondayString(at(WED)),MON);
 assert.equal(weekMondayString(at(SUN)),MON);
 assert.equal(weekMondayString(at('2026-11-15')),'2026-11-09');
 assert.equal(weekMondayString(at('2026-11-23')),'2026-11-23');
});

test('unknown account reads an empty streak',async()=>{
 assert.deepEqual(await getAccountStreak(randomUUID(),{db,today:at(MON)}),emptyStreakState(at(MON)));
 assert.deepEqual(deriveStreakState(null,at(MON)),emptyStreakState(at(MON)));
});

test('consecutive days add up; double record on the same day does not',async()=>{
 await resetStreak();
 const mon=await recordDecodeDay(accountId,{db,today:at(MON)});
 assert.equal(mon.currentStreakDays,1);
 assert.deepEqual(mon.weekCompleted,[true,false,false,false,false,false,false]);
 assert.equal(mon.chestOpen,false);
 assert.equal(mon.creditGranted,false);
 const again=await recordDecodeDay(accountId,{db,today:at(MON)});
 assert.equal(again.currentStreakDays,1);
 assert.deepEqual(again.weekCompleted,[true,false,false,false,false,false,false]);
 const tue=await recordDecodeDay(accountId,{db,today:at(TUE)});
 assert.equal(tue.currentStreakDays,2);
 assert.deepEqual(tue.weekCompleted,[true,true,false,false,false,false,false]);
 const row=(await db.query('SELECT * FROM spdecode_shop.account_streaks WHERE account_id=$1',
   [accountId])).rows[0];
 assert.equal(row.current_streak,2);
 assert.equal((await ledgerGrants()).length,0);
});

test('skipping one day restarts the streak at 1 (no grace day)',async()=>{
 await resetStreak();
 await recordDecodeDay(accountId,{db,today:at(MON)});
 const wed=await recordDecodeDay(accountId,{db,today:at(WED)});
 assert.equal(wed.currentStreakDays,1);
 // The week still remembers Monday, but the streak restarted.
 assert.deepEqual(wed.weekCompleted,[true,false,true,false,false,false,false]);
 // A stale streak reads as 0 without writing: last active Monday, read Friday.
 await resetStreak();
 await recordDecodeDay(accountId,{db,today:at(MON)});
 const stale=await getAccountStreak(accountId,{db,today:at(FRI)});
 assert.equal(stale.currentStreakDays,0);
 assert.deepEqual(stale.weekCompleted,[true,false,false,false,false,false,false]);
 assert.equal(stale.chestOpen,false);
 // Yesterday still counts: last active Monday, read Tuesday -> 1.
 const alive=await getAccountStreak(accountId,{db,today:at(TUE)});
 assert.equal(alive.currentStreakDays,1);
});

test('week rolls over on Monday but a Sunday->Monday streak continues',async()=>{
 await resetStreak();
 await recordDecodeDay(accountId,{db,today:at('2026-11-15')}); // Sunday
 const mon=await recordDecodeDay(accountId,{db,today:at(MON)});
 assert.equal(mon.currentStreakDays,2);
 assert.deepEqual(mon.weekCompleted,[true,false,false,false,false,false,false]);
 const row=(await db.query('SELECT * FROM spdecode_shop.account_streaks WHERE account_id=$1',
   [accountId])).rows[0];
 assert.equal(row.week_start.toISOString().slice(0,10),MON);
 // The old week reads as empty once the week has passed.
 const oldWeek=deriveStreakState(row,at('2026-11-23'));
 assert.deepEqual(oldWeek.weekCompleted,[false,false,false,false,false,false,false]);
});

test('completing all 7 days grants exactly one credit, once per week',async()=>{
 await resetStreak();
 let last=null;
 for(const day of [MON,TUE,WED,THU,FRI,SAT]){
  last=await recordDecodeDay(accountId,{db,today:at(day)});
  assert.equal(last.creditGranted,false);
  assert.equal(last.chestOpen,false);
 }
 const sun=await recordDecodeDay(accountId,{db,today:at(SUN)});
 assert.equal(sun.currentStreakDays,7);
 assert.deepEqual(sun.weekCompleted,[true,true,true,true,true,true,true]);
 assert.equal(sun.chestOpen,true);
 assert.equal(sun.creditGranted,true);
 const grants=await ledgerGrants();
 assert.equal(grants.length,1);
 assert.equal(grants[0].delta,1);
 assert.equal(grants[0].movement_kind,'grant');
 assert.equal(grants[0].job_id,chestJobId(accountId,MON));
 const balance=await creditBalance(accountId,{db});
 assert.equal(balance.balance,1);
 assert.equal(balance.available,1);
 // Re-recording Sunday (retry) grants nothing more.
 const retry=await recordDecodeDay(accountId,{db,today:at(SUN)});
 assert.equal(retry.creditGranted,false);
 assert.equal(retry.chestOpen,true);
 assert.equal((await ledgerGrants()).length,1);
 // Next Monday: a new week, chest closed, streak continues (7 -> 8).
 const next=await recordDecodeDay(accountId,{db,today:at('2026-11-23')});
 assert.equal(next.currentStreakDays,8);
 assert.equal(next.chestOpen,false);
 assert.deepEqual(next.weekCompleted,[true,false,false,false,false,false,false]);
 assert.equal((await ledgerGrants()).length,1);
});

test('chest job id is deterministic per account and week',()=>{
 assert.equal(chestJobId(accountId,MON),chestJobId(accountId,MON));
 assert.notEqual(chestJobId(accountId,MON),chestJobId(otherId,MON));
 assert.notEqual(chestJobId(accountId,MON),chestJobId(accountId,'2026-11-23'));
 assert.match(chestJobId(accountId,MON),
   /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('device key resolves to the linked account; unknown keys count nothing',async()=>{
 await resetStreak();
 const recorded=await recordSuccessfulDecodeForDevice(deviceKey,{db,today:at(MON)});
 assert.equal(recorded.currentStreakDays,1);
 assert.equal(await recordSuccessfulDecodeForDevice('no-such-key',{db,today:at(TUE)}),null);
 assert.equal(await recordSuccessfulDecodeForDevice('',{db,today:at(TUE)}),null);
 assert.equal(await recordSuccessfulDecodeForDevice(null,{db,today:at(TUE)}),null);
 // The unknown-key attempts did not advance the streak.
 assert.equal((await getAccountStreak(accountId,{db,today:at(TUE)})).currentStreakDays,1);
 // Gateway hook: bound V2 claims count, anything without a key does not.
 await resetStreak();
 const viaClaims=await recordDecodeStreak({key:deviceKey},{db,today:at(MON)});
 assert.equal(viaClaims.currentStreakDays,1);
 assert.equal(await recordDecodeStreak({},{db,today:at(TUE)}),null);
 assert.equal(await recordDecodeStreak(null,{db,today:at(TUE)}),null);
 assert.equal(await recordDecodeStreak({key:''},{db,today:at(TUE)}),null);
});

async function seedJob(jobId){
 const sha=createHash('sha256').update('x').digest('hex');
 await mkdir(join(root,jobId),{recursive:true,mode:0o700});
 await db.query(`INSERT INTO spdecode_shop.app_analysis_jobs
   (job_id,account_id,device_key_hash,upload_token_hash,filename,input_sha256,
    input_bytes,status)
   VALUES($1,$2,$3,$4,'test.apk',$5,100,'QUEUED_FOR_ANALYSIS')`,
  [jobId,accountId,sha,sha,sha]);
 await db.query(`INSERT INTO spdecode_shop.credit_reservations
   (id,account_id,job_id,payment_live,state) VALUES($1,$2,$3,false,'held')`,
  [randomUUID(),accountId,jobId]);
}
test('completeJob accepts an optional resultSummary and exposes it in the job',async()=>{
 const jobId=randomUUID();
 await seedJob(jobId);
 const result=Buffer.from('fake-result-zip');
 const done=await completeJob(jobId,{resultBase64:result.toString('base64'),
   resultSha256:createHash('sha256').update(result).digest('hex'),verdict:'completed',
   resultSummary:{servers:6,networks:101}},{db,env,root});
 assert.deepEqual(done.resultSummary,{servers:6,networks:101});
 // Charging still happens: the held credit is spent.
 assert.equal(done.creditState,'completed');
 const stored=(await db.query(
   'SELECT result_servers,result_networks FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',
   [jobId])).rows[0];
 assert.equal(stored.result_servers,6);
 assert.equal(stored.result_networks,101);
 // Without resultSummary the job exposes null, as before.
 const jobId2=randomUUID();
 await seedJob(jobId2);
 const done2=await completeJob(jobId2,{resultBase64:result.toString('base64'),
   resultSha256:createHash('sha256').update(result).digest('hex'),verdict:'completed'},
  {db,env,root});
 assert.equal(done2.resultSummary,null);
});

test('completeJob rejects an invalid resultSummary without changing the job',async()=>{
 const jobId=randomUUID();
 await seedJob(jobId);
 const result=Buffer.from('fake-result-zip');
 const sha=createHash('sha256').update(result).digest('hex');
 for(const bad of [{servers:-1},{servers:1.5},{servers:'6'},{networks:-2},
   {servers:6,extra:1},{servers:6,networks:null}]){
  await assert.rejects(
   completeJob(jobId,{resultBase64:result.toString('base64'),resultSha256:sha,
     verdict:'completed',resultSummary:bad},{db,env,root}),
   err=>err.code==='INVALID_REQUEST');
 }
 const row=(await db.query('SELECT status FROM spdecode_shop.app_analysis_jobs WHERE job_id=$1',
   [jobId])).rows[0];
 assert.equal(row.status,'QUEUED_FOR_ANALYSIS');
});

async function calendarAccount(){
 const id=randomUUID();
 await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
  VALUES($1,'Calendar Test',$2,true,now(),now())`,[id,id+'@example.invalid']);
 return id;
}
const hour=value=>new Date(value);
test('local midnight follows the locked account zone, never a changed phone zone or clock',async()=>{
 const id=await calendarAccount();
 let state=await configureStreakTimeZone(id,'America/Tijuana',{db,today:hour('2026-11-17T07:59:00Z')});
 assert.equal(state.today,'2026-11-16');assert.equal(state.currentStreakDays,0);
 assert.equal(state.timeZoneLocked,true);
 state=await recordDecodeDay(id,{db,today:hour('2026-11-17T07:59:30Z')});
 assert.equal(state.currentStreakDays,1);assert.equal(state.completedToday,true);
 state=await configureStreakTimeZone(id,'Pacific/Kiritimati',{db,today:hour('2026-11-17T07:59:45Z')});
 assert.equal(state.timeZone,'America/Tijuana');assert.equal(state.today,'2026-11-16');
 assert.equal(state.currentStreakDays,1);
 assert.equal((await recordDecodeDay(id,{db,today:hour('2026-11-17T07:59:59Z')})).currentStreakDays,1);
 state=await recordDecodeDay(id,{db,today:hour('2026-11-17T08:00:00Z')});
 assert.equal(state.today,'2026-11-17');assert.equal(state.currentStreakDays,2);
 assert.equal((await creditBalance(id,{db})).available,0);
});
test('daylight-saving transitions use local calendar dates, without an extra repeated day',async()=>{
 const id=await calendarAccount();
 await configureStreakTimeZone(id,'America/Tijuana',{db,today:hour('2026-11-01T07:30:00Z')});
 const first=await recordDecodeDay(id,{db,today:hour('2026-11-01T08:30:00Z')});
 const repeated=await recordDecodeDay(id,{db,today:hour('2026-11-01T09:30:00Z')});
 assert.equal(first.today,'2026-11-01');assert.equal(repeated.today,first.today);
 assert.equal(repeated.currentStreakDays,1);
 assert.equal((await recordDecodeDay(id,{db,today:hour('2026-11-02T08:01:00Z')})).currentStreakDays,2);
});
test('105 consecutive days starting Wednesday pay 15 credits; 100 unlocks violet without capping the total',async()=>{
 const id=await calendarAccount(),start=Date.parse('2026-01-07T20:00:00Z');
 await configureStreakTimeZone(id,'America/Tijuana',{db,today:new Date(start)});
 for(let n=1;n<=105;n++){
  const clock=new Date(start+(n-1)*86400000);
  const state=await recordDecodeDay(id,{db,today:clock});
  assert.equal(state.currentStreakDays,n);
  assert.equal(state.creditGranted,n%7===0);
  assert.equal(state.rewardProgress,((n-1)%7)+1);
  if(n===99)assert.equal(state.flameColor,'orange');
  if(n>=100)assert.equal(state.flameColor,'violet');
  if(n%7===0){
   assert.equal(state.chestOpen,true);
   const retry=await recordDecodeDay(id,{db,today:clock});
   assert.equal(retry.creditGranted,false);assert.equal(retry.rewardClaimId,state.rewardClaimId);
  }
 }
 assert.equal((await creditBalance(id,{db})).available,15);
 const grants=(await db.query("SELECT job_id FROM spdecode_shop.credit_ledger WHERE account_id=$1 AND movement_kind='grant'",[id])).rows;
 assert.equal(grants.length,15);assert.equal(new Set(grants.map(g=>g.job_id)).size,15);
});
test('a missed day resets only the active run; already awarded credits survive',async()=>{
 const id=await calendarAccount(),start=Date.parse('2026-02-04T12:00:00Z');
 for(let n=0;n<7;n++)await recordDecodeDay(id,{db,today:new Date(start+n*86400000)});
 const next=await recordDecodeDay(id,{db,today:new Date(start+9*86400000)});
 assert.equal(next.currentStreakDays,1);assert.equal(next.rewardProgress,1);
 assert.equal(next.chestOpen,false);assert.equal((await creditBalance(id,{db})).available,1);
});
test('future stored dates and server clock rollback cannot add or reset earned days',async()=>{
 const id=await calendarAccount();
 const first=await recordDecodeDay(id,{db,today:at(WED)});
 const old=await recordDecodeDay(id,{db,today:at(MON)});
 assert.equal(old.currentStreakDays,0);assert.equal(old.creditGranted,false);
 assert.equal((await getAccountStreak(id,{db,today:at(WED)})).currentStreakDays,first.currentStreakDays);
 assert.equal((await recordDecodeDay(id,{db,today:at(THU)})).currentStreakDays,2);
});
test('legacy totals and credited chests migrate without an immediate or duplicate award',async()=>{
 const id=await calendarAccount(),oldMonday='2026-11-16';
 await db.query(`INSERT INTO spdecode_shop.account_streaks
  (account_id,current_streak,last_active_date,week_start,week_days,last_counted_at)
  VALUES($1,13,'2026-11-23','2026-11-23','{t,f,f,f,f,f,f}', '2026-11-23T20:00:00Z')`,[id]);
 await db.query(`INSERT INTO spdecode_shop.credit_ledger(id,account_id,job_id,movement_kind,delta,payment_live,created_at)
  VALUES($1,$2,$3,'grant',1,false,'2026-11-22T20:00:00Z')`,[randomUUID(),id,chestJobId(id,oldMonday)]);
 const state=await configureStreakTimeZone(id,'America/Tijuana',{db,today:hour('2026-11-23T20:00:00Z')});
 assert.equal(state.currentStreakDays,13);assert.equal(state.rewardProgress,1);
 assert.equal((await creditBalance(id,{db})).available,1);
 assert.equal((await recordDecodeDay(id,{db,today:hour('2026-11-24T20:00:00Z')})).creditGranted,false);
 for(let n=25;n<=29;n++)await recordDecodeDay(id,{db,today:hour('2026-11-'+n+'T20:00:00Z')});
 assert.equal((await creditBalance(id,{db})).available,2);
});
test('calendar setup authenticates ownership and rejects client dates, counters and claim actions',async()=>{
 const id=await calendarAccount(),auth=async()=>({user:{id}});
 const request=input=>new Request('http://localhost:3000/api/account/streak',{method:'POST',
  headers:{origin:'http://localhost:3000','content-type':'application/json',date:'Wed, 01 Jan 2099 00:00:00 GMT'},body:JSON.stringify(input)});
 for(const field of ['today','date','currentStreakDays','rewardProgress','claim','accountId']){
  const response=await streakTimeZoneRequest(request({timeZone:'America/Tijuana',[field]:'2099-01-01'}),{db,authenticate:auth,today:at(MON)});
  assert.equal(response.status,400,field);
 }
 const unauthorized=await streakTimeZoneRequest(request({timeZone:'UTC'}),{db,authenticate:async()=>{throw new ShopError('SIGN_IN_REQUIRED',401);}});
 assert.equal(unauthorized.status,401);
 const ok=await streakTimeZoneRequest(request({timeZone:'America/Tijuana'}),{db,authenticate:auth,today:hour('2026-11-17T01:00:00Z')});
 assert.equal(ok.status,200);
 const state=(await ok.json()).streak;
 assert.equal(state.today,'2026-11-16');assert.equal(state.currentStreakDays,0);
 assert.equal((await creditBalance(id,{db})).available,0);
 for(const zone of ['Not/AZone','2099-01-01',123,''])assert.throws(()=>validatedTimeZone(zone));
 assert.equal(localDayString('2026-11-17T01:00:00Z','America/Tijuana'),'2026-11-16');
});
