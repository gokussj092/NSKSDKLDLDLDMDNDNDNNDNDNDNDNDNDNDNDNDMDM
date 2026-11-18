import test from 'node:test';
import assert from 'node:assert/strict';
import {before,after} from 'node:test';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID,randomBytes} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth,requireAccount} from '../lib/commerce/auth.mjs';
import {takeStreakAccountToken,withDecodeStreak} from '../lib/commerce/decode-account-streak.mjs';
import {decodeRequest} from '../lib/c3-gateway.mjs';
import {bindVerifiedRequest} from '../lib/v2-bound-request.mjs';
import {recordDecodeDay} from '../lib/commerce/account-streak.mjs';
import {normalizeInstallSource,takePlayTesterFields,recordPlayTesterActivity,
 summarizePlayTesters,listPlayTesters,PLAY_INSTALLER_PACKAGE,
 TESTER_WINDOW_DAYS} from '../lib/commerce/play-testers.mjs';

let pg,db,auth,root;
const env={...process.env,NODE_ENV:'test',
 CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgres://synthetic',
 BETTER_AUTH_SECRET:randomBytes(32).toString('hex'),
 GOOGLE_CLIENT_ID:'synthetic.apps.googleusercontent.com',GOOGLE_CLIENT_SECRET:'synthetic'};
Object.assign(process.env,env);
const at=iso=>new Date(iso+'T12:00:00.000Z');
// 2026-11-16 is a Monday; the test window is Mon 2026-11-16 .. Sun 2026-11-29.
const MON='2026-11-16',TUE='2026-11-17',WED='2026-11-18',DAY15='2026-11-30',DAY16='2026-12-01';
const claims={hpke:true,scope:'decode',key:'transport-key-1',jti:randomUUID()};
const playFields={installerPackage:PLAY_INSTALLER_PACKAGE,versionName:'1.1.29',
 versionCode:44,deviceKey:'transport-key-1'};
before(async()=>{
 root=await mkdtemp(join(tmpdir(),'spdecode-play-testers-'));
 pg=new PGlite();
 const query=async(sql,params=[])=>{
  const r=await pg.query(sql,params);
  return {rows:r.rows,rowCount:r.rows.length||r.affectedRows||0};
 };
 db={query,connect:async()=>({query,release(){}})};
 auth=makeAuth(db,env);
 await (await getMigrations(auth.options)).runMigrations();
 for(const name of ['002_shop.sql','012_app_analysis.sql','014_account_streak.sql','015_streak_calendar.sql',
   '017_play_testers.sql']){
  const sql=await readFile(new URL('../sql/'+name,import.meta.url),'utf8');
  await pg.exec(sql);
 }
});
after(async()=>{await pg?.close();await rm(root,{recursive:true,force:true});});
async function freshAccount(){
 const id=randomUUID();
 await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
  VALUES($1,$2,$3,true,now(),now())`,[id,'Play Tester','play-tester-'+id.slice(0,8)+'@example.invalid']);
 return id;
}
async function freshSession(accountId){
 const token=randomBytes(32).toString('base64url');
 await db.query(`INSERT INTO shop_session(id,token,"userId","expiresAt","createdAt","updatedAt")
  VALUES($1,$2,$3,now()+interval '1 day',now(),now())`,[randomUUID(),token,accountId]);
 return token;
}
async function firstSeen(id){
 return (await db.query(`SELECT * FROM spdecode_shop.play_tester_first_seen
  WHERE account_id=$1`,[id])).rows[0];
}
async function testerDays(id){
 return (await db.query(`SELECT day FROM spdecode_shop.play_tester_days
  WHERE account_id=$1 ORDER BY day`,[id])).rows.map(r=>
   r.day instanceof Date?r.day.toISOString().slice(0,10):String(r.day).slice(0,10));
}

test('installer package normalizes to play / other / unknown',()=>{
 assert.equal(normalizeInstallSource('com.android.vending'),'play');
 assert.equal(normalizeInstallSource('com.example.sideload'),'other');
 assert.equal(normalizeInstallSource(''),'unknown');
 assert.equal(normalizeInstallSource(null),'unknown');
 assert.equal(normalizeInstallSource(undefined),'unknown');
 assert.equal(normalizeInstallSource(42),'unknown');
 assert.equal(TESTER_WINDOW_DAYS,14);
});

test('takePlayTesterFields strips the fields and validates them, never fatally',()=>{
 for(const bad of [null,{}, {key:'x'}, {...claims,hpke:false},{...claims,scope:'catalog'}]){
  const payload={text:'sample',installerPackage:PLAY_INSTALLER_PACKAGE,
   versionName:'1.1.29',versionCode:44};
  assert.equal(takePlayTesterFields(payload,bad),null);
  // Stripped even when the session is not a decode session, so the strict
  // payload validator never sees unknown keys.
  assert.deepEqual(payload,{text:'sample'});
 }
 const payload={text:'sample',installerPackage:PLAY_INSTALLER_PACKAGE,
  versionName:'1.1.29',versionCode:44};
 assert.deepEqual(takePlayTesterFields(payload,claims),playFields);
 assert.deepEqual(payload,{text:'sample'});
 // Invalid values are dropped; a payload with nothing valid yields null.
 assert.equal(takePlayTesterFields({installerPackage:1,versionName:'',versionCode:-1},claims),null);
 assert.equal(takePlayTesterFields({versionName:'x'.repeat(33)},claims),null);
 assert.deepEqual(takePlayTesterFields({installerPackage:'com.other.store'},claims),
  {installerPackage:'com.other.store',versionName:null,versionCode:null,deviceKey:'transport-key-1'});
 assert.equal(takePlayTesterFields({installerPackage:PLAY_INSTALLER_PACKAGE},claims).versionName,null);
});

test('first-seen wins: later installs never overwrite origin or version',async()=>{
 const id=await freshAccount();
 assert.equal(await recordPlayTesterActivity(id,playFields,MON,{db}),true);
 assert.equal(await recordPlayTesterActivity(id,playFields,MON,{db}),false); // Same day twice.
 assert.deepEqual(await testerDays(id),[MON]);
 const row=await firstSeen(id);
 assert.equal(row.install_source,'play');
 assert.equal(row.installer_package,PLAY_INSTALLER_PACKAGE);
 assert.equal(row.version_name,'1.1.29');
 assert.equal(row.version_code,44);
 assert.match(row.device_key_hash,/^[0-9a-f]{64}$/);
 // A "newer" sideload install of another version must not replace it.
 assert.equal(await recordPlayTesterActivity(id,
  {installerPackage:'com.other.store',versionName:'9.9.9',versionCode:99,deviceKey:'other-key'},
  TUE,{db}),true);
 const kept=await firstSeen(id);
 assert.equal(kept.install_source,'play');
 assert.equal(kept.version_name,'1.1.29');
 assert.equal(kept.version_code,44);
 assert.deepEqual(await testerDays(id),[MON,TUE]);
});

test('days only count for known testers, and invalid days are rejected',async()=>{
 const id=await freshAccount();
 assert.equal(await recordPlayTesterActivity(id,null,MON,{db}),false);
 assert.deepEqual(await testerDays(id),[]);
 assert.equal(await recordPlayTesterActivity(id,playFields,'not-a-day',{db}),false);
 assert.equal(await recordPlayTesterActivity(null,playFields,MON,{db}),false);
 assert.equal(await firstSeen(id),undefined);
});

test('summary counts only days inside the 14-day window; Play + >=1 day qualifies',()=>{
 const rows=[{account_id:'a',install_source:'play',installer_package:PLAY_INSTALLER_PACKAGE,
   version_name:'1.1.29',version_code:44,device_key_hash:'aa',first_seen_at:new Date('2026-11-16T10:00:00Z')},
  {account_id:'b',install_source:'other',installer_package:'com.other.store',
   version_name:'1.0.0',version_code:1,device_key_hash:null,first_seen_at:new Date('2026-11-16T11:00:00Z')},
  {account_id:'c',install_source:'unknown',installer_package:null,
   version_name:'1.1.29',version_code:44,device_key_hash:null,first_seen_at:new Date('2026-11-16T12:00:00Z')},
  {account_id:'d',install_source:'play',installer_package:PLAY_INSTALLER_PACKAGE,
   version_name:'1.1.29',version_code:44,device_key_hash:null,first_seen_at:new Date('2026-11-16T13:00:00Z')}];
 const days=[{account_id:'a',day:MON},{account_id:'a',day:TUE},{account_id:'a',day:WED},
  {account_id:'a',day:DAY15},{account_id:'a',day:DAY16},
  {account_id:'b',day:MON},{account_id:'b',day:TUE},{account_id:'c',day:MON}];
 const out=summarizePlayTesters(rows,days);
 assert.equal(out.length,4);
 const a=out.find(t=>t.accountId==='a');
 assert.equal(a.windowStart,MON);assert.equal(a.windowEnd,'2026-11-29');
 assert.equal(a.activeDays,3); // DAY15/DAY16 fall outside the window.
 assert.equal(a.lastActiveDay,DAY16);
 assert.equal(a.qualifies,true);
 const b=out.find(t=>t.accountId==='b');
 assert.equal(b.activeDays,2);assert.equal(b.qualifies,false); // Not from Play.
 const c=out.find(t=>t.accountId==='c');
 assert.equal(c.activeDays,1);assert.equal(c.qualifies,false); // Unknown origin.
 const d=out.find(t=>t.accountId==='d');
 assert.equal(d.activeDays,0);assert.equal(d.windowStart,null);
 assert.equal(d.qualifies,false); // From Play but never used the app.
});

test('successful decode records tester + day through withDecodeStreak; later decodes keep counting',async()=>{
 const id=await freshAccount();
 const token=await freshSession(id);
 const authenticate=request=>requireAccount(request,{auth});
 const success=()=>Response.json({status:'success',rawText:'{"decoded":true}',isPartial:false});
 const opts={streakDb:db,streakToday:at(MON),streakAuthenticate:authenticate,tester:playFields};
 const body=await (await withDecodeStreak(success(),claims,
  takeStreakAccountToken({accountToken:token},claims),opts)).json();
 assert.equal(body.streak.currentStreakDays,1);
 assert.equal((await firstSeen(id)).install_source,'play');
 assert.deepEqual(await testerDays(id),[MON]);
 // Second day, same tester, app no longer sends the fields: the day counts.
 const body2=await (await withDecodeStreak(success(),claims,
  takeStreakAccountToken({accountToken:token},claims),
  {...opts,streakToday:at(TUE),tester:null})).json();
 assert.equal(body2.streak.currentStreakDays,2);
 assert.deepEqual(await testerDays(id),[MON,TUE]);
 // Failed decode and guest decode record nothing.
 const failed=Response.json({error:{code:'INVALID_PASSWORD'}},{status:422});
 assert.equal(await withDecodeStreak(failed,claims,token,opts),failed);
 const guest=Response.json({status:'success',rawText:'{}'});
 assert.equal(await withDecodeStreak(guest,claims,null,opts),guest);
 assert.deepEqual(await testerDays(id),[MON,TUE]);
 assert.equal((await listPlayTesters({db})).testers.find(t=>t.accountId===id).activeDays,2);
});

test('recordDecodeDay and the tester day agree on the account local day',async()=>{
 const id=await freshAccount();
 const streak=await recordDecodeDay(id,{db,today:at(MON)});
 assert.equal(streak.today,MON);
 assert.equal(await recordPlayTesterActivity(id,playFields,streak.today,{db}),true);
 assert.deepEqual(await testerDays(id),[MON]);
});

test('file/text gateway strips installer fields from the worker payload and records the tester',async()=>{
 Object.assign(process.env,{CLOUD_API_ENABLED:'true',CLOUD_WORKER_TOKEN:'x'.repeat(48),
  CLOUD_SESSION_SIGNING_KEY:'s'.repeat(48),CLOUD_GOOGLE_PLAY_PACKAGE:'com.ghostdeveloper.spdecode',
  CLOUD_BETA_ADMISSION_ENABLED:'true',CLOUD_REDIS_URL:'redis://redis:6379',CLOUD_TRUST_PROXY:'true',
  WORKER_INTERNAL_URL:'http://decoder-worker:8787'});
 const id=await freshAccount();
 const token=await freshSession(id);
 const redis={get:async()=>null,eval:async()=>1,zRem:async()=>1};
 // What the app actually sends: only the three fields (the device key comes
 // from the session claims, never from the payload).
 const appFields={installerPackage:playFields.installerPackage,
  versionName:playFields.versionName,versionCode:playFields.versionCode};
 for(const kind of ['file','text']){
  const payload=kind==='file'?{format:'hc',dataBase64:'YWJj'}:{text:'synthetic'};
  const request=new Request('https://example.invalid/api/v2',{method:'POST',
   headers:{'content-type':'application/json'},
   body:JSON.stringify({...payload,accountToken:token,...appFields})});
  bindVerifiedRequest(request,{hpke:true,scope:'decode',key:'transport-key-1',jti:randomUUID()});
  const result=await decodeRequest(request,kind,{storeProvider:async()=>redis,streakDb:db,
   streakToday:at(MON),
   streakAuthenticate:async req=>{assert.equal(req.headers.get('authorization'),'Bearer '+token);
    return {user:{id,emailVerified:true}};},
   fetchImpl:async(url,options)=>{
    assert.deepEqual(JSON.parse(options.body),payload); // No token, no installer fields.
    return Response.json({apiVersion:'v1',status:'success',rawText:'{"decoded":true}',isPartial:false});
   }});
  assert.equal(result.status,200);
  assert.equal((await result.json()).streak.currentStreakDays,1);
 }
 assert.equal((await firstSeen(id)).version_name,'1.1.29');
 assert.equal((await firstSeen(id)).install_source,'play');
 assert.deepEqual(await testerDays(id),[MON]);
});
