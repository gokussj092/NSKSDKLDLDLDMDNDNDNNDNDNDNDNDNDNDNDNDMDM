/** Server-owned streak. Only successful bound file/text decodes record a day.
 * Calendar zone is initialized once per account; client wall clocks never count.
 * Every seven consecutive days grants one idempotent analysis credit. No cap on
 * the total streak. Historical weekly rows/ledger grants remain compatible. */
import {randomUUID,createHash} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {fail} from './config.mjs';

const DAY_MS=86400000;
const emptyWeek=()=>[false,false,false,false,false,false,false];
const dateString=value=>value instanceof Date?value.toISOString().slice(0,10):typeof value==='string'?value.slice(0,10):null;
export const utcDayString=(date=new Date())=>new Date(date).toISOString().slice(0,10);
export function weekDayIndex(date=new Date()){return (new Date(date).getUTCDay()+6)%7;}
export function weekMondayString(date=new Date()){
 const d=new Date(date);return new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),d.getUTCDate()-weekDayIndex(d))).toISOString().slice(0,10);
}
const plusDays=(day,n)=>new Date(Date.parse(day+'T12:00:00Z')+n*DAY_MS).toISOString().slice(0,10);
const dayDistance=(a,b)=>Math.round((Date.parse(a+'T12:00:00Z')-Date.parse(b+'T12:00:00Z'))/DAY_MS);
export function validatedTimeZone(value){
 if(typeof value!=='string'||value.length<1||value.length>80)fail('INVALID_TIME_ZONE');
 try{return new Intl.DateTimeFormat('en',{timeZone:value}).resolvedOptions().timeZone;}
 catch{fail('INVALID_TIME_ZONE');}
}
export function localDayString(clock,zone='UTC'){
 const parts=new Intl.DateTimeFormat('en-CA',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date(clock));
 return ['year','month','day'].map(type=>parts.find(p=>p.type===type).value).join('-');
}
async function serverClock(db,today){
 // `today` is an internal test clock, never accepted by an HTTP route or decode payload.
 if(today!==undefined)return new Date(typeof today==='string'&&today.length===10?today+'T12:00:00Z':today);
 const row=(await db.query('SELECT now() AS server_now')).rows[0];
 return new Date(row.server_now);
}
export function emptyStreakState(clock=new Date(),zone='UTC'){return deriveStreakState(null,clock,zone);}
export function deriveStreakState(row,clock=new Date(),fallbackZone='UTC'){
 const now=new Date(typeof clock==='string'&&clock.length===10?clock+'T12:00:00Z':clock);
 const zone=row?.time_zone||fallbackZone,today=localDayString(now,zone),yesterday=plusDays(today,-1);
 const last=dateString(row?.last_active_date),alive=last===today||last===yesterday;
 const days=alive?Number(row.current_streak)||0:0;
 const progress=alive?Math.max(0,Math.min(7,row.reward_progress??Math.min(days,6))):0;
 const cycleStart=progress>0?(dateString(row?.reward_cycle_start)||plusDays(last,1-progress)):today;
 const monday=weekMondayString(today+'T12:00:00Z');
 return {currentStreakDays:days,
  weekCompleted:dateString(row?.week_start)===monday&&Array.isArray(row?.week_days)&&row.week_days.length===7?row.week_days.map(v=>v===true):emptyWeek(),
  chestOpen:progress===7&&!!row?.reward_claim_id,
  serverNow:now.toISOString(),today,timeZone:zone,timeZoneLocked:!!row?.time_zone,
  weekStart:monday,completedToday:last===today,rewardProgress:progress,daysUntilReward:7-progress,
  cycleStart,cycleDays:Array.from({length:7},(_,n)=>plusDays(cycleStart,n)),
  cycleCompleted:Array.from({length:7},(_,n)=>n<progress),
  rewardClaimId:row?.reward_claim_id??null,rewardClaimDate:dateString(row?.reward_claim_date),
  flameColor:days>=100?'violet':'orange'};
}
// Same namespace as the original Monday-based chest; account/date uniqueness
// also protects rolling blocks, including after a missed day or reinstall.
export function chestJobId(accountId,cycleStart){
 const digest=createHash('sha256').update('spdecode-streak-chest:v1:'+accountId+':'+cycleStart,'utf8').digest('hex');
 const h=digest.slice(0,32).split('');h[12]='5';h[16]='8';const s=h.join('');
 return s.slice(0,8)+'-'+s.slice(8,12)+'-'+s.slice(12,16)+'-'+s.slice(16,20)+'-'+s.slice(20,32);
}
async function lockRow(client,accountId){
 const user=(await client.query('SELECT id FROM shop_user WHERE id=$1 FOR UPDATE',[accountId])).rows[0];
 if(!user)fail('SIGN_IN_REQUIRED',401);
 await client.query('INSERT INTO spdecode_shop.account_streaks(account_id) VALUES($1) ON CONFLICT(account_id) DO NOTHING',[accountId]);
 return (await client.query('SELECT * FROM spdecode_shop.account_streaks WHERE account_id=$1 FOR UPDATE',[accountId])).rows[0];
}
async function initializeReward(client,row,zone,live){
 if(row.reward_progress!==null&&row.reward_progress!==undefined)return row;
 const oldLast=dateString(row.last_active_date);
 const last=row.last_counted_at?localDayString(row.last_counted_at,zone):oldLast;
 let progress=Math.min(Number(row.current_streak)||0,6),claim=null,claimDate=null;
 if(oldLast){
  const monday=weekMondayString(oldLast+'T12:00:00Z');
  const oldGrant=(await client.query(`SELECT job_id,created_at FROM spdecode_shop.credit_ledger
    WHERE account_id=$1 AND movement_kind='grant' AND delta=1 AND payment_live=$2
    AND job_id=ANY($3::uuid[]) ORDER BY created_at DESC LIMIT 1`,
   [row.account_id,live,[chestJobId(row.account_id,monday),chestJobId(row.account_id,plusDays(monday,-7))]])).rows[0];
  if(oldGrant){
   claim=oldGrant.job_id;claimDate=localDayString(oldGrant.created_at,zone);
   const elapsed=dayDistance(last,claimDate);
   progress=elapsed===0?7:Math.max(0,Math.min(6,elapsed));
  }
 }
 const start=last&&progress>0?plusDays(last,1-progress):null;
 await client.query(`UPDATE spdecode_shop.account_streaks SET reward_progress=$2,
  reward_cycle_start=$3,reward_claim_id=$4,reward_claim_date=$5 WHERE account_id=$1`,
 [row.account_id,progress,start,claim,claimDate]);
 return {...row,reward_progress:progress,reward_cycle_start:start,reward_claim_id:claim,reward_claim_date:claimDate};
}
export async function getAccountStreak(accountId,{db=database(),today}={}){
 const clock=await serverClock(db,today);
 const row=(await db.query('SELECT * FROM spdecode_shop.account_streaks WHERE account_id=$1',[accountId])).rows[0];
 return deriveStreakState(row,clock);
}
export async function configureStreakTimeZone(accountId,requestedZone,
 {db=database(),today,live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 const zone=validatedTimeZone(requestedZone);
 return transaction(async client=>{
  const clock=await serverClock(client,today);
  let row=await lockRow(client,accountId);
  if(row.time_zone)return deriveStreakState(row,clock); // Immutable account calendar.
  row=await initializeReward(client,row,zone,live);
  const last=row.last_counted_at?localDayString(row.last_counted_at,zone):dateString(row.last_active_date);
  const cycle=row.reward_progress>0&&last?plusDays(last,1-row.reward_progress):null;
  await client.query(`UPDATE spdecode_shop.account_streaks SET time_zone=$2,
    last_active_date=$3,reward_cycle_start=$4 WHERE account_id=$1`,[accountId,zone,last,cycle]);
  return deriveStreakState({...row,time_zone:zone,last_active_date:last,reward_cycle_start:cycle},clock);
 },db);
}
export async function recordDecodeDay(accountId,
 {db=database(),today,live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 return transaction(async client=>{
  const clock=await serverClock(client,today);
  let row=await lockRow(client,accountId);
  row=await initializeReward(client,row,row.time_zone||'UTC',live);
  const day=localDayString(clock,row.time_zone||'UTC'),last=dateString(row.last_active_date);
  // Clock rollback/future stored dates must never reset a row or create another reward.
  if(last&&last>=day)return {...deriveStreakState(row,clock),creditGranted:false};
  const consecutive=last===plusDays(day,-1);
  const total=consecutive?Number(row.current_streak)+1:1;
  const progress=consecutive&&row.reward_progress<7?row.reward_progress+1:1;
  const start=progress===1?day:dateString(row.reward_cycle_start)||plusDays(day,1-progress);
  let claim=row.reward_claim_id,claimDate=dateString(row.reward_claim_date),creditGranted=false;
  if(progress===7){
   claim=chestJobId(accountId,start);claimDate=day;
   const grant=(await client.query(`INSERT INTO spdecode_shop.credit_ledger
    (id,account_id,job_id,movement_kind,delta,payment_live,created_at)
    VALUES($1,$2,$3,'grant',1,$4,$5) ON CONFLICT(job_id,movement_kind) DO NOTHING RETURNING id`,
    [randomUUID(),accountId,claim,live,clock])).rows[0];
   creditGranted=!!grant;
  }
  const monday=weekMondayString(day+'T12:00:00Z');
  const week=dateString(row.week_start)===monday&&Array.isArray(row.week_days)?row.week_days.slice():emptyWeek();
  week[weekDayIndex(day+'T12:00:00Z')]=true;
  await client.query(`UPDATE spdecode_shop.account_streaks SET current_streak=$2,last_active_date=$3,
   week_start=$4,week_days=$5::boolean[],chest_open=$6,chest_week=$7,last_counted_at=$8,
   reward_progress=$9,reward_cycle_start=$10,reward_claim_id=$11,reward_claim_date=$12,updated_at=$8 WHERE account_id=$1`,
   [accountId,total,day,monday,week,progress===7,progress===7?monday:null,clock,progress,start,claim,claimDate]);
  const updated={...row,current_streak:total,last_active_date:day,week_start:monday,week_days:week,
   reward_progress:progress,reward_cycle_start:start,reward_claim_id:claim,reward_claim_date:claimDate};
  return {...deriveStreakState(updated,clock),creditGranted};
 },db);
}
