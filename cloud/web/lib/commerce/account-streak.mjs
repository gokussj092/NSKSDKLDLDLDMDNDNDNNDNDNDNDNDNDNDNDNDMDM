/**
 * Decryption streak (racha de descifrado, 2026-11-16). Server-side only:
 * the state lives in spdecode_shop.account_streaks keyed by account_id, so
 * it survives reinstalling the app or changing phones. The client never
 * writes streak state; it only reads it through GET /api/account.
 *
 * Rules (Pedro, 2026-11-16; no grace day):
 * - Day = UTC calendar day; week = Monday to Sunday (UTC). week_days[0..6]
 *   is Mon..Sun of the current week (week_start = its Monday).
 * - A day counts when the account performs a SUCCESSFUL decode while
 *   logged in. What counts, exactly:
 *     * YES: file decode (V2 op 5) and text decode (V2 op 6). Both travel
 *       through decodeRequest() in lib/c3-gateway.mjs, which is where the
 *       day is recorded (see recordDecodeStreak, called only after the
 *       worker returned success and the 2xx response was built).
 *     * NO: remote catalog import (op 9) and Server VPN decode (op 12).
 *       They never reach decodeRequest (op 9 uses externalImportRequest,
 *       op 12 uses decodeServerVpn), and they are catalog downloads from
 *       the server, not decodes the user initiated.
 *     * NO: failed decodes, and decodes on a V1 legacy session. A V1
 *       session token carries no device key (see issueSession in
 *       lib/c3-session.mjs: iss/aud/scope/iat/exp/jti only), so the server
 *       cannot attribute it to an account without trusting client input.
 *       Only V2-bound sessions carry claims.key (the device public key),
 *       which is resolved server-side through
 *       spdecode_shop.account_device_keys.public_key (registered by the
 *       account owner in lib/commerce/account-device.mjs). An unlinked
 *       device simply has no account, so its decodes do not count.
 * - Consecutive days: last_active_date == yesterday (UTC) -> +1;
 *   last_active_date == today -> no change (recording twice the same day
 *   never adds a second day); any other case -> 1 (new streak starting
 *   today). There is NO grace day: skipping one day restarts the streak.
 *   Reading the state applies the same rule without writing: if the last
 *   active day is neither today nor yesterday, currentStreakDays reads 0.
 * - Chest: when the 7 days of the current UTC week are all true, the
 *   server grants exactly 1 analysis credit (movement_kind 'grant',
 *   delta +1 in spdecode_shop.credit_ledger, the same ledger the purchase
 *   grant in lib/commerce/orders.mjs uses) and marks chest_open=true with
 *   chest_week = the current Monday. Idempotency is enforced twice:
 *   chest_open/chest_week on the streak row, AND the ledger
 *   UNIQUE(job_id, movement_kind) on a deterministic job UUID derived
 *   from account + week (chestJobId), so a retried grant can never
 *   double-spend. The credit is granted at most once per completed week.
 * - Best-effort: recordDecodeStreak never throws into the decode path;
 *   the gateway wraps it so a streak failure can never fail a decode.
 */
import {randomUUID,createHash} from 'node:crypto';
import {database,transaction} from './db.mjs';

const DAY_MS=24*60*60*1000;
const toDateString=value=>{
 if(value instanceof Date)return value.toISOString().slice(0,10);
 if(typeof value==='string')return value.slice(0,10);
 return null;
};
/** UTC calendar day ('YYYY-MM-DD') of a Date (defaults to now). */
export function utcDayString(date=new Date()){
 return new Date(date).toISOString().slice(0,10);
}
/** Monday ('YYYY-MM-DD') of the UTC week containing date. */
export function weekMondayString(date=new Date()){
 const d=new Date(date);
 const day=(d.getUTCDay()+6)%7; // 0 = Monday .. 6 = Sunday
 return new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),d.getUTCDate()-day))
   .toISOString().slice(0,10);
}
/** 0 = Monday .. 6 = Sunday (UTC) for date. */
export function weekDayIndex(date=new Date()){
 return (new Date(date).getUTCDay()+6)%7;
}
const yesterdayString=today=>{
 return new Date(new Date(today+'T00:00:00.000Z').getTime()-DAY_MS)
   .toISOString().slice(0,10);
};
const emptyWeek=()=>[false,false,false,false,false,false,false];
export function emptyStreakState(){
 return {currentStreakDays:0,weekCompleted:emptyWeek(),chestOpen:false};
}
const normalizeWeekDays=value=>{
 if(!Array.isArray(value)||value.length!==7)return emptyWeek();
 return value.map(v=>v===true);
};
/** Pure read view of a stored streak row for `today` (Date or 'YYYY-MM-DD').
 * A stale week reads as all-false; a streak whose last active day is neither
 * today nor yesterday reads as 0; a chest from a past week reads as closed. */
export function deriveStreakState(row,today=new Date()){
 if(!row)return emptyStreakState();
 const todayStr=typeof today==='string'?today.slice(0,10):utcDayString(today);
 const monday=weekMondayString(todayStr+'T00:00:00.000Z');
 const yesterday=yesterdayString(todayStr);
 const lastActive=toDateString(row.last_active_date);
 const alive=lastActive!==null&&lastActive>=yesterday;
 return {
  currentStreakDays:alive?Number(row.current_streak)||0:0,
  weekCompleted:toDateString(row.week_start)===monday
    ?normalizeWeekDays(row.week_days):emptyWeek(),
  chestOpen:row.chest_open===true&&toDateString(row.chest_week)===monday,
 };
}
/** Deterministic ledger job UUID for the chest credit of (account, week).
 * Namespaced so it can never collide with a real analysis job UUID (random);
 * the ledger UNIQUE(job_id, movement_kind) makes the grant idempotent. */
export function chestJobId(accountId,weekStart){
 const digest=createHash('sha256')
   .update('spdecode-streak-chest:v1:'+accountId+':'+weekStart,'utf8').digest('hex');
 const hex=digest.slice(0,32).split('');
 hex[12]='5';hex[16]='8'; // UUID v5 version + RFC 4122 variant bits
 const s=hex.join('');
 return s.slice(0,8)+'-'+s.slice(8,12)+'-'+s.slice(12,16)+'-'+s.slice(16,20)+'-'+s.slice(20,32);
}

export async function getAccountStreak(accountId,{db=database(),today=new Date()}={}){
 const row=(await db.query(
   'SELECT * FROM spdecode_shop.account_streaks WHERE account_id=$1',[accountId])).rows[0];
 return deriveStreakState(row,today);
}

/**
 * Record one successful decode day for an account. Idempotent per day and
 * transactional: the streak row, the week rollover and the chest credit are
 * committed together. Returns the read state plus creditGranted (true only
 * when this call granted the weekly chest credit).
 */
export async function recordDecodeDay(accountId,
 {db=database(),today=new Date(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 const todayStr=typeof today==='string'?today.slice(0,10):utcDayString(today);
 const monday=weekMondayString(todayStr+'T00:00:00.000Z');
 const yesterday=yesterdayString(todayStr);
 const index=weekDayIndex(todayStr+'T00:00:00.000Z');
 return transaction(async client=>{
  let row=(await client.query(
    'SELECT * FROM spdecode_shop.account_streaks WHERE account_id=$1 FOR UPDATE',
    [accountId])).rows[0];
  if(!row){
   const week=emptyWeek();week[index]=true;
   await client.query(`INSERT INTO spdecode_shop.account_streaks
     (account_id,current_streak,last_active_date,week_start,week_days)
     VALUES($1,1,$2,$3,$4::boolean[]) ON CONFLICT(account_id) DO NOTHING`,
    [accountId,todayStr,monday,week]);
   row=(await client.query(
     'SELECT * FROM spdecode_shop.account_streaks WHERE account_id=$1 FOR UPDATE',
     [accountId])).rows[0];
  }
  const lastActive=toDateString(row.last_active_date);
  if(lastActive===todayStr)
   return {...deriveStreakState(row,todayStr),creditGranted:false};
  const streak=lastActive===yesterday?(Number(row.current_streak)||0)+1:1;
  const week=toDateString(row.week_start)===monday
    ?normalizeWeekDays(row.week_days):emptyWeek();
  week[index]=true;
  const complete=week.every(Boolean);
  const alreadyChest=row.chest_open===true&&toDateString(row.chest_week)===monday;
  let creditGranted=false;
  if(complete&&!alreadyChest){
   const granted=(await client.query(`INSERT INTO spdecode_shop.credit_ledger
      (id,account_id,job_id,movement_kind,delta,payment_live)
      VALUES($1,$2,$3,'grant',1,$4)
      ON CONFLICT(job_id,movement_kind) DO NOTHING RETURNING id`,
     [randomUUID(),accountId,chestJobId(accountId,monday),live])).rows[0];
   creditGranted=Boolean(granted);
  }
  // chest_open/chest_week describe ONLY the current week: a completed week
  // opens the chest for that Monday; any other week reads as closed (the
  // ledger grant is the durable record of the credit, not this flag).
  const chestOpen=complete;
  const chestWeek=complete?monday:null;
  await client.query(`UPDATE spdecode_shop.account_streaks
    SET current_streak=$2,last_active_date=$3,week_start=$4,week_days=$5::boolean[],
      chest_open=$6,chest_week=$7,updated_at=now() WHERE account_id=$1`,
   [accountId,streak,todayStr,monday,week,chestOpen,chestWeek]);
  const updated=(await client.query(
    'SELECT * FROM spdecode_shop.account_streaks WHERE account_id=$1',[accountId])).rows[0];
  return {...deriveStreakState(updated,todayStr),creditGranted};
 },db);
}

/**
 * Resolve the account owning a V2 device session key and record one decode
 * day for it. Returns null when the device is not linked to any account
 * (anonymous decode: does not count). Never throws for an unknown key.
 */
export async function recordSuccessfulDecodeForDevice(devicePublicKey,
 {db=database(),today=new Date(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 if(typeof devicePublicKey!=='string'||!devicePublicKey)return null;
 const owner=(await db.query(
   'SELECT account_id FROM spdecode_shop.account_device_keys WHERE public_key=$1',
   [devicePublicKey])).rows[0];
 if(!owner?.account_id)return null;
 return recordDecodeDay(owner.account_id,{db,today,live});
}

/**
 * Gateway hook: record one decode day from bound V2 session claims, after a
 * successful decode. Best-effort by contract: never throws, so a streak
 * failure can never fail a decode. Returns null when there is nothing to
 * record (no device key in the claims, unlinked device, or DB unavailable).
 */
export async function recordDecodeStreak(claims,{db,today,live}={}){
 try{
  if(!claims||typeof claims.key!=='string'||!claims.key)return null;
  return await recordSuccessfulDecodeForDevice(claims.key,{db,today,live});
 }catch{return null;}
}
