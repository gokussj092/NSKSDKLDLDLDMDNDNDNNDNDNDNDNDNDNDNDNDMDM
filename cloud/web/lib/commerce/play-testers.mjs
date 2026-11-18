/** Closed Google Play test detection (2026-11-17). Server side only: no
 * Play Console call, no automatic reward, no code system, no auto-grant.
 * The app (Android) reports three optional fields with the decode payload,
 * next to the account token: installerPackage (e.g. "com.android.vending"),
 * versionName (e.g. "1.1.29") and versionCode (e.g. 44). They are
 * accepted only inside the encrypted HPKE decode session, stripped before
 * the worker ever sees them, and stored FIRST-SEEN WINS per account.
 * Active days reuse the streak's day: withDecodeStreak passes the local
 * day recordDecodeDay already computed for the account's time zone, so the
 * streak calendar stays the single source of "a decode happened that day".
 * A tester "califica" when installed from Play and used the app at least
 * once inside the 14-day window starting on its first active day. Daily use
 * is NOT required; the panel shows how many days were used so Pedro can
 * judge, and he grants credits / ad-free time BY HAND from the panel. */
import {createHash} from 'node:crypto';
import {database,transaction} from './db.mjs';

export const PLAY_INSTALLER_PACKAGE='com.android.vending';
export const TESTER_WINDOW_DAYS=14;
const DAY_MS=86400000;
const plusDays=(day,n)=>new Date(Date.parse(day+'T12:00:00Z')+n*DAY_MS).toISOString().slice(0,10);
const dayString=value=>value instanceof Date?value.toISOString().slice(0,10):
 typeof value==='string'?value.slice(0,10):null;

export function normalizeInstallSource(installerPackage){
 if(typeof installerPackage!=='string'||!installerPackage)return 'unknown';
 return installerPackage===PLAY_INSTALLER_PACKAGE?'play':'other';
}
const cleanString=(value,max)=>typeof value==='string'&&value.length>0&&value.length<=max?value:null;
const cleanVersionCode=value=>Number.isSafeInteger(value)&&value>=0?value:null;

// Mirrors takeStreakAccountToken: the three fields are stripped from the
// payload unconditionally (validatePayload rejects unknown keys), but only
// returned for HPKE decode sessions. Old clients that never send them keep
// working; invalid values are dropped, never fatal to the decode.
export function takePlayTesterFields(payload,claims){
 if(!payload||typeof payload!=='object'||Array.isArray(payload))return null;
 const raw={installerPackage:payload.installerPackage,versionName:payload.versionName,
  versionCode:payload.versionCode,
  deviceKey:typeof claims?.key==='string'&&claims.key?claims.key:null};
 delete payload.installerPackage;delete payload.versionName;delete payload.versionCode;
 if(claims?.hpke!==true||claims.scope!=='decode')return null;
 const installerPackage=cleanString(raw.installerPackage,256);
 const versionName=cleanString(raw.versionName,32);
 const versionCode=cleanVersionCode(raw.versionCode);
 if(installerPackage===null&&versionName===null&&versionCode===null)return null;
 return {installerPackage,versionName,versionCode,deviceKey:raw.deviceKey};
}

// First-seen insert never overwrites; the day row is only written for an
// account the app has reported at least once, so stray decodes from clients
// that never send install info do not create tester rows. `fields` may be
// null (known tester, later decode without fields): the day still counts.
export async function recordPlayTesterActivity(accountId,fields,day,{db=database()}={}){
 if(!accountId||typeof day!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(day))return false;
 return transaction(async client=>{
  if(fields){
   const deviceKeyHash=fields.deviceKey?
    createHash('sha256').update(fields.deviceKey,'utf8').digest('hex'):null;
   await client.query(`INSERT INTO spdecode_shop.play_tester_first_seen
    (account_id,install_source,installer_package,version_name,version_code,device_key_hash)
    VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(account_id) DO NOTHING`,
    [accountId,normalizeInstallSource(fields.installerPackage),fields.installerPackage??null,
     fields.versionName??null,fields.versionCode??null,deviceKeyHash]);
  }
  const inserted=(await client.query(`INSERT INTO spdecode_shop.play_tester_days(account_id,day)
   SELECT $1,$2 WHERE EXISTS(SELECT 1 FROM spdecode_shop.play_tester_first_seen WHERE account_id=$1)
   ON CONFLICT(account_id,day) DO NOTHING RETURNING day`,[accountId,day])).rows.length>0;
  return inserted;
 },db);
}

// Pure summary, unit-testable without a database. The window starts on the
// first active day and covers TESTER_WINDOW_DAYS calendar days; only days
// inside it count. qualifies is exactly: from Play AND >=1 active day.
export function summarizePlayTesters(firstSeenRows,dayRows){
 const daysByAccount=new Map();
 for(const row of dayRows||[]){
  const day=dayString(row.day);
  if(!day)continue;
  const list=daysByAccount.get(row.account_id)||[];
  list.push(day);daysByAccount.set(row.account_id,list);
 }
 return (firstSeenRows||[]).map(row=>{
  const days=(daysByAccount.get(row.account_id)||[]).sort();
  const windowStart=days[0]||null;
  const windowEnd=windowStart?plusDays(windowStart,TESTER_WINDOW_DAYS-1):null;
  const activeDays=windowStart?days.filter(d=>d<=windowEnd).length:0;
  return {accountId:row.account_id,installSource:row.install_source,
   installerPackage:row.installer_package??null,versionName:row.version_name??null,
   versionCode:row.version_code??null,deviceKeyHash:row.device_key_hash??null,
   firstSeenAt:row.first_seen_at instanceof Date?row.first_seen_at.toISOString():row.first_seen_at??null,
   windowStart,windowEnd,activeDays,
   lastActiveDay:days.length?days[days.length-1]:null,
   qualifies:row.install_source==='play'&&activeDays>=1};
 }).sort((a,b)=>String(b.firstSeenAt||'').localeCompare(String(a.firstSeenAt||'')));
}
export async function listPlayTesters({db=database()}={}){
 const firstSeen=(await db.query(`SELECT account_id,install_source,installer_package,
  version_name,version_code,device_key_hash,first_seen_at
  FROM spdecode_shop.play_tester_first_seen ORDER BY first_seen_at DESC LIMIT 500`)).rows;
 const days=firstSeen.length?(await db.query(`SELECT account_id,day FROM spdecode_shop.play_tester_days
  WHERE account_id=ANY($1::text[])`,[firstSeen.map(r=>r.account_id)])).rows:[];
 return {testers:summarizePlayTesters(firstSeen,days)};
}
