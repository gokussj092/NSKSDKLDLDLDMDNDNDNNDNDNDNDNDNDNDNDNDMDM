/** Supplemental RASP. Reports are untrusted even when bound by HPKE/PoP.
 * No report can authorize a request or bypass Play, hardware, rate limits or replay.
 * Presence of developer tools is not part of this protocol.
 */
export const raspActions=new Set([4,5,6,7,8,9,10,12,13,18,19,20]);
const modes=new Set(["off","observe","enforce"]);
const accessLabels=new Set(["KNOWN_INSTALLED","UNKNOWN_INSTALLED","KNOWN_CAPTURING",
  "UNKNOWN_CAPTURING","KNOWN_CONTROLLING","UNKNOWN_CONTROLLING","KNOWN_OVERLAYS","UNKNOWN_OVERLAYS"]);
export function raspSettings(env={}) {
  const mode=env.CLOUD_RASP_MODE??"observe";
  const minVersion=Number(env.CLOUD_RASP_MIN_VERSION_CODE??"38");
  const accessMode=env.CLOUD_RASP_ACCESS_MODE??"observe";
  return {mode,minVersion,accessMode,configured:modes.has(mode)&&modes.has(accessMode)&&
    Number.isSafeInteger(minVersion)&&minVersion>=35&&minVersion<=2147483647};
}
export function parseRaspReport(value) {
  if(!value || typeof value!=="object" || Array.isArray(value) ||
     Object.keys(value).sort().join(",")!=="elapsedUs,evaluated,signals,v" || value.v!==1 ||
     !Number.isInteger(value.signals)||value.signals<0||value.signals>15 ||
     !Number.isInteger(value.evaluated)||value.evaluated<0||value.evaluated>15 ||
     !Number.isSafeInteger(value.elapsedUs)||value.elapsedUs<0||value.elapsedUs>60000000 ||
     (value.signals & ~value.evaluated)!==0)return null;
  return {v:1,signals:value.signals,evaluated:value.evaluated,elapsedUs:value.elapsedUs};
}
export function decideRasp(value,version,policy) {
  const report=parseRaspReport(value);
  const state=!report?"unknown":(report.signals&13)?"high":
    (report.signals&2)?"advisory":report.evaluated===15?"observed":"unknown";
  // UNKNOWN never means clean. Compatibility mode observes incomplete reports;
  // explicit enforcement requires all four own-process checks for new clients.
  const active=policy.mode==="enforce"&&version>=policy.minVersion;
  return {state,report,deny:active&&(state==="high"||state==="unknown")};
}
export function accessRisk(verdict) {
  const values=verdict?.tokenPayloadExternal?.environmentDetails?.appAccessRiskVerdict?.appsDetected;
  if(!Array.isArray(values)||!values.length||values.length>8||
     values.some(x=>!accessLabels.has(x)))return "unknown";
  if(values.some(x=>x.endsWith("_CAPTURING")||x.endsWith("_CONTROLLING")))return "restricted";
  if(values.some(x=>x.endsWith("_OVERLAYS")))return "advisory";
  return "observed";
}
export function denyAccessRisk(verdict,cfg,version) {
  const p=cfg.rasp;
  return !!p&&p.mode!=="off"&&p.accessMode==="enforce"&&version>=p.minVersion&&
    ["unknown","restricted"].includes(accessRisk(verdict));
}
export async function recordRasp(redis,decision,version,policy) {
  if(policy.mode==="off")return;
  // Bounded enums + attested version bucket, no session/IP/module/profile data.
  const build=Number.isSafeInteger(version)&&version>=35&&version<=4096?String(version):"other";
  const day=new Date().toISOString().slice(0,10);
  const bucket=!decision.report?"unknown":decision.report.elapsedUs<=5000?"le5ms":
    decision.report.elapsedUs<=20000?"le20ms":decision.report.elapsedUs<=100000?"le100ms":"gt100ms";
  try {
    for(const suffix of [decision.state,bucket]){
      const key=`spsec:rasp:${day}:${build}:${suffix}`;
      await redis.incr(key);await redis.expire(key,8*86400);
    }
  }catch { /* Supplemental metrics must not change the authorization decision. */ }
}
