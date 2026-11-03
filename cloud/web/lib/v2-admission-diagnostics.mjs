/** Aggregate decision telemetry only. Never retain tokens, keys, IPs or certificates. */
const key=now=>"spc2:admission:"+new Date(now).toISOString().slice(0,10);
const safe=value=>typeof value==="string"&&/^[A-Z][A-Z0-9_]{1,63}$/.test(value);
export function playSignals(verdict){
 const p=verdict?.tokenPayloadExternal,d=p?.deviceIntegrity;
 const labels=Array.isArray(d?.deviceRecognitionVerdict)?d.deviceRecognitionVerdict:[];
 return {application:["PLAY_RECOGNIZED","UNRECOGNIZED_VERSION","UNEVALUATED"].includes(p?.appIntegrity?.appRecognitionVerdict)?p.appIntegrity.appRecognitionVerdict:"UNKNOWN",
  licensing:["LICENSED","UNLICENSED","UNEVALUATED"].includes(p?.accountDetails?.appLicensingVerdict)?p.accountDetails.appLicensingVerdict:"UNKNOWN",
  device:labels.includes("MEETS_STRONG_INTEGRITY")?"STRONG":labels.includes("MEETS_DEVICE_INTEGRITY")?"DEVICE":labels.includes("MEETS_BASIC_INTEGRITY")?"BASIC":"UNKNOWN",
  sdk:Number.isInteger(d?.deviceAttributes?.sdkVersion)&&d.deviceAttributes.sdkVersion>=19&&d.deviceAttributes.sdkVersion<=100?d.deviceAttributes.sdkVersion:null,
  root:"UNKNOWN"};
}
export async function recordAdmission(redis,stage,outcome,reason,signals=null,now=Date.now()){
 if(!["SESSION","ACTION"].includes(stage)||!["ACCEPTED","REJECTED","OBSERVED","UNAVAILABLE"].includes(outcome)||!safe(reason))return;
 try{
  if(typeof redis.hIncrBy!=="function")return;
  const bucket=key(now),fields=[stage+"_"+outcome,"REASON_"+reason];
  if(signals){
   for(const name of ["application","licensing","device"])if(safe(signals[name]))fields.push("SIGNAL_"+name.toUpperCase()+"_"+signals[name]);
   fields.push(signals.sdk===null?"SIGNAL_SDK_UNKNOWN":"SIGNAL_SDK_"+signals.sdk);
  }
  for(const field of fields)await redis.hIncrBy(bucket,field,1);
  await redis.expire(bucket,8*86400);
 }catch{ /* Observability cannot become an admission requirement. */ }
}
export async function admissionDiagnostics(redis,now=Date.now()){
 if(typeof redis.hGetAll!=="function")return null;
 try{
  const values=await redis.hGetAll(key(now)),counts={};
  for(const [field,raw] of Object.entries(values||{}))if(/^[A-Z][A-Z0-9_]{1,95}$/.test(field)&&/^\d{1,15}$/.test(String(raw)))counts[field]=Number(raw);
  const accepted=counts.SESSION_ACCEPTED||0,rejected=counts.SESSION_REJECTED||0;
  return {period:"utc_today",date:new Date(now).toISOString().slice(0,10),unit:"session_attempts",
   accepted,rejected,total:accepted+rejected,rejectionPercent:accepted+rejected?Math.round(10000*rejected/(accepted+rejected))/100:null,
   counts,rootDetection:"unknown",updatedAt:new Date(now).toISOString()};
 }catch{return null;}
}
