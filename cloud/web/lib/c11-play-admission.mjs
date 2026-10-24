/** 15-day maximum, operator-only temporary off-Play distribution window.
 * This disables Google attestation, NOT Redis rate limits, signed short sessions,
 * challenge IP binding, service maintenance, or worker isolation.
 */
const KEY="spcplay:beta-admission:until";
export const MAX_BETA_SECONDS=15*24*60*60;
export function betaPermitted(env=process.env){return env.CLOUD_BETA_ADMISSION_ENABLED==="true";}
export async function admissionPolicy(redis,env=process.env,{now=Date.now()}={}){
 const allowed=betaPermitted(env);
 if(!allowed)return {integrityRequired:true,betaUntil:null,locked:true};
 const stamp=Number(await redis.get(KEY));
 if(!Number.isSafeInteger(stamp)||stamp<=now||stamp>now+MAX_BETA_SECONDS*1000)
  return {integrityRequired:true,betaUntil:null,locked:false};
 return {integrityRequired:false,betaUntil:new Date(stamp).toISOString(),locked:false};
}
export async function setAdmissionPolicy(redis,required,env=process.env,{now=Date.now()}={}){
 if(typeof required!=="boolean")throw Error("INVALID_POLICY");
 if(!required&&!betaPermitted(env))throw Error("BETA_LOCKED");
 if(required){await redis.del(KEY);return admissionPolicy(redis,env,{now});}
 const until=now+MAX_BETA_SECONDS*1000;
 await redis.set(KEY,String(until),{EX:MAX_BETA_SECONDS});
 return admissionPolicy(redis,env,{now});
}
