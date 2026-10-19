import { scrypt as scryptCallback, randomBytes, randomUUID, createHmac, createHash, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { throttle } from "./c3-store.mjs";

const scrypt=promisify(scryptCallback);
const COOKIE="spdecode_admin_session";
const TTL=1800;
const KEY_PREFIX="spc6:admin:session:";
const USERNAME=/^[a-zA-Z][a-zA-Z0-9._-]{2,63}$/;
const HASH=/^scrypt\$16384\$8\$1\$([a-f0-9]{32})\$([a-f0-9]{128})$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const err=(code,status)=>({error:code,status});
const b64=x=>Buffer.from(JSON.stringify(x)).toString("base64url");

export function adminSettings(env=process.env) {
  const username=env.CLOUD_ADMIN_USERNAME||"";
  const passwordHash=env.CLOUD_ADMIN_PASSWORD_SCRYPT||"";
  const signingKey=env.CLOUD_ADMIN_SESSION_KEY||"";
  const publicOrigin=env.CLOUD_ADMIN_PUBLIC_ORIGIN||"";
  const validHash=HASH.test(passwordHash);
  let validOrigin=false;
  try {
    const u=new URL(publicOrigin);
    validOrigin=u.protocol==="https:" && !!u.hostname && u.origin===publicOrigin &&
      !u.username && !u.password && !u.port && u.hostname.includes(".");
  } catch {}
  return {
    enabled:env.CLOUD_ADMIN_ENABLED==="true" && env.CLOUD_TRUST_PROXY==="true" &&
      /^rediss?:\/\//.test(env.CLOUD_REDIS_URL||"") &&
      signingKey.length>=32 && USERNAME.test(username) && validHash && validOrigin,
    username,passwordHash,signingKey,publicOrigin,
  };
}
export async function checkPassword(password,hash) {
  if(typeof password!=="string" || password.length<16 || password.length>512) return false;
  const m=HASH.exec(hash||"");
  if(!m) return false;
  const actual=await scrypt(password,Buffer.from(m[1],"hex"),64,{
    N:16384,r:8,p:1,maxmem:32*1024*1024,
  });
  const expected=Buffer.from(m[2],"hex");
  return actual.length===expected.length && timingSafeEqual(actual,expected);
}
const sign=(raw,key)=>createHmac("sha256",key).update(raw).digest("base64url");
function safeToken(value,key,now=Math.floor(Date.now()/1000)) {
  if(!value || value.length>1024 || !/^[\w-]+\.[\w-]+$/.test(value))return null;
  const [body,tag]=value.split(".");
  const expected=Buffer.from(sign(body,key),"base64url");
  const actual=Buffer.from(tag,"base64url");
  if(expected.length!==actual.length || !timingSafeEqual(expected,actual))return null;
  try {
    const data=JSON.parse(Buffer.from(body,"base64url").toString("utf8"));
    if(data.aud!=="spdecode-admin-c6" || !UUID.test(data.jti) ||
       !Number.isInteger(data.iat) || !Number.isInteger(data.exp) ||
       data.iat>now+5 || data.exp<=now || data.exp-data.iat>TTL ||
       typeof data.sub!=="string" || !/^[a-f0-9]{64}$/.test(data.sub))return null;
    return data;
  }catch{return null;}
}
export function parseAdminCookie(request) {
  const raw=request.headers.get("cookie")||"";
  if(raw.length>4096)return null;
  const entries=raw.split(";").map(x=>x.trim()).filter(x=>x.startsWith(COOKIE+"="));
  if(entries.length!==1)return null;
  return entries[0].slice(COOKIE.length+1);
}
export function validMutation(request,cfg) {
  const origin=request.headers.get("origin");
  const site=request.headers.get("sec-fetch-site");
  return origin===cfg.publicOrigin && (site===null || site==="same-origin") &&
    request.headers.get("x-spdecode-admin-action")==="1" &&
    request.headers.get("content-type")?.split(";")[0]?.trim()==="application/json";
}
export const cookieHeader=(token,maxAge=TTL)=>
  COOKIE+"="+token+"; Path=/api/admin; HttpOnly; Secure; SameSite=Strict; Max-Age="+maxAge;
export const deleteCookie=()=>cookieHeader("",0);

const usernameDigest=(username)=>createHash("sha256").update(username,"utf8").digest();
const matchesUsername=(a,b)=>{
  // Equal-length hashed comparisons avoid username timing leakage.
  return typeof a==="string" && USERNAME.test(a) &&
    timingSafeEqual(usernameDigest(a),usernameDigest(b));
};
export async function adminLogin(redis,request,username,password,cfg=adminSettings()) {
  if(!cfg.enabled)return err("ADMIN_DISABLED",503);
  if(!validMutation(request,cfg))return err("CSRF_REJECTED",403);
  // Global and per-account counters work without reading/checking client IP.
  // Keep the same response for nonexistent usernames and invalid passwords.
  const account=matchesUsername(username,cfg.username);
  const scope=account?usernameDigest(cfg.username).toString("hex"):"unknown";
  const allOk=await throttle(redis,"spc6:admin:login:global",60,900);
  const userOk=await throttle(redis,"spc6:admin:login:user:"+scope,8,900);
  if(!allOk||!userOk)return err("RATE_LIMITED",429);
  const validPassword=await checkPassword(password,cfg.passwordHash);
  if(!account||!validPassword)return err("INVALID_CREDENTIALS",401);
  const now=Math.floor(Date.now()/1000);
  const sub=usernameDigest(cfg.username).toString("hex");
  const claims={aud:"spdecode-admin-c6",jti:randomUUID(),iat:now,exp:now+TTL,sub};
  const stored=await redis.set(KEY_PREFIX+claims.jti,sub,{EX:TTL,NX:true});
  if(stored!=="OK")return err("SERVICE_UNAVAILABLE",503);
  const body=b64(claims);
  return {token:body+"."+sign(body,cfg.signingKey),expiresIn:TTL};
}
export async function authenticateAdmin(redis,request,cfg=adminSettings()) {
  if(!cfg.enabled)return null;
  const claim=safeToken(parseAdminCookie(request),cfg.signingKey);
  if(!claim)return null;
  const expected=usernameDigest(cfg.username).toString("hex");
  if(claim.sub!==expected)return null;
  if(await redis.get(KEY_PREFIX+claim.jti)!==expected)return null;
  return claim;
}
export async function revokeAdmin(redis,claims) {
  await redis.del(KEY_PREFIX+claims.jti);
}
