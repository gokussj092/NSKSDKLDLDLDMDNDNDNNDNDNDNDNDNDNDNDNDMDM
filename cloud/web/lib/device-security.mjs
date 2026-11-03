import { createHash } from "node:crypto";
import { throttle } from "./c3-store.mjs";
import {v2DevicePolicyStatus} from "./v2-device-admission-policy.mjs";

export const keyId = key => createHash("sha256").update(key).digest("hex");
export const attestationChallenge = (nonce, id, bootstrapKey) => createHash("sha256")
  .update(["SPDECODE-HARDWARE-V1", nonce, id, bootstrapKey].join("\n")).digest("base64url");
export const keyRecordName = key => "spsec:key:" + keyId(key);

export async function registeredKey(redis, key, cfg) {
  if (await redis.get("spsec:revoked:" + keyId(key))) return null;
  const raw = await redis.get(keyRecordName(key));
  if (!raw) return null;
  try {
    const value = JSON.parse(raw);
    if (value.epoch !== cfg.epoch || !Number.isSafeInteger(value.expires) || value.expires <= Date.now() ||
        (value.deviceRevision??0)!==(cfg.deviceRevision??0) ||
        value.expires > Date.now()+86400000 ||
        (cfg.playIntegrityRequired===false&&
         (!Number.isSafeInteger(value.versionCode)||value.versionCode<cfg.minimumVersionCode)) ||
        !["tee", "strongbox"].includes(value.level) ||
        (cfg.hardwareLevel === "strongbox" && value.level !== "strongbox")) return null;
    return value;
  } catch { return null; }
}

/** Only this private service verifies certificates. No HTTP-supplied verdict is trusted. */
export async function verifyHardware(chain, challenge, publicKey, cfg, {fetchImpl = fetch,policyLoader = v2DevicePolicyStatus} = {}) {
  if (!Array.isArray(chain) || chain.length < 2 || chain.length > 8 ||
      chain.some(x => typeof x !== "string" || x.length > 8192 || !/^[A-Za-z0-9+/]+={0,2}$/.test(x))) return null;
  if (cfg.attestationUrl !== "http://key-attestation:8788/verify" || cfg.attestationToken.length < 32)
    throw Error("ATTESTATION_NOT_CONFIGURED");
  // Server-to-server policy is never provided by Android and cannot weaken
  // trust anchor, APK signer, Keystore level or challenge verification.
  const policy=await policyLoader();
  const devicePolicy={
    patchMonths:policy.patchMonths,enforcePatch:policy.enforcePatch,
    enforceBoot:policy.enforceBoot,expiresAt:Date.now()+60_000,
  };
  const response = await fetchImpl(cfg.attestationUrl, {
    method:"POST", redirect:"error", signal:AbortSignal.timeout(10000), cache:"no-store",
    headers:{"Content-Type":"application/json", "X-SP-Attestation-Token":cfg.attestationToken},
    body:JSON.stringify({chain,challenge,publicKey,...(devicePolicy?{devicePolicy}:{})}),
  });
  if (!response.ok) return null;
  const reader = response.body.getReader(); let size = 0; const parts = [];
  try {
    for (;;) { const {done,value}=await reader.read(); if(done)break;
      size+=value.length; if(size>2048){await reader.cancel();throw Error("ATTESTATION_RESPONSE_SIZE");}
      parts.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  const result=JSON.parse(Buffer.concat(parts).toString("utf8"));
  return result.valid === true && result.publicKey === publicKey &&
    ["tee","strongbox"].includes(result.level) &&
    (cfg.hardwareLevel !== "strongbox" || result.level === "strongbox") ? result : null;
}

export async function rememberKey(redis, key, level, cfg, versionCode=null) {
  if (await redis.get("spsec:revoked:" + keyId(key))) return false;
  const value={level,epoch:cfg.epoch,deviceRevision:cfg.deviceRevision??0,expires:Date.now()+86400000,
    ...(Number.isSafeInteger(versionCode)&&versionCode>=cfg.minimumVersionCode?
      {versionCode}:{})};
  return await redis.set(keyRecordName(key),JSON.stringify(value),{EX:86400}) === "OK";
}

/** Per-key budgets survive new sessions. Global budgets also cover bearer-only V1. */
export async function workBudget(redis, claims) {
  if (claims.key) {
    const id=keyId(claims.key);
    if (!await throttle(redis,"spsec:work:key-minute:"+id,10,60) ||
        !await throttle(redis,"spsec:work:key-day:"+id,300,86400)) return false;
  }
  return throttle(redis,"spsec:work:global",120,60);
}
