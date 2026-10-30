import { settings } from "./c3-config.mjs";
export function v2Settings(env = process.env,{playIntegrityRequired=true}={}) {
  const base = settings(env);
  const certificateDigests = (env.CLOUD_PLAY_CERT_SHA256 || "").split(",").map(x=>x.trim().toLowerCase());
  const minimumVersionCode = Number(env.CLOUD_MIN_ANDROID_VERSION_CODE || "33");
  const epoch = env.CLOUD_V2_SESSION_EPOCH || "1";
  const requireHardware=env.CLOUD_KEY_ATTESTATION_REQUIRED !== "false";
  // Action Integrity requires Play token verification. The beta profile cannot pretend to provide it.
  const requireAction=playIntegrityRequired && env.CLOUD_ACTION_INTEGRITY_REQUIRED !== "false";
  const cloudProjectNumber=env.CLOUD_GOOGLE_CLOUD_PROJECT_NUMBER || "";
  // Staged V2-only switch; requiring an invalid/missing secret fails closed.
  const hpkeRequired=env.CLOUD_V2_HPKE_REQUIRED === "true";
  const hpkeSeed=env.CLOUD_V2_HPKE_PRIVATE_KEY || "";
  const hpkeKeyValid=/^[A-Za-z0-9_-]{43}$/.test(hpkeSeed) &&
    Buffer.from(hpkeSeed,"base64url").length===32 &&
    Buffer.from(hpkeSeed,"base64url").toString("base64url")===hpkeSeed;
  const maxRecentActivity=Number(env.CLOUD_INTEGRITY_MAX_RECENT_ACTIVITY || "3");
  const minimumDeviceSdk=Number(env.CLOUD_INTEGRITY_MIN_DEVICE_SDK || "33");
  const valid = certificateDigests.length > 0 && certificateDigests.length <= 4 &&
    certificateDigests.every(x=>/^[a-f0-9]{64}$/.test(x)) &&
    Number.isSafeInteger(minimumVersionCode) && minimumVersionCode >= 33 && minimumVersionCode <= 2147483647 &&
    /^[A-Za-z0-9_-]{1,32}$/.test(epoch) &&
    (!requireHardware || ((env.CLOUD_KEY_ATTESTATION_TOKEN||"").length>=32 &&
      [undefined,"tee","strongbox"].includes(env.CLOUD_KEY_ATTESTATION_LEVEL))) &&
    (!requireAction || /^[1-9][0-9]{5,18}$/.test(cloudProjectNumber)) &&
    Number.isInteger(maxRecentActivity) && maxRecentActivity>=1 && maxRecentActivity<=4 &&
    Number.isInteger(minimumDeviceSdk) && minimumDeviceSdk>=24 && minimumDeviceSdk<=100 &&
    (!hpkeRequired || hpkeKeyValid);
  const betaCore=env.CLOUD_API_ENABLED==="true" &&
    (env.CLOUD_WORKER_TOKEN||"").length>=32 && (env.CLOUD_SESSION_SIGNING_KEY||"").length>=32 &&
    /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(base.packageName) &&
    /^rediss?:\/\//.test(env.CLOUD_REDIS_URL||"") &&
    env.CLOUD_TRUST_PROXY==="true" &&
    [ "CLOUD_V1_REQUIRE_BOUND_SESSION","CLOUD_LEGACY_API_ENABLED" ].every(
      key=>env[key]===undefined||["true","false"].includes(env[key]));
  const betaSafe=!playIntegrityRequired && requireHardware;
  return {...base, configured:valid && (playIntegrityRequired ?
    (base.configured && Boolean(base.account)):(betaCore && betaSafe)),
    certificateDigests, minimumVersionCode, epoch, playIntegrityRequired, requireLicensed:true,
    requireStrong:env.CLOUD_V2_REQUIRE_STRONG_INTEGRITY !== "false",
    requirePlayProtect:env.CLOUD_V2_REQUIRE_PLAY_PROTECT === "true",
    requireAccessRisk:env.CLOUD_V2_REQUIRE_ACCESS_RISK === "true",
    requireHardware,requireAction,cloudProjectNumber,hpkeRequired,
    hardwareLevel:env.CLOUD_KEY_ATTESTATION_LEVEL === "strongbox" ? "strongbox" : "tee",
    attestationUrl:env.CLOUD_KEY_ATTESTATION_URL || "http://key-attestation:8788/verify",
    attestationToken:env.CLOUD_KEY_ATTESTATION_TOKEN || "",
    maxRecentActivity,minimumDeviceSdk};
}
export function legacyApiRetired(pathname, env = process.env) {
  return env.CLOUD_LEGACY_API_ENABLED === "false" &&
    (pathname === "/api/v1" || pathname.startsWith("/api/v1/"));
}
