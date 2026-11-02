import { raspSettings } from "./rasp-policy.mjs";
import { settings } from "./c3-config.mjs";
export function v2Settings(env = process.env,{playIntegrityRequired=true,playPolicy=null}={}) {
  const base = settings(env);
  const rasp=raspSettings(env);
  const certificateDigests = (env.CLOUD_PLAY_CERT_SHA256 || "").split(",").map(x=>x.trim().toLowerCase());
  const minimumVersionCode = Number(env.CLOUD_MIN_ANDROID_VERSION_CODE || "33");
  const epoch = env.CLOUD_V2_SESSION_EPOCH || "1";
  const requireHardware=env.CLOUD_KEY_ATTESTATION_REQUIRED !== "false";
  // Action Integrity requires Play token verification. The beta profile cannot pretend to provide it.
  const requireAction=playIntegrityRequired && (playPolicy?.requireAction??(env.CLOUD_ACTION_INTEGRITY_REQUIRED !== "false"));
  const cloudProjectNumber=env.CLOUD_GOOGLE_CLOUD_PROJECT_NUMBER || "";
  const maxRecentActivity=Number(env.CLOUD_INTEGRITY_MAX_RECENT_ACTIVITY || "3");
  const minimumDeviceSdk=playPolicy?.minimumDeviceSdk??Number(env.CLOUD_INTEGRITY_MIN_DEVICE_SDK || "24");
  const valid = (rasp.accessMode!=="enforce" || (playIntegrityRequired && requireAction)) && certificateDigests.length > 0 && certificateDigests.length <= 4 &&
    certificateDigests.every(x=>/^[a-f0-9]{64}$/.test(x)) &&
    Number.isSafeInteger(minimumVersionCode) && minimumVersionCode >= 33 && minimumVersionCode <= 2147483647 &&
    /^[A-Za-z0-9_-]{1,32}$/.test(epoch) &&
    (!requireHardware || ((env.CLOUD_KEY_ATTESTATION_TOKEN||"").length>=32 &&
      [undefined,"tee","strongbox"].includes(env.CLOUD_KEY_ATTESTATION_LEVEL))) &&
    (!requireAction || /^[1-9][0-9]{5,18}$/.test(cloudProjectNumber)) &&
    Number.isInteger(maxRecentActivity) && maxRecentActivity>=1 && maxRecentActivity<=4 &&
    Number.isInteger(minimumDeviceSdk) && minimumDeviceSdk>=24 && minimumDeviceSdk<=100;
  const betaCore=env.CLOUD_API_ENABLED==="true" &&
    (env.CLOUD_WORKER_TOKEN||"").length>=32 && (env.CLOUD_SESSION_SIGNING_KEY||"").length>=32 &&
    /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(base.packageName) &&
    /^rediss?:\/\//.test(env.CLOUD_REDIS_URL||"") &&
    env.CLOUD_TRUST_PROXY==="true" &&
    [ "CLOUD_V1_REQUIRE_BOUND_SESSION","CLOUD_LEGACY_API_ENABLED" ].every(
      key=>env[key]===undefined||["true","false"].includes(env[key]));
  const betaSafe=!playIntegrityRequired && requireHardware;
  return {...base, configured:valid && rasp.configured && (playIntegrityRequired ?
    (base.configured && Boolean(base.account)):(betaCore && betaSafe)),
    rasp, certificateDigests, minimumVersionCode, epoch, playIntegrityRequired,
    playMode:playPolicy?.mode??(playIntegrityRequired?"enforce":"observe"),
    playIntegrityRequested:playPolicy?.integrityRequested??playIntegrityRequired,
    requireLicensed:playPolicy?.requireLicensed??true,
    requireStrong:playPolicy?playPolicy.deviceIntegrity==="strong":env.CLOUD_V2_REQUIRE_STRONG_INTEGRITY === "true",
    deviceIntegrity:playPolicy?.deviceIntegrity??"device",requireSdk:playPolicy?.requireSdk??false,
    requireRecentActivity:false,
    requirePlayProtect:playPolicy?.requirePlayProtect??(env.CLOUD_V2_REQUIRE_PLAY_PROTECT === "true"),
    requireAccessRisk:playPolicy?.requireAccessRisk??(env.CLOUD_V2_REQUIRE_ACCESS_RISK === "true"),
    sessionSeconds:playPolicy?.sessionSeconds??1800,
    policyRevision:playPolicy?.revision??0,
    requireHardware,requireAction,cloudProjectNumber,
    hardwareLevel:env.CLOUD_KEY_ATTESTATION_LEVEL === "strongbox" ? "strongbox" : "tee",
    attestationUrl:env.CLOUD_KEY_ATTESTATION_URL || "http://key-attestation:8788/verify",
    attestationToken:env.CLOUD_KEY_ATTESTATION_TOKEN || "",
    maxRecentActivity,minimumDeviceSdk};
}
export function legacyApiRetired(pathname, env = process.env) {
  return env.CLOUD_LEGACY_API_ENABLED === "false" &&
    (pathname === "/api/v1" || pathname.startsWith("/api/v1/"));
}
