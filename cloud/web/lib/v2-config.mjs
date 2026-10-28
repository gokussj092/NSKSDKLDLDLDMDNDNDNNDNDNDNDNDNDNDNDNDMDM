import { settings } from "./c3-config.mjs";
export function v2Settings(env = process.env) {
  const base = settings(env);
  const certificateDigests = (env.CLOUD_PLAY_CERT_SHA256 || "").split(",").map(x=>x.trim().toLowerCase());
  const minimumVersionCode = Number(env.CLOUD_MIN_ANDROID_VERSION_CODE || "33");
  const epoch = env.CLOUD_V2_SESSION_EPOCH || "1";
  const valid = certificateDigests.length > 0 && certificateDigests.length <= 4 &&
    certificateDigests.every(x=>/^[a-f0-9]{64}$/.test(x)) &&
    Number.isSafeInteger(minimumVersionCode) && minimumVersionCode >= 33 && minimumVersionCode <= 2147483647 &&
    /^[A-Za-z0-9_-]{1,32}$/.test(epoch);
  return {...base, configured: base.configured && Boolean(base.account) && valid,
    certificateDigests, minimumVersionCode, epoch, requireLicensed:true,
    requireStrong:env.CLOUD_V2_REQUIRE_STRONG_INTEGRITY !== "false",
    requirePlayProtect:env.CLOUD_V2_REQUIRE_PLAY_PROTECT === "true",
    requireAccessRisk:env.CLOUD_V2_REQUIRE_ACCESS_RISK === "true"};
}
export function legacyApiRetired(pathname, env = process.env) {
  return env.CLOUD_LEGACY_API_ENABLED !== "true" &&
    (pathname === "/api/v1" || pathname.startsWith("/api/v1/")) &&
    !["/api/v1/health","/api/v1/ready"].includes(pathname.replace(/\/$/,""));
}
