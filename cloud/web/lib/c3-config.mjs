/** C3 is disabled unless every server-side security prerequisite exists. */
export function settings(env = process.env) {
  const packageName = env.CLOUD_GOOGLE_PLAY_PACKAGE || "";
  const workerToken = env.CLOUD_WORKER_TOKEN || "";
  const signingKey = env.CLOUD_SESSION_SIGNING_KEY || "";
  const json = env.CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON || "";
  let account = null;
  try {
    const value = JSON.parse(json);
    if (value && value.type === "service_account" && typeof value.client_email === "string"
        && typeof value.private_key === "string" && value.private_key.includes("PRIVATE KEY")) account = value;
  } catch {}
  // QA is a temporary, explicit VPS-only mode; expiry cannot be unlimited.
  const qaExpiration=Number(env.CLOUD_QA_EXPIRES_AT || 0);
  const now=Math.floor(Date.now()/1000);
  const qaActive=env.CLOUD_QA_ENABLED==="true" &&
    Number.isSafeInteger(qaExpiration) && qaExpiration>now &&
    qaExpiration<=now+24*3600;
  const validPackage = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(packageName);
  const configured = env.CLOUD_API_ENABLED === "true" &&
    workerToken.length >= 32 && signingKey.length >= 32 && validPackage &&
    (Boolean(account) || qaActive || env.CLOUD_BETA_ADMISSION_ENABLED === "true") && /^rediss?:\/\//.test(env.CLOUD_REDIS_URL || "") &&
    env.CLOUD_TRUST_PROXY === "true";
  return {
    configured, account, packageName, workerToken, signingKey,
    qaActive, qaExpiration,
    betaAdmissionAllowed:env.CLOUD_BETA_ADMISSION_ENABLED === "true",
    redisUrl: env.CLOUD_REDIS_URL,
    requireLicensed: env.CLOUD_REQUIRE_LICENSED !== "false",
    requireStrong: env.CLOUD_REQUIRE_STRONG_INTEGRITY === "true",
    allowedOrigin: env.CLOUD_ANDROID_ORIGIN || "",
  };
}
export const limits = Object.freeze({
  maxPublicFileBytes: 8 * 1024 * 1024,
  maxPublicTextChars: 250_000,
  maxJsonBodyBytes: 11 * 1024 * 1024,
  challengeTtlSeconds: 120,
  sessionTtlSeconds: 300,
  requestsPerSessionMinute: 10,
  requestsPerIpWindow: 20,
  maxActivePerSession: 2,
});
