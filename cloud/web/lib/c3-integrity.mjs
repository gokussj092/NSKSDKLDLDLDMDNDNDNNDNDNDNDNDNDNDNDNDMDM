import { createPrivateKey, createSign } from "node:crypto";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const PLAY_API = "https://playintegrity.googleapis.com/v1/";
const SCOPE = "https://www.googleapis.com/auth/playintegrity";
const MAX_ATTESTATION_AGE = 120_000;
const b64 = x => Buffer.from(JSON.stringify(x)).toString("base64url");

/** OAuth service account JWT: never embed these credentials in Android/C++. */
export async function googleAccessToken(account, { fetchImpl = fetch } = {}) {
  const now = Math.floor(Date.now()/1000);
  const unsigned = b64({alg:"RS256",typ:"JWT"}) + "." + b64({
    iss:account.client_email, sub:account.client_email, aud:TOKEN_URL,
    scope:SCOPE, iat:now, exp:now+300,
  });
  const signer = createSign("RSA-SHA256");
  signer.update(unsigned); signer.end();
  const assertion = unsigned + "." + signer.sign(createPrivateKey(account.private_key)).toString("base64url");
  const response = await fetchImpl(TOKEN_URL, {
    method:"POST", signal:AbortSignal.timeout(8000),
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:new URLSearchParams({
      grant_type:"urn:ietf:params:oauth:grant-type:jwt-bearer", assertion,
    }).toString(),
  });
  if (!response.ok) throw Error("GOOGLE_AUTH_UNAVAILABLE");
  const result = await response.json();
  if (!result.access_token || result.token_type?.toLowerCase() !== "bearer") throw Error("GOOGLE_AUTH_INVALID");
  return result.access_token;
}

export function integrityVerdictReason(verdict, { nonce, requestHash, packageName, now = Date.now(), requireLicensed = true, requireStrong = false,
  certificateDigests, minimumVersionCode, requirePlayProtect = false, requireAccessRisk = false,
  minimumDeviceSdk, maxRecentActivity, deviceIntegrity = "device", requireSdk = true, requireRecentActivity = true }) {
  const details = verdict?.tokenPayloadExternal?.requestDetails;
  const app = verdict?.tokenPayloadExternal?.appIntegrity;
  const device = verdict?.tokenPayloadExternal?.deviceIntegrity;
  const account = verdict?.tokenPayloadExternal?.accountDetails;
  const recorded = Number(details?.timestampMillis);
  if ((requestHash !== undefined ? (typeof details?.requestHash!=="string" || details.requestHash!==requestHash) :
      (typeof details?.nonce !== "string" || details.nonce !== nonce)) ||
      details.requestPackageName !== packageName || !Number.isFinite(recorded) ||
      now - recorded > MAX_ATTESTATION_AGE || recorded > now + 5000) return "PLAY_REQUEST_BINDING";
  if (app?.appRecognitionVerdict !== "PLAY_RECOGNIZED" || app.packageName !== packageName) return "PLAY_APP_RECOGNITION";
  if (certificateDigests) {
    const certificates = app.certificateSha256Digest;
    if (!Array.isArray(certificates) || !certificates.length || !certificateDigests.length ||
        certificates.some(value => typeof value !== "string" ||
          !/^[A-Za-z0-9_-]{43}=?$/.test(value) ||
          !certificateDigests.includes(Buffer.from(value,"base64url").toString("hex")))) return "PLAY_SIGNING_CERTIFICATE";
  }
  if (minimumVersionCode !== undefined && (!/^[1-9][0-9]{0,9}$/.test(String(app.versionCode)) ||
      !Number.isSafeInteger(Number(app.versionCode)) || Number(app.versionCode) < minimumVersionCode)) return "PLAY_APP_VERSION";
  const recognized = device?.deviceRecognitionVerdict;
  const requiredLabel=deviceIntegrity==="observe"?null:deviceIntegrity==="basic"?"MEETS_BASIC_INTEGRITY":"MEETS_DEVICE_INTEGRITY";
  if (requiredLabel && (!Array.isArray(recognized) || !recognized.includes(requiredLabel))) return "PLAY_DEVICE_LEVEL";
  if (requireStrong && (!Array.isArray(recognized)||!recognized.includes("MEETS_STRONG_INTEGRITY"))) return "PLAY_STRONG_INTEGRITY";
  if (minimumDeviceSdk !== undefined) {
    const sdk=device?.deviceAttributes?.sdkVersion;
    if ((sdk===undefined && requireSdk) || (sdk!==undefined && (!Number.isInteger(sdk) || sdk < minimumDeviceSdk))) return "PLAY_SDK";
  }
  if (maxRecentActivity !== undefined) {
    const activity=device?.recentDeviceActivity?.deviceActivityLevel;
    if ((activity===undefined&&requireRecentActivity) || (activity!==undefined &&
        (!/^LEVEL_[1-4]$/.test(activity)||Number(activity.at(-1))>maxRecentActivity))) return "PLAY_ACTIVITY";
  }
  if (requireLicensed && account?.appLicensingVerdict !== "LICENSED") return "PLAY_LICENSE";
  const environment = verdict.tokenPayloadExternal.environmentDetails;
  if (requirePlayProtect && environment?.playProtectVerdict !== "NO_ISSUES") return "PLAY_PROTECT";
  if (requireAccessRisk) {
    const detected = environment?.appAccessRiskVerdict?.appsDetected;
    if (!Array.isArray(detected) || !detected.length || detected.some(value =>
      !["KNOWN_INSTALLED","UNKNOWN_INSTALLED"].includes(value))) return "PLAY_ACCESS_RISK";
  }
  return null;
}
export function checkIntegrityVerdict(verdict,options){return integrityVerdictReason(verdict,options)===null;}

export async function decodePlayToken(token, cfg, { fetchImpl = fetch } = {}) {
  if (typeof token !== "string" || token.length < 80 || token.length > 16384) return null;
  const access = await googleAccessToken(cfg.account, { fetchImpl });
  // The destination is fixed, derived only from validated server configuration.
  const response = await fetchImpl(PLAY_API + encodeURIComponent(cfg.packageName) + ":decodeIntegrityToken", {
    method:"POST", signal:AbortSignal.timeout(10000), redirect:"error",
    headers:{"Content-Type":"application/json",Authorization:"Bearer "+access},
    body:JSON.stringify({integrityToken:token}),
  });
  if (!response.ok) return null;
  return response.json();
}

export async function verifyPlayToken(token, nonce, cfg, { fetchImpl = fetch } = {}) {
  return checkIntegrityVerdict(await decodePlayToken(token,cfg,{fetchImpl}), {
    nonce, packageName:cfg.packageName,
    requireLicensed:cfg.requireLicensed, requireStrong:cfg.requireStrong,
    certificateDigests:cfg.certificateDigests,minimumVersionCode:cfg.minimumVersionCode,
    requirePlayProtect:cfg.requirePlayProtect,requireAccessRisk:cfg.requireAccessRisk,
    minimumDeviceSdk:cfg.minimumDeviceSdk,maxRecentActivity:cfg.maxRecentActivity,
  });
}

