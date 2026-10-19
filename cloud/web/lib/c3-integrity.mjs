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

export function checkIntegrityVerdict(verdict, { nonce, packageName, now = Date.now(), requireLicensed = true, requireStrong = false }) {
  const details = verdict?.tokenPayloadExternal?.requestDetails;
  const app = verdict?.tokenPayloadExternal?.appIntegrity;
  const device = verdict?.tokenPayloadExternal?.deviceIntegrity;
  const account = verdict?.tokenPayloadExternal?.accountDetails;
  const recorded = Number(details?.timestampMillis);
  if (typeof details?.nonce !== "string" || details.nonce !== nonce ||
      details.requestPackageName !== packageName || !Number.isFinite(recorded) ||
      Math.abs(now - recorded) > MAX_ATTESTATION_AGE) return false;
  if (app?.appRecognitionVerdict !== "PLAY_RECOGNIZED" || app.packageName !== packageName) return false;
  const recognized = device?.deviceRecognitionVerdict;
  if (!Array.isArray(recognized) || !recognized.includes("MEETS_DEVICE_INTEGRITY")) return false;
  if (requireStrong && !recognized.includes("MEETS_STRONG_INTEGRITY")) return false;
  if (requireLicensed && account?.appLicensingVerdict !== "LICENSED") return false;
  return true;
}

export async function verifyPlayToken(token, nonce, cfg, { fetchImpl = fetch } = {}) {
  if (typeof token !== "string" || token.length < 80 || token.length > 16384) return false;
  const access = await googleAccessToken(cfg.account, { fetchImpl });
  // The destination is fixed, derived only from validated server configuration.
  const response = await fetchImpl(PLAY_API + encodeURIComponent(cfg.packageName) + ":decodeIntegrityToken", {
    method:"POST", signal:AbortSignal.timeout(10000),
    headers:{"Content-Type":"application/json",Authorization:"Bearer "+access},
    body:JSON.stringify({integrityToken:token}),
  });
  if (!response.ok) return false;
  return checkIntegrityVerdict(await response.json(), {
    nonce, packageName:cfg.packageName,
    requireLicensed:cfg.requireLicensed, requireStrong:cfg.requireStrong,
  });
}
