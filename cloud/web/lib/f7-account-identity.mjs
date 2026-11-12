/**
 * F7-A1-P01: inert, reusable account identity and cryptographic contracts.
 *
 * Not an enabled login endpoint or user database. Only the server may import
 * this module. Durable verification challenges and concurrency-safe account
 * creation must be provided by the future PostgreSQL transaction layer.
 *
 * Never return a password, OTP or continuation token in API logs/reports.
 */
import { randomBytes, randomInt, createHmac, createHash, scrypt as callbackScrypt,
         timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { domainToASCII } from "node:url";

const scrypt = promisify(callbackScrypt);
const RESERVED = new Set([
  "admin", "administrator", "support", "soporte", "spdecode", "root", "system",
  "api", "null", "undefined", "deleted", "security", "billing", "moderator",
]);
const HASH_FORMAT = /^scrypt\$32768\$8\$2\$([0-9a-f]{48})\$([0-9a-f]{128})$/;
const OTP_FORMAT = /^[0-9]{6}$/;
const CHALLENGE_ID = /^[0-9a-f]{32}$/;
const TTL_SECONDS = 600;
const MAX_ATTEMPTS = 5;

export const accountPolicy = Object.freeze({
  handleMin: 3, handleMax: 24, passwordMin: 12, passwordMaxBytes: 256,
  emailOtpTtlSeconds: TTL_SECONDS, emailOtpMaxAttempts: MAX_ATTEMPTS,
  registrationContinuationTtlSeconds: 900,
  passwordKdf: "scrypt", passwordCost: Object.freeze({N:32768,r:8,p:2}),
  publicRegistrationEnabled: false,
});

export function normalizeHandle(value) {
  if (typeof value !== "string") return null;
  const handle = value.normalize("NFKC").toLowerCase();
  if (!/^[a-z][a-z0-9_]{2,23}$/.test(handle) || RESERVED.has(handle)) return null;
  return handle;
}

export function normalizeEmail(value) {
  if (typeof value !== "string" || value.length > 254 || value !== value.trim()
      || /[\x00-\x1f\x7f]/.test(value)) return null;
  const at = value.lastIndexOf("@");
  if (at < 1 || at === value.length-1) return null;
  const local = value.slice(0, at);
  const domain = domainToASCII(value.slice(at+1).toLowerCase());
  if (!domain || local.length > 64 || domain.length > 253
      || !/^[a-z0-9._%+-]+$/i.test(local)
      || !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(domain)
      || domain.split(".").some(label=>label.startsWith("-") || label.endsWith("-") || label.length > 63))
    return null;
  return local.toLowerCase() + "@" + domain;
}

export function normalizeDisplayName(value) {
  if (typeof value !== "string") return null;
  const display = value.trim().normalize("NFC");
  if ([...display].length < 1 || [...display].length > 80 ||
      /[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/u.test(display))
    return null;
  return display;
}

function validPassword(password) {
  return typeof password === "string"
    && password.normalize("NFC") === password
    && [...password].length >= accountPolicy.passwordMin
    && Buffer.byteLength(password, "utf8") <= accountPolicy.passwordMaxBytes
    && !/[\x00-\x1f\x7f]/.test(password);
}

export async function hashPassword(password) {
  if (!validPassword(password)) throw Error("INVALID_PASSWORD_POLICY");
  const salt = randomBytes(24);
  const derived = await scrypt(password, salt, 64, {N:32768,r:8,p:2,maxmem:128*1024*1024});
  // Versioned format; salt is unique, never store passwords in plaintext.
  return "scrypt$32768$8$2$"+salt.toString("hex")+"$"+derived.toString("hex");
}

export async function verifyPassword(password, encoded) {
  if (!validPassword(password) || typeof encoded !== "string") return false;
  const m = HASH_FORMAT.exec(encoded);
  if (!m) return false;
  const expected = Buffer.from(m[2], "hex");
  const computed = await scrypt(password, Buffer.from(m[1], "hex"), 64,
                               {N:32768,r:8,p:2,maxmem:128*1024*1024});
  return computed.length === expected.length && timingSafeEqual(computed,expected);
}

function secretKey(key) {
  if (!Buffer.isBuffer(key) || key.length < 32) throw Error("OTP_KEY_NOT_CONFIGURED");
  return key;
}
function otpDigest(key, challengeId, email, code) {
  return createHmac("sha256",secretKey(key))
    .update("spdecode:f7:email-otp:v1\0").update(challengeId).update("\0")
    .update(email).update("\0").update(code).digest("hex");
}
export function issueEmailChallenge(email, key, now = Date.now()) {
  const canonical = normalizeEmail(email);
  secretKey(key);
  if (!canonical) throw Error("INVALID_EMAIL");
  if (!Number.isFinite(now) || now < 0) throw Error("INVALID_TIME");
  const challengeId = randomBytes(16).toString("hex");
  const code = String(randomInt(0,1_000_000)).padStart(6,"0");
  const record = {
    challengeId, email: canonical, codeDigest: otpDigest(key,challengeId,canonical,code),
    expiresAt: now+TTL_SECONDS*1000, attempts: 0, verifiedAt: null, consumedAt: null,
  };
  // Return code ONLY to the trusted mailer; persist record in DB, not API output.
  return {code, record};
}
export function verifyEmailChallenge(record, code, key, now=Date.now()) {
  secretKey(key);
  if (!record || !CHALLENGE_ID.test(record.challengeId) ||
      !normalizeEmail(record.email) || record.email!==normalizeEmail(record.email) ||
      !/^[0-9a-f]{64}$/.test(record.codeDigest||"") ||
      !Number.isInteger(record.attempts) || record.attempts<0 ||
      record.attempts>=MAX_ATTEMPTS || record.verifiedAt!==null ||
      record.consumedAt!==null || !Number.isFinite(now) ||
      now < 0 || !Number.isFinite(record.expiresAt) || now>=record.expiresAt ||
      !OTP_FORMAT.test(code)) return false;
  const actual=Buffer.from(otpDigest(key,record.challengeId,record.email,code),"hex");
  return timingSafeEqual(actual,Buffer.from(record.codeDigest,"hex"));
}
export function generateContinuation() {
  const token = randomBytes(32).toString("base64url");
  return {token, tokenDigest:createHash("sha256").update(token).digest("hex")};
}
export function verifyContinuation(token, digest) {
  if(typeof token!=="string" || !/^[A-Za-z0-9_-]{43}$/.test(token) ||
     typeof digest!=="string" || !/^[0-9a-f]{64}$/.test(digest))return false;
  const actual=createHash("sha256").update(token).digest();
  return timingSafeEqual(actual,Buffer.from(digest,"hex"));
}
