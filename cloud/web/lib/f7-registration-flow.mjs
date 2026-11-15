/**
 * F7-A1-P03: registration orchestration with INJECTED durable transaction and mailer.
 * This is not wired to public endpoints. The production repository MUST use
 * SELECT FOR UPDATE and UNIQUE(email_canonical), UNIQUE(username) constraints.
 * Do not back these operations with ephemeral Redis alone.
 */
import {
  normalizeEmail, normalizeHandle, normalizeDisplayName,
  issueEmailChallenge, verifyEmailChallenge,
  generateContinuation, verifyContinuation, hashPassword, accountPolicy,
} from "./f7-account-identity.mjs";

function requireAdapters(store, mail, key) {
  if (!store || typeof store.createPending !== "function" ||
      typeof store.withPendingLock !== "function" ||
      typeof store.invalidatePending !== "function" ||
      typeof store.canStartRegistration !== "function" ||
      !mail || typeof mail.sendVerificationCode !== "function" ||
      !Buffer.isBuffer(key) || key.length < 32)
    throw Error("REGISTRATION_BACKEND_NOT_CONFIGURED");
}

export function createRegistrationFlow({store, mail, otpKey, now=()=>Date.now()}) {
  requireAdapters(store,mail,otpKey);
  if (typeof now !== "function") throw Error("REGISTRATION_BACKEND_NOT_CONFIGURED");
  return {
    async start({email,username,displayName}) {
      const e=normalizeEmail(email);
      const h=normalizeHandle(username);
      const n=normalizeDisplayName(displayName);
      if (!e || !h || !n) return {status:"INVALID_INPUT"};
      if (!await store.canStartRegistration(e)) return {status:"RATE_LIMITED"};
      const {code,record}=issueEmailChallenge(e,otpKey,now());
      await store.createPending({...record,requestedUsername:h,requestedDisplayName:n});
      try {
        await mail.sendVerificationCode(e,code,{
          challengeId:record.challengeId,expiresIn:accountPolicy.emailOtpTtlSeconds
        });
      } catch {
        await store.invalidatePending(record.challengeId);
        // No mailer exception, address, code, API key or SMTP response in logs.
        return {status:"EMAIL_UNAVAILABLE"};
      }
      return {status:"VERIFY_EMAIL",challengeId:record.challengeId,
              expiresIn:accountPolicy.emailOtpTtlSeconds};
    },
    async verify({challengeId,code}) {
      if (typeof challengeId!=="string" || typeof code!=="string")
        return {status:"INVALID_OR_EXPIRED_CODE"};
      return store.withPendingLock(challengeId,async (tx,record)=>{
        if (!record || !Number.isInteger(record.attempts) ||
            record.attempts >= accountPolicy.emailOtpMaxAttempts ||
            record.consumedAt!==null || record.verifiedAt!==null ||
            !Number.isFinite(record.expiresAt) || now()>=record.expiresAt)
          return {status:"INVALID_OR_EXPIRED_CODE"};
        const valid=verifyEmailChallenge(record,code,otpKey,now());
        // Persist attempts even when code is invalid: transaction must commit.
        await tx.incrementAttempts(record.challengeId);
        if (!valid)return {status:"INVALID_OR_EXPIRED_CODE"};
        const continuation=generateContinuation();
        await tx.markVerified(record.challengeId,{
          verifiedAt:now(),continuationSha256:continuation.tokenDigest,
          continuationExpiresAt:now()+accountPolicy.registrationContinuationTtlSeconds*1000,
        });
        return {status:"CREATE_PASSWORD",challengeId:record.challengeId,
                continuationToken:continuation.token,
                expiresIn:accountPolicy.registrationContinuationTtlSeconds};
      });
    },
    async complete({challengeId,continuationToken,password,termsVersion,privacyVersion}) {
      if (typeof challengeId!=="string" || !/^[0-9a-f]{32}$/.test(challengeId)
        || typeof termsVersion!=="string" || !/^[a-zA-Z0-9_.-]{3,64}$/.test(termsVersion)
        || typeof privacyVersion!=="string" || !/^[a-zA-Z0-9_.-]{3,64}$/.test(privacyVersion))
        return {status:"INVALID_REQUEST"};
      let passwordHash;
      try {passwordHash=await hashPassword(password);}catch{
        return {status:"INVALID_PASSWORD_POLICY"};
      }
      return store.withPendingLock(challengeId,async(tx,record)=>{
        if (!record || record.consumedAt!==null
          || !Number.isFinite(record.verifiedAt) ||
          !Number.isFinite(record.continuationExpiresAt) ||
          now()>=record.continuationExpiresAt ||
          !verifyContinuation(continuationToken,record.continuationSha256))
          return {status:"INVALID_OR_EXPIRED_REGISTRATION"};
        // This is ONE transaction. Only the DB can guarantee concurrent
        // uniqueness of username/email and single-use continuation.
        const accountId=await tx.createVerifiedAccount({
          email:record.email,username:record.requestedUsername,
          displayName:record.requestedDisplayName,passwordHash,
          emailVerifiedAt:new Date(record.verifiedAt),
          termsVersion,privacyVersion,
        });
        await tx.consumePending(challengeId,now());
        return {status:"ACCOUNT_CREATED",accountId};
      });
    },
  };
}
