import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import {createRegistrationFlow} from "../lib/f7-registration-flow.mjs";

const NOW=1773000000000;
function scenario({mailFails=false,mayStart=true}={}) {
  let clock=NOW;
  const pending=new Map(),accounts=[];
  const sent=[];
  const store={
    async canStartRegistration(){return mayStart;},
    async createPending(record){pending.set(record.challengeId,{...record});},
    async invalidatePending(id){pending.delete(id);},
    async withPendingLock(id,callback) {
      const record=pending.get(id);
      const tx={
        async incrementAttempts(key){pending.get(key).attempts++;},
        async markVerified(key,fields){
          Object.assign(pending.get(key),{
            verifiedAt:fields.verifiedAt,
            continuationSha256:fields.continuationSha256,
            continuationExpiresAt:fields.continuationExpiresAt,
          });
        },
        async createVerifiedAccount(item){
          if(accounts.some(x=>x.username===item.username || x.email===item.email))
            throw Error("UNIQUE_CONSTRAINT");
          accounts.push(item);
          return "11111111-1111-4111-8111-111111111111";
        },
        async consumePending(key,when){pending.get(key).consumedAt=when;},
      };
      return callback(tx,record);
    },
  };
  const mail={
    async sendVerificationCode(email,code,meta){
      if(mailFails)throw Error("SMTP_SECRET_TOKEN_NEVER_LOG_THIS");
      sent.push({email,code,meta});
    },
  };
  const flow=createRegistrationFlow({store,mail,otpKey:randomBytes(32),now:()=>clock});
  return {flow,pending,accounts,sent,advance(ms){clock+=ms}};
}
const first={email:"Human@Example.COM",username:"Ghost_DEV",displayName:"María"};

test("start normalizes fields without persisting OTP or plaintext password",async()=>{
  const s=scenario(),r=await s.flow.start(first);
  assert.equal(r.status,"VERIFY_EMAIL");
  assert.equal(s.sent.length,1);
  const record=s.pending.get(r.challengeId);
  assert.equal(record.email,"human@example.com");
  assert.equal(record.requestedUsername,"ghost_dev");
  assert.equal(record.requestedDisplayName,"María");
  assert(!JSON.stringify(record).includes(s.sent[0].code));
  assert.equal(s.accounts.length,0);
});
test("email OTP then continuation then password creates one verified user",async()=>{
  const s=scenario();
  const start=await s.flow.start(first);
  const verified=await s.flow.verify({challengeId:start.challengeId,code:s.sent[0].code});
  assert.equal(verified.status,"CREATE_PASSWORD");
  const done=await s.flow.complete({
    challengeId:start.challengeId,continuationToken:verified.continuationToken,
    password:"UnaClave-MuySegura-yUnica-2026!",termsVersion:"terms-2026-11",
    privacyVersion:"privacy-2026-11",
  });
  assert.equal(done.status,"ACCOUNT_CREATED");
  assert.equal(s.accounts.length,1);
  assert.equal(s.accounts[0].username,"ghost_dev");
  assert.match(s.accounts[0].passwordHash,/^scrypt\$/);
  assert(!JSON.stringify(s.accounts[0]).includes("UnaClave-MuySegura-yUnica-2026!"));
  const replay=await s.flow.complete({
    challengeId:start.challengeId,continuationToken:verified.continuationToken,
    password:"OtraClave-MuySegura-yUnica-2026!",termsVersion:"terms-2026-11",
    privacyVersion:"privacy-2026-11",
  });
  assert.equal(replay.status,"INVALID_OR_EXPIRED_REGISTRATION");
  assert.equal(s.accounts.length,1);
});
test("five bad codes exhaust challenge without issuing a continuation",async()=>{
  const s=scenario(),start=await s.flow.start(first);
  const otp=s.sent[0].code;
  const bad=otp==="999999"?"000000":"999999";
  for(let i=0;i<5;i++){
    const result=await s.flow.verify({challengeId:start.challengeId,code:bad});
    assert.equal(result.status,"INVALID_OR_EXPIRED_CODE");
  }
  const attempt=await s.flow.verify({challengeId:start.challengeId,code:otp});
  assert.equal(attempt.status,"INVALID_OR_EXPIRED_CODE");
  assert.equal(s.pending.get(start.challengeId).attempts,5);
});
test("expired verification blocks password creation",async()=>{
  const s=scenario(),start=await s.flow.start(first);
  s.advance(600_000);
  assert.equal((await s.flow.verify({
    challengeId:start.challengeId,code:s.sent[0].code
  })).status,"INVALID_OR_EXPIRED_CODE");
});
test("expired continuation cannot create account",async()=>{
  const s=scenario(),start=await s.flow.start(first);
  const verified=await s.flow.verify({
    challengeId:start.challengeId,code:s.sent[0].code
  });
  s.advance(901_000);
  const result=await s.flow.complete({
    challengeId:start.challengeId,continuationToken:verified.continuationToken,
    password:"UnaClave-MuySegura-yUnica-2026!",termsVersion:"terms-2026-11",
    privacyVersion:"privacy-2026-11",
  });
  assert.equal(result.status,"INVALID_OR_EXPIRED_REGISTRATION");
  assert.equal(s.accounts.length,0);
});
test("SMTP failure invalidates challenge and hides provider secret exception",async()=>{
  const s=scenario({mailFails:true}),r=await s.flow.start(first);
  assert.equal(r.status,"EMAIL_UNAVAILABLE");
  assert.equal(s.pending.size,0);
  assert(!JSON.stringify(r).includes("SMTP_SECRET"));
});
test("invalid display/handle/email and rate limit do not create records",async()=>{
  const s=scenario();
  for(const data of [{...first,username:"admin"},{...first,email:"bad"},
                     {...first,displayName:"\u202E"}]){
    assert.equal((await s.flow.start(data)).status,"INVALID_INPUT");
  }
  assert.equal(s.pending.size,0);
  assert.equal((await scenario({mayStart:false}).flow.start(first)).status,"RATE_LIMITED");
});
test("wrong continuation token never creates account",async()=>{
  const s=scenario(),start=await s.flow.start(first);
  await s.flow.verify({challengeId:start.challengeId,code:s.sent[0].code});
  const result=await s.flow.complete({
    challengeId:start.challengeId,continuationToken:"fake",
    password:"UnaClave-MuySegura-yUnica-2026!",termsVersion:"terms-2026-11",
    privacyVersion:"privacy-2026-11",
  });
  assert.equal(result.status,"INVALID_OR_EXPIRED_REGISTRATION");
});
