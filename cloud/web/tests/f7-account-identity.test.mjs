import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import {
  accountPolicy, normalizeHandle, normalizeEmail, normalizeDisplayName,
  hashPassword, verifyPassword, issueEmailChallenge, verifyEmailChallenge,
  generateContinuation, verifyContinuation,
} from "../lib/f7-account-identity.mjs";

const key = () => randomBytes(32);

test("account module is disabled by default, separate from C6 admin login",()=>{
  assert.equal(accountPolicy.publicRegistrationEnabled,false);
  assert.equal(accountPolicy.emailOtpMaxAttempts,5);
  assert.equal(accountPolicy.emailOtpTtlSeconds,600);
});
test("usernames are casefolded, unique-ready, and reserved names rejected",()=>{
  assert.equal(normalizeHandle("Ghost_DEV"),"ghost_dev");
  assert.equal(normalizeHandle("Ｇｈｏｓｔ"),"ghost");
  for(const bad of ["admin","Support","spdecode","2ghost","a","a ".repeat(12),"my user","@foo","undefined","root"])
    assert.equal(normalizeHandle(bad),null);
});
test("email canonicalization does not trust unverified free-form values",()=>{
  assert.equal(normalizeEmail("Example+test@EXAMPLE.COM"),"example+test@example.com");
  assert.equal(normalizeEmail("x@bücher.de"),"x@xn--bcher-kva.de");
  for(const bad of ["x", "a@invalid", "a@.com", "a@a..com", "a@@b.com", " a@b.com",
                    "a@b.com\n", "", null, "a@-bad.com"])
    assert.equal(normalizeEmail(bad),null);
});
test("display names support Unicode without bidirectional control spoofing",()=>{
  assert.equal(normalizeDisplayName("  María Gómez  "),"María Gómez");
  for(const bad of ["", "   ", "hi\u202eexe", "a".repeat(81), "a\nb"])
    assert.equal(normalizeDisplayName(bad),null);
});
test("password is stored only as a salted scrypt hash, never plaintext",async()=>{
  const password="GranClaveSegura-unica-2026!";
  const a=await hashPassword(password),b=await hashPassword(password);
  assert.match(a,/^scrypt\$32768\$8\$2\$[0-9a-f]{48}\$[0-9a-f]{128}$/);
  assert.notEqual(a,b);
  assert(!a.includes(password));
  assert.equal(await verifyPassword(password,a),true);
  assert.equal(await verifyPassword("GranClaveSegura-diferente-2026!",a),false);
});
test("malformed or weakened password hashes are rejected",async()=>{
  for(const hash of ["","sha256$abcdef","scrypt$16384$8$1$foo$bar",
                     "scrypt$32768$8$2$"+"a".repeat(48)+"$"+"g".repeat(128),null])
    assert.equal(await verifyPassword("GranClaveSegura-unica-2026!",hash),false);
  for(const pass of ["a".repeat(11),"hello\nworld1234567","a".repeat(257)])
    await assert.rejects(()=>hashPassword(pass),/INVALID_PASSWORD_POLICY/);
});
test("email verification uses one-time six-digit HMAC OTP not stored plaintext",()=>{
  const k=key(),now=1773000000000;
  const {code,record}=issueEmailChallenge("User@EXAMPLE.COM",k,now);
  assert.match(code,/^\d{6}$/);
  assert(!JSON.stringify(record).includes(code));
  assert.equal(record.email,"user@example.com");
  assert.equal(verifyEmailChallenge(record,code,k,now+30_000),true);
  assert.equal(verifyEmailChallenge(record,"not-code",k,now+30_000),false);
  assert.equal(verifyEmailChallenge(record,code,key(),now+30_000),false);
  assert.equal(verifyEmailChallenge({...record,email:"other@example.com"},code,k,now),false);
});
test("OTP expires and cannot be reused or brute-forced after five attempts",()=>{
  const k=key(),now=1773000000000;
  const {code,record}=issueEmailChallenge("user@example.com",k,now);
  assert.equal(verifyEmailChallenge(record,code,k,now+600_000),false);
  assert.equal(verifyEmailChallenge({...record,attempts:5},code,k,now),false);
  assert.equal(verifyEmailChallenge({...record,consumedAt:now},code,k,now),false);
  assert.equal(verifyEmailChallenge({...record,verifiedAt:now},code,k,now),false);
});
test("continuation tokens are opaque and stored only as digests",()=>{
  const first=generateContinuation(),second=generateContinuation();
  assert.notEqual(first.token,second.token);
  assert(!first.tokenDigest.includes(first.token));
  assert.equal(verifyContinuation(first.token,first.tokenDigest),true);
  assert.equal(verifyContinuation(second.token,first.tokenDigest),false);
  assert.equal(verifyContinuation("bad",first.tokenDigest),false);
  assert.equal(verifyContinuation(first.token,"bad"),false);
});
