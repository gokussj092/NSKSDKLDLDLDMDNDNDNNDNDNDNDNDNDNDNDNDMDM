import test from "node:test";
import assert from "node:assert/strict";
import {formatSecurityEmail} from "../lib/f7-account-email.mjs";

test("registration and recovery verification messages contain correct OTP and TTL",()=>{
  for(const type of ["verify_email","password_reset"]){
    const es=formatSecurityEmail({type,name:"María",code:"012345",locale:"es"});
    assert.match(es.text,/012345/);
    assert.match(es.text,/10 minutos/);
    assert.equal(es.senderConfigured,false);
    assert.equal(es.marketing,false);
    assert.equal(es.hasAttachments,false);
    assert.equal(es.format,"text/plain; charset=utf-8");
    const en=formatSecurityEmail({type,name:"Jo",code:"012345",locale:"en"});
    assert.match(en.text,/10 minutes/);
    assert.match(en.text,/012345/);
  }
});
test("sign-in, password and email change alerts never disclose credentials",()=>{
  for(const type of ["new_signin","password_changed","email_changed"]){
    const msg=formatSecurityEmail({type,name:"Usuario",when:new Date("2026-11-06T00:00:00Z")});
    assert.match(msg.text,/soporte@spdecode\.xyz/);
    assert.match(msg.text,/2026-11-06T00:00:00\.000Z/);
    assert(!msg.text.includes("012345"));
    assert.equal(msg.hasAttachments,false);
  }
});
test("unexpected code or type is rejected instead of logged or rendered",()=>{
  assert.throws(()=>formatSecurityEmail({type:"verify_email",code:"123"}),/INVALID_CODE/);
  assert.throws(()=>formatSecurityEmail({type:"verify_email",code:"123456\n"}),/INVALID_CODE/);
  assert.throws(()=>formatSecurityEmail({type:"new_signin",code:"123456"}),/CODE_NOT_ALLOWED/);
  assert.throws(()=>formatSecurityEmail({type:"unknown"}),/UNKNOWN_SECURITY_EVENT/);
  assert.throws(()=>formatSecurityEmail({type:"new_signin",locale:"xx"}),/UNSUPPORTED_LOCALE/);
});
test("untrusted display name is not placed as a header or HTML",()=>{
  const msg=formatSecurityEmail({type:"new_signin",name:"admin\nBcc: attacker@example.org"});
  assert(!msg.text.includes("Bcc:"));
  assert.equal(msg.subject,"SP-DECODE — Nuevo inicio de sesión");
});
