import assert from "node:assert/strict";
import {test} from "node:test";
import {CREDENTIAL_PROMPTS_HEADER,legacyCredentialError,supportsCredentialPrompts} from "../lib/decoder-client-compat.mjs";

const request=(feature)=>new Request("https://example.invalid",{
  headers:feature===undefined?{}:{[CREDENTIAL_PROMPTS_HEADER]:feature}
});
test("old APKs lack capability, new APKs explicitly negotiate it",()=>{
  assert.equal(supportsCredentialPrompts(request()),false);
  assert.equal(supportsCredentialPrompts(request("1")),true);
  assert.equal(supportsCredentialPrompts(request("0")),false);
  assert.equal(supportsCredentialPrompts(request("yes")),false);
});
test("legacy NPVS protected files use an existing localized code, not an impossible prompt",()=>{
  for(const code of ["PASSWORD_REQUIRED","AUTH_FAILED"]){
    assert.equal(legacyCredentialError(request(),"file",{format:"npvs"},code),"NPVS_PROTECTION_UNSUPPORTED");
    assert.equal(legacyCredentialError(request("1"),"file",{format:"npvs"},code),null);
  }
});
test("legacy 1FTunnel and Tunneltweak cannot enter new file passwords",()=>{
  for(const format of ["1ftnl","tut"]){
    assert.equal(legacyCredentialError(request(),"file",{format},"PASSWORD_REQUIRED"),"UNSUPPORTED_FORMAT");
    assert.equal(legacyCredentialError(request("1"),"file",{format},"PASSWORD_REQUIRED"),null);
  }
});
test("five NPV text schemes and 1FTunnel texts are handled without a new UI on old APKs",()=>{
  for(const prefix of ["npvt://","npvt-ssh://","npvt-vless://","npvt-vmess://","npv://",
                       "1FTnl.","1FT1.","1ftunnel://1FTnl/","1ftunnel://1FT1/"]){
    assert.equal(legacyCredentialError(request(),"text",{text:prefix+"payload"},"PASSWORD_REQUIRED"),"UNSUPPORTED_FORMAT");
    assert.equal(legacyCredentialError(request("1"),"text",{text:prefix+"payload"},"PASSWORD_REQUIRED"),null);
  }
});
test("HC/UA, unprotected files, tampering and network errors never get masked",()=>{
  for(const format of ["hc","ua","ehi","tls"]){
    for(const code of ["PASSWORD_REQUIRED","AUTH_FAILED","PRIVATE_KEY_REQUIRED","ENGINE_TIMEOUT","DECODE_FAILED"])
      assert.equal(legacyCredentialError(request(),"file",{format},code),null);
  }
  for(const code of ["PRIVATE_KEY_REQUIRED","RECIPIENT_MISMATCH","NPVS_PROTECTION_UNSUPPORTED","DECODE_FAILED","ENGINE_TIMEOUT"])
    assert.equal(legacyCredentialError(request(),"file",{format:"npvs"},code),null);
  assert.equal(legacyCredentialError(request(),"text",{text:"ua://payload"},"PASSWORD_REQUIRED"),null);
  assert.equal(legacyCredentialError(request(),"text",{text:"dns://payload"},"PASSWORD_REQUIRED"),null);
  assert.equal(legacyCredentialError(request(),"file",{format:"npvs"},""),null);
});
