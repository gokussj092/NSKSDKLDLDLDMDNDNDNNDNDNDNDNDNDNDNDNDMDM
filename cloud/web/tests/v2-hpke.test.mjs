// Cryptographic regression scaffolding; do not execute on this feature branch.
import {strict as assert} from "node:assert";
import {test} from "node:test";
import {hpkeServerKey,openRequest} from "../lib/v2-hpke.mjs";
test("requires configured canonical private key",()=>{
 assert.throws(()=>hpkeServerKey({}),/KEY_MISSING/);
 assert.throws(()=>hpkeServerKey({CLOUD_V2_HPKE_PRIVATE_KEY:"wrong"}),/KEY_MISSING/);
});
test("rejects invalid ciphertext framing",()=>{
 const key=hpkeServerKey({CLOUD_V2_HPKE_PRIVATE_KEY:Buffer.alloc(32,7).toString("base64url")});
 assert.equal(key.publicKey.length,43);
 assert.throws(()=>openRequest(Buffer.from("plaintext"),key,{}),/HPKE_ENVELOPE/);
});
