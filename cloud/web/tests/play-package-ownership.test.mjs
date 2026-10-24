import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync,existsSync} from "node:fs";
const read=path=>readFileSync(new URL("../../../"+path,import.meta.url),"utf8");
test("Google Play package registration proof is a private CI-only asset",()=>{
 const gradle=read("android/app/build.gradle.kts");
 const actions=read(".github/workflows/play-beta-artifacts.yml");
 assert.match(gradle,/SPDECODE_ADI_VERIFICATION_BUILD/);
 assert.match(gradle,/src\/main\/assets\/adi-registration\.properties/);
 assert.match(actions,/secrets\.SPDECODE_ADI_REGISTRATION_TOKEN/);
 assert.match(actions,/SP-DECODE-PLAY-PACKAGE-OWNERSHIP-VERIFICATION/);
 assert.match(actions,/assets\/adi-registration\.properties/);
 assert.match(actions,/SPDECODE_ADI_VERIFICATION_BUILD: "true"/);
 assert.match(actions,/apksigner/);
 assert.ok(actions.indexOf("Publish artifacts only to the private workflow run")<
           actions.indexOf("Prepare optional private package-name ownership verification"));
 assert.ok(!existsSync(new URL("../../../android/app/src/main/assets/adi-registration.properties",import.meta.url)));
 assert.doesNotMatch(actions,/DC4TBESV3MLZE/);
});
