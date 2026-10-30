/**
 * Offline operator-only keyring generator; run OUTSIDE the repository.
 * The private key is written to a new 0600 file, never stdout or commits.
 * Supports a single active key; add the previous key during overlap by an
 * offline, reviewed edit of the protected keyring.
 */
import { generateKeyPairSync,createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { resolve,sep } from "node:path";
if(process.argv.length!==3 || !process.argv[2].startsWith("/")) {
  process.stderr.write("Usage: node scripts/v2-hpke-keygen.mjs /absolute/secure/path/keyring.json\n");
  process.exit(2);
}
const destination=resolve(process.argv[2]);
const repo=resolve(process.cwd());
if(destination===repo || destination.startsWith(repo+sep)) {
  process.stderr.write("Refusing to write private key inside repository\n");process.exit(2);
}
process.umask(0o077);
const pair=generateKeyPairSync("x25519");
const publicKey=pair.publicKey.export({format:"jwk"}).x;
const privateKey=pair.privateKey.export({format:"jwk"}).d;
const raw=Buffer.from(publicKey,"base64url");
const kid=createHash("sha256").update(raw).digest().subarray(0,8).toString("hex");
writeFileSync(destination,JSON.stringify([{publicKey,privateKey}])+"\n",{mode:0o600,flag:"wx"});
process.stdout.write("Public Android pin only: "+kid+":"+publicKey+"\n");
process.stdout.write("Protected keyring written outside repo. Never commit it.\n");
