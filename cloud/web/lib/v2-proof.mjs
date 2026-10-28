import { createHash, createPublicKey, verify } from "node:crypto";
export const sha256 = value => createHash("sha256").update(value).digest("hex");
export function publicKey(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{120,128}$/.test(value)) return null;
  try {
    const der=Buffer.from(value,"base64url");
    if(der.toString("base64url")!==value)return null;
    const key=createPublicKey({key:der,format:"der",type:"spki"});
    return key.asymmetricKeyType==="ec" && key.asymmetricKeyDetails?.namedCurve==="prime256v1" &&
      key.export({format:"der",type:"spki"}).equals(der) ? key : null;
  } catch {return null;}
}
export function integrityNonce(nonce, challengeId, encodedKey) {
  return createHash("sha256").update(["SPDECODE-KEY-V2",nonce,challengeId,encodedKey].join("\n")).digest("base64url");
}
export function proofMessage(operation,version,timestamp,nonce,bearer,bytes) {
  return ["SPDECODE-POP-V2","POST",String(operation),version,timestamp,nonce,sha256(bearer),sha256(bytes)].join("\n");
}
export function verifyProof(request,operation,bytes,bearer,encodedKey,now=Date.now()) {
  const timestamp=request.headers.get("x-sp-timestamp")||"",nonce=request.headers.get("x-sp-nonce")||"";
  const signature=request.headers.get("x-sp-proof")||"",version=request.headers.get("x-spdecode-app-version")||"";
  if(!/^[1-9][0-9]{9,10}$/.test(timestamp) || Math.abs(now-Number(timestamp)*1000)>30000 ||
     !/^[A-Za-z0-9_-]{32}$/.test(nonce) || !/^[A-Za-z0-9_-]{90,100}$/.test(signature) ||
     !/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(version))return null;
  const key=publicKey(encodedKey);if(!key)return null;
  try {
    const raw=Buffer.from(signature,"base64url");
    if(raw.toString("base64url")!==signature || !verify("sha256",
      Buffer.from(proofMessage(operation,version,timestamp,nonce,bearer,bytes)),key,raw))return null;
    return nonce;
  } catch {return null;}
}
