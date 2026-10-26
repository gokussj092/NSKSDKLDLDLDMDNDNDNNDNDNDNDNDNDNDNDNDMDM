/**
 * C3.5 remote provider broker. Public requests provide a reference or an
 * explicit action, NEVER an arbitrary fetch destination or request headers.
 * DNS is checked and pinned to one approved public IPv4 for each TLS request.
 */
import https from "node:https";
import dns from "node:dns/promises";
import net from "node:net";
import {
  createCipheriv, createDecipheriv, createHash, createHmac,
  randomUUID, timingSafeEqual,
} from "node:crypto";
import { inflateSync, deflateSync } from "node:zlib";

export const EHI_ENDPOINT = "https://www.ehi.tools/httpinjector/import_config";
export const NUR_ALLOWED_HOST = "strongteam.co";
export const EHI_ALLOWED_HOST = "www.ehi.tools";
export const MNR_ALLOWED_HOST = "firebasestorage.googleapis.com";
export const HC_HOST = "cloudvpn.mrfrankofc.com";
export const HC_SHORT_HOST = "link.playsmarty.uk";
export const MNR_BUCKET = "hamovpn.firebasestorage.app";
const EHI_BUILD = "244";
const MAX_REMOTE_BYTES = 8 * 1024 * 1024;
const MAX_NUR_BYTES = 16 * 1024 * 1024; // matches NUR_TUNNEL_SERVERS.py MAX_INPUT
const NUR_TIMEOUT_MS = 30000; // matches the proven standalone client
const NUR_REDIRECT_LIMIT = 3; // only the same approved HTTPS origin
const MAX_UNCOMPRESSED_BYTES = 8 * 1024 * 1024;
const CONNECT_TIMEOUT_MS = 10000;
const EMOJI_START = 0x1f489;
const EMOJI_END = 0x1f680;
const EMOJI_OFFSET = 128467;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const KEY = /^[A-Za-z0-9_]{1,128}$/;
const ERRORS = Object.freeze({
  INVALID_REFERENCE: 400,
  USER_CONSENT_REQUIRED: 400,
  REMOTE_NOT_CONFIGURED: 503,
  REMOTE_NETWORK_DENIED: 502,
  REMOTE_PROVIDER_UNAVAILABLE: 502,
  REMOTE_CONFIG_UNAVAILABLE: 410, // remote link consumed, expired or removed
  REMOTE_RESPONSE_INVALID: 502,
  REMOTE_INTEGRITY_FAILED: 422,
  REMOTE_TOO_LARGE: 413,
  REMOTE_DECODER_FAILED: 422,
});

export class ExternalImportError extends Error {
  constructor(code, reason="") {
    super(code);
    this.name = "ExternalImportError";
    this.code = Object.hasOwn(ERRORS, code) ? code : "REMOTE_PROVIDER_UNAVAILABLE";
    this.status = ERRORS[this.code];
    // Sanitized diagnostics for root-only 'spdecode qa probe-nur'; not included
    // in the public API response. NEVER retain URLs, headers or response bodies.
    this.reason = /^HTTP_[1-5][0-9]{2}$/.test(reason) ||
      ["DNS","TLS","TIMEOUT","CONNECTION","CONNECTION_RESET","CONNECTION_REFUSED","NETWORK_UNREACHABLE","REDIRECT_BLOCKED","REDIRECT_LIMIT"].includes(reason)
      ? reason : "";

  }
}
const fail = code => { throw new ExternalImportError(code); };
export const isExternalImportError = e => e instanceof ExternalImportError;

function strictBase64(encoded, max = MAX_REMOTE_BYTES) {
  if (typeof encoded !== "string" || !encoded || encoded.length > Math.ceil(max / 3) * 4 + 8 ||
      encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))
    fail("REMOTE_RESPONSE_INVALID");
  const data = Buffer.from(encoded, "base64");
  if (!data.length || data.length > max || data.toString("base64") !== encoded)
    fail("REMOTE_RESPONSE_INVALID");
  return data;
}

export function parseEhiReference(value) {
  if (typeof value !== "string" || value.length > 1024) fail("INVALID_REFERENCE");
  const input = value.trim().replace(/^\ufeff/, "");
  if (KEY.test(input)) return input;
  const match = /^(?:https|ehi):\/\/ehi\.link\/([A-Za-z0-9_]{1,128})$/.exec(input);
  if (match) return match[1];
  const symbols = [...input];
  if (symbols[0]?.codePointAt(0) !== EMOJI_START ||
      symbols.at(-1)?.codePointAt(0) !== EMOJI_END || symbols.length < 3)
    fail("INVALID_REFERENCE");
  let translated = "";
  for (const symbol of symbols.slice(1, -1)) {
    const ascii = symbol.codePointAt(0) - EMOJI_OFFSET;
    if (ascii < 0 || ascii > 127 || !ALPHABET.includes(String.fromCharCode(ascii)))
      fail("INVALID_REFERENCE");
    translated += String.fromCharCode(ascii);
  }
  let decoded;
  try { decoded = strictBase64(translated, 128).toString("utf8"); }
  catch { fail("INVALID_REFERENCE"); }
  if (!KEY.test(decoded)) fail("INVALID_REFERENCE");
  return decoded;
}

export function parseMnrReference(value) {
  if(typeof value!=="string" || value.length>64)fail("INVALID_REFERENCE");
  const match=/^(?:mnrtunneludp:\/\/)?([A-Za-z0-9]{10})$/.exec(value.trim());
  if(!match)fail("INVALID_REFERENCE");
  return match[1];
}
export function mnrReferenceUrl(value) {
  // Firebase StorageReference.child() collapses the doubled slash in ://.
  return "https://"+MNR_ALLOWED_HOST+"/v0/b/"+MNR_BUCKET+"/o/"+
    encodeURIComponent("mnrtunneludp:/"+parseMnrReference(value)+".sky");
}
export async function importMnrReference(value,options={}) {
  const id=parseMnrReference(value),url=mnrReferenceUrl(value);
  const fetcher=options.download || downloadApproved;
  let metadata;
  try{
    const raw=await fetcher({url,kind:"mnr",maxBytes:256*1024},options);
    if(!Buffer.isBuffer(raw)||!raw.length||raw.length>256*1024)fail("REMOTE_RESPONSE_INVALID");
    metadata=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(raw));
  }catch(error){if(isExternalImportError(error))throw error;fail("REMOTE_RESPONSE_INVALID");}
  if(!metadata || Array.isArray(metadata) || metadata.bucket!==MNR_BUCKET ||
     metadata.name!=="mnrtunneludp:/"+id+".sky" || typeof metadata.downloadTokens!=="string")
    fail("REMOTE_RESPONSE_INVALID");
  const token=metadata.downloadTokens.split(",")[0];
  if(!/^[A-Za-z0-9_-]{1,256}$/.test(token))fail("REMOTE_RESPONSE_INVALID");
  const data=await fetcher({url:url+"?alt=media&token="+token,kind:"mnr",maxBytes:MAX_REMOTE_BYTES},options);
  if(!Buffer.isBuffer(data)||!data.length||data.length>MAX_REMOTE_BYTES)fail("REMOTE_RESPONSE_INVALID");
  return data;
}

/** Public .hc hosting references, not HTTP Injector's signed cloud protocol. */
export function parseHttpCustomReference(value) {
  if(typeof value!=="string" || value.length>256)fail("INVALID_REFERENCE");
  const input=value.trim();
  const match=/^https:\/\/(cloudvpn\.mrfrankofc\.com|link\.playsmarty\.uk)\/([A-Za-z0-9_-]{1,64})$/.exec(input);
  if(!match || (match[1]===HC_HOST && !/^[A-Za-z0-9_-]{6}$/.test(match[2])))
    fail("INVALID_REFERENCE");
  return input;
}
export function isHttpCustomReference(value) {
  try{parseHttpCustomReference(value);return true;}catch{return false;}
}
export async function importHttpCustomReference(reference,options={}) {
  const url=parseHttpCustomReference(reference);
  const bytes=await (options.download||downloadApproved)({url,kind:"hc",maxBytes:MAX_REMOTE_BYTES},options);
  if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>MAX_REMOTE_BYTES)
    fail("REMOTE_RESPONSE_INVALID");
  // HTML is a landing/error page, never a downloadable HC payload. Do not
  // rewrite the bytes: Latin1/UTF-8 carriers are handled by the existing codec.
  if(/^\s*(?:<!doctype\s+html|<html[\s>])/i.test(bytes.subarray(0,512).toString("utf8")))
    fail("REMOTE_RESPONSE_INVALID");
  return bytes;
}

/* Only hardcoded vendor destinations are accepted. No user URLs, custom ports,
 * userinfo, IP literals or aliases. MNR media has one generated token query.
 */
export function approvedUrl(address, kind) {
  if(kind==="hc") {
    let result;
    try{result=parseHttpCustomReference(address);}catch{fail("REMOTE_NETWORK_DENIED");}
    if(result!==address)fail("REMOTE_NETWORK_DENIED");
    return new URL(result);
  }
  const expectedHost = kind === "ehi" ? EHI_ALLOWED_HOST : kind === "nur" ? NUR_ALLOWED_HOST : kind === "mnr" ? MNR_ALLOWED_HOST : "";
  if (typeof address !== "string" || address.length > 2048 || !expectedHost)
    fail("REMOTE_NETWORK_DENIED");
  let parsed;
  try { parsed = new URL(address); } catch { fail("REMOTE_NETWORK_DENIED"); }
  if (parsed.protocol !== "https:" || parsed.hostname !== expectedHost ||
      parsed.port || parsed.username || parsed.password || (kind!=="mnr" && parsed.search) || parsed.hash ||
      parsed.pathname.length > 256 || parsed.href !== address ||
      (kind === "ehi" && parsed.href !== EHI_ENDPOINT))
    fail("REMOTE_NETWORK_DENIED");
  if(kind==="mnr" && (!/^\/v0\/b\/hamovpn\.firebasestorage\.app\/o\/mnrtunneludp%3A%2F[A-Za-z0-9]{10}\.sky$/.test(parsed.pathname) ||
      (parsed.search!=="" && !/^\?alt=media&token=[A-Za-z0-9_-]{1,256}$/.test(parsed.search))))fail("REMOTE_NETWORK_DENIED");
  return parsed;
}

/** Refuse non-public, private, documentation, benchmark and reserved IPv4.
 * IPv6-only hosts fail closed in C3.5; no DNS rebinding between check/TLS.
 */
export function publicIpv4(address) {
  if (net.isIP(address) !== 4) return false;
  const parts = address.split(".").map(Number);
  const [a,b,c] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || b === 0 && c === 0 || b === 0 && c === 2 ||
      b === 88 && c === 99)) return false;
  if (a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  return true;
}

export async function pinnedAddresses(host, resolver = dns.lookup) {
  // The only legal hosts come from approvedUrl; never accept raw user host.
  if (![EHI_ALLOWED_HOST, NUR_ALLOWED_HOST, MNR_ALLOWED_HOST, HC_HOST, HC_SHORT_HOST].includes(host)) fail("REMOTE_NETWORK_DENIED");
  let answers;
  try { answers = await resolver(host, {all:true, family:4, verbatim:true}); }
  catch { fail("REMOTE_NETWORK_DENIED"); }
  if (!Array.isArray(answers) || !answers.length || answers.length > 32 ||
      answers.some(r => r.family !== 4 || !publicIpv4(r.address)))
    fail("REMOTE_NETWORK_DENIED");
  return answers.map(r => r.address);
}

/** Private broker: validated DNS and TLS are pinned per HTTPS hop. NUR
 * follows only bounded SAME-host redirects; HC follows its two-host allowlist.
 * Unlike Python urllib's broader
 * automatic redirect handling; EHI rejects all redirects as before.
 */
export async function downloadApproved({url,kind,method="GET",body,headers={},maxBytes=MAX_REMOTE_BYTES},
    {resolve = dns.lookup, request = https.request} = {}) {
  const initial=approvedUrl(url,kind);
  const upperLimit=kind==="nur" ? MAX_NUR_BYTES : MAX_REMOTE_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes<1 || maxBytes>upperLimit ||
      (!["GET","POST"].includes(method) || kind==="hc" && (method!=="GET" || body!==undefined)))
    fail("REMOTE_NETWORK_DENIED");

  const timeout=kind==="nur" ? NUR_TIMEOUT_MS : CONNECT_TIMEOUT_MS;
  const deadline=Date.now()+timeout+5000;
  const visited=new Set();

  const reasonFromError=error=>{
    if(error?.name==="AbortError" || ["ETIMEDOUT","ESOCKETTIMEDOUT"].includes(error?.code))
      return "TIMEOUT";
    if(["ENOTFOUND","EAI_AGAIN"].includes(error?.code))return "DNS";
    if(["ECONNRESET","EPIPE"].includes(error?.code))return "CONNECTION_RESET";
    if(error?.code==="ECONNREFUSED")return "CONNECTION_REFUSED";
    if(["ENETUNREACH","EHOSTUNREACH"].includes(error?.code))return "NETWORK_UNREACHABLE";
    if(typeof error?.code==="string" &&
       (/^ERR_TLS_/.test(error.code) || /CERT|SSL/.test(error.code)))return "TLS";
    return "CONNECTION";
  };
  const failTransport=(code,reason)=>{throw new ExternalImportError(code,reason);};
  let address=initial.href;
  for(let hops=0;hops<=NUR_REDIRECT_LIMIT;hops++){
    if(visited.has(address))failTransport("REMOTE_PROVIDER_UNAVAILABLE","REDIRECT_LIMIT");
    visited.add(address);
    const destination=approvedUrl(address,kind);
    // DNS re-checked on every redirect and bound to the same HTTPS socket.
    const resolved=await pinnedAddresses(destination.hostname,resolve);
    // Python urllib tries the next resolved address after a socket failure.
    // Retry NUR only, across independently validated public IPv4s, never on
    // HTTP errors or TLS certificate failures. Keep one global deadline.
    let result;
    const addresses=kind==="nur"?resolved.slice(0,8):resolved.slice(0,1);
    for(let index=0;index<addresses.length;index++){
      const selected=addresses[index];
      const timeLeft=deadline-Date.now();
      if(timeLeft<=0)failTransport("REMOTE_PROVIDER_UNAVAILABLE","TIMEOUT");
      try{
        result=await new Promise((resolvePromise,rejectPromise)=>{
      let settled=false,req;
      const accept=value=>{
        if(settled)return;
        settled=true;clearTimeout(timer);
        resolvePromise(value);
      };
      const reject=(code,reason)=>{
        if(settled)return;
        settled=true;clearTimeout(timer);
        rejectPromise(new ExternalImportError(code,reason));
      };
      const controller=new AbortController();
      const timer=setTimeout(()=>{
        reject("REMOTE_PROVIDER_UNAVAILABLE","TIMEOUT");
        req?.destroy();
        controller.abort();
      },Math.min(timeout+1000,timeLeft));
      const options={
        method, signal:controller.signal,agent:false,rejectUnauthorized:true,
        minVersion:"TLSv1.2",timeout:Math.min(timeout,timeLeft),
        headers:{...headers,"Accept-Encoding":"identity","Connection":"close"},
        lookup:(host,opts,callback)=>{
          if(host!==destination.hostname)return callback(new Error("hostname mismatch"));
          // Node 22's autoSelectFamily calls lookup({all:true}) and REQUIRES
          // an array of {address,family}. A scalar silently fails with
          // ERR_INVALID_IP_ADDRESS before the HTTPS connection is attempted.
          if(opts?.all===true)return callback(null,[{address:selected,family:4}]);
          callback(null,selected,4);
        },
      };
      try{
        req=request(destination,options,res=>{
          const status=res.statusCode;
          if(status!==200){
            res.destroy();
            if(["nur","hc"].includes(kind) && method==="GET" &&
                [301,302,303,307,308].includes(status)){
              let next;
              try{
                const target=res.headers.location;
                if(typeof target!=="string" || target.length>2048)
                  throw new Error("missing redirect");
                next=new URL(target,destination);
                approvedUrl(next.href,kind);
                // NUR stays same-host; HC can cross only to its other fixed reference host.
                if(kind==="nur" && next.hostname!==initial.hostname)
                  throw new Error("cross-host redirect denied");
              }catch{
                return reject("REMOTE_NETWORK_DENIED","REDIRECT_BLOCKED");
              }
              return accept({redirect:next.href});
            }
            if(["ehi","mnr","hc"].includes(kind) && [404,410].includes(status))
              return reject("REMOTE_CONFIG_UNAVAILABLE");
            return reject("REMOTE_PROVIDER_UNAVAILABLE","HTTP_"+String(status));
          }
          if(kind==="hc" && /^(?:text\/html|application\/xhtml\+xml)(?:;|$)/i.test(String(res.headers["content-type"]||""))){
            res.destroy();return reject("REMOTE_RESPONSE_INVALID");
          }
          const encoding=res.headers["content-encoding"];
          if(encoding && encoding!=="identity"){
            res.destroy();return reject("REMOTE_RESPONSE_INVALID");
          }
          const announced=res.headers["content-length"];
          if(announced!==undefined && (!/^\d+$/.test(String(announced)) ||
              Number(announced)>maxBytes)){
            res.destroy();return reject("REMOTE_TOO_LARGE");
          }
          let size=0;
          const chunks=[];
          res.on("data",chunk=>{
            if(settled)return;
            size+=chunk.length;
            if(size>maxBytes){
              res.destroy();req.destroy();
              return reject("REMOTE_TOO_LARGE");
            }
            chunks.push(chunk);
          });
          res.on("end",()=>{
            if(settled)return;
            if(!size)return reject("REMOTE_RESPONSE_INVALID");
            accept({data:Buffer.concat(chunks,size)});
          });
          res.on("error",error=>reject("REMOTE_PROVIDER_UNAVAILABLE",reasonFromError(error)));
          res.on("aborted",()=>reject("REMOTE_PROVIDER_UNAVAILABLE","CONNECTION"));
        });
        req.on("timeout",()=>{req.destroy();reject("REMOTE_PROVIDER_UNAVAILABLE","TIMEOUT");});
        req.on("error",error=>reject("REMOTE_PROVIDER_UNAVAILABLE",reasonFromError(error)));
        if(body!==undefined)req.write(body);
        req.end();
      }catch(error){
        reject("REMOTE_PROVIDER_UNAVAILABLE",reasonFromError(error));
      }
        });
        break;
      }catch(error){
        const retryable=error instanceof ExternalImportError &&
          error.code==="REMOTE_PROVIDER_UNAVAILABLE" &&
          ["CONNECTION","CONNECTION_RESET","CONNECTION_REFUSED",
           "NETWORK_UNREACHABLE","TIMEOUT"].includes(error.reason);
        if(!retryable || index===addresses.length-1 || Date.now()>=deadline)
          throw error;
      }
    }
    if(result.data)return result.data;
    if(!result.redirect || !["nur","hc"].includes(kind) || hops===NUR_REDIRECT_LIMIT)
      failTransport("REMOTE_PROVIDER_UNAVAILABLE","REDIRECT_LIMIT");
    address=result.redirect;
  }
  failTransport("REMOTE_PROVIDER_UNAVAILABLE","REDIRECT_LIMIT");
}

// Android Java URLEncoder encodes ~ and punctuation and replaces '+' with %2B.
const formEncode = v => encodeURIComponent(String(v)).replace(/[!'()*~]/g,c=>
  "%"+c.charCodeAt(0).toString(16).toUpperCase());
const shaUpper = (name,text) => createHash(name).update(text,"utf8").digest("hex").toUpperCase();
export function buildEhiRequest(key,{signKey,now=Math.floor(Date.now()/1000),nonce=randomUUID(),identity=randomUUID()}={}) {
  if (!KEY.test(key)) fail("INVALID_REFERENCE");
  if (typeof signKey !== "string" || signKey.length !== 32 ||
      !Number.isSafeInteger(now) || now < 1 ||
      !/^[0-9a-f-]{36}$/.test(nonce))
    fail("REMOTE_NOT_CONFIGURED");
  const headers={
    "x-nonce":nonce,"x-timestamp":String(now),"x-sign-version":"1.0",
    "x-uid":shaUpper("sha1",identity),"x-did":shaUpper("md5",identity),
    "x-platform":"android","x-device":"Android","x-os-api":"35",
    "x-app-build":EHI_BUILD,
  };
  const entries=Object.entries({...headers,config_key:key})
    .sort(([a],[b])=>a<b?-1:a>b?1:0);
  const canonical=entries.map(([k,v])=>k+"="+v).join("&");
  const message=["POST",EHI_ENDPOINT,canonical].map(formEncode).join("&");
  headers["x-signature"]=formEncode(createHmac("sha1",Buffer.from(formEncode("-1")+"&"+formEncode(signKey),"utf8"))
    .update(message,"utf8").digest("base64"));
  return {
    url:EHI_ENDPOINT,method:"POST",
    headers:{...headers,"Content-Type":"application/x-www-form-urlencoded",
      "Accept":"application/json","User-Agent":"okhttp/4.12.0"},
    body:Buffer.from("config_key="+key,"ascii"),
  };
}
export function unwrapEhiResponse(source,{responseKey}) {
  if (!Buffer.isBuffer(source) || source.length>MAX_REMOTE_BYTES)
    fail("REMOTE_RESPONSE_INVALID");
  let doc;
  try {doc=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(source));}
  catch {fail("REMOTE_RESPONSE_INVALID");}
  // The vendor responded at the application level: the reference may be
  // expired, already consumed or removed. Not a decoding engine failure.
  if (!doc || doc.code!==200) fail("REMOTE_CONFIG_UNAVAILABLE");
  const envelope=strictBase64(doc.data);
  if (envelope.length<64 || (envelope.length-48)%16 !== 0)
    fail("REMOTE_RESPONSE_INVALID");
  if (typeof responseKey !== "string" || Buffer.byteLength(responseKey,"utf8")!==32)
    fail("REMOTE_NOT_CONFIGURED");
  const shared=Buffer.from(responseKey,"utf8");
  const iv=envelope.subarray(0,16), mac=envelope.subarray(16,48), encrypted=envelope.subarray(48);
  const computed=createHmac("sha256",shared).update(encrypted).digest();
  if (computed.length!==mac.length || !timingSafeEqual(computed,mac))
    fail("REMOTE_INTEGRITY_FAILED");
  let inflated;
  try {
    const cipher=createDecipheriv("aes-256-cbc",shared,iv);
    const compressed=Buffer.concat([cipher.update(encrypted),cipher.final()]);
    inflated=inflateSync(compressed,{maxOutputLength:MAX_UNCOMPRESSED_BYTES});
  } catch {fail("REMOTE_INTEGRITY_FAILED");}
  let clear;
  try {clear=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(inflated));}
  catch {fail("REMOTE_RESPONSE_INVALID");}
  if (!clear || clear.status!=="success") fail("REMOTE_CONFIG_UNAVAILABLE");
  const ciphertext=strictBase64(clear.config_data);
  if (ciphertext.length % 16!==0) fail("REMOTE_DECODER_FAILED");
  // Same Java DataOutputStream binary format as Android's temporary EHI envelope.
  const wrapped=Buffer.alloc(2+3+8+2+3+8+4+8+ciphertext.length);
  let offset=0;
  wrapped.writeUInt16BE(3,offset);offset+=2;wrapped.write("ehi",offset,"ascii");offset+=3;
  offset+=8;wrapped.writeUInt16BE(3,offset);offset+=2;wrapped.write(EHI_BUILD,offset,"ascii");offset+=3;
  offset+=8;wrapped.writeUInt32BE(ciphertext.length,offset);offset+=4;
  offset+=8;ciphertext.copy(wrapped,offset);
  return wrapped; // never return the encrypted envelope or secrets to Android
}

export function nurConfigured(env=process.env) {
  try {
    if (env.CLOUD_NUR_FETCH_ENABLED!=="true") return false;
    approvedUrl(env.CLOUD_NUR_CATALOG_URL,"nur");
    return true;
  } catch {return false;}
}
export function ehiConfigured(env=process.env) {
  return env.CLOUD_EHI_IMPORT_ENABLED==="true" &&
    typeof env.CLOUD_EHI_SIGN_KEY==="string" &&
    env.CLOUD_EHI_SIGN_KEY.length===32 &&
    typeof env.CLOUD_EHI_RESPONSE_KEY==="string" &&
    Buffer.byteLength(env.CLOUD_EHI_RESPONSE_KEY,"utf8")===32;
}
export async function importEhiReference(reference,{env=process.env,transport=downloadApproved}={}) {
  const key=parseEhiReference(reference); // no network before validation
  if (!ehiConfigured(env)) fail("REMOTE_NOT_CONFIGURED");
  const request=buildEhiRequest(key,{signKey:env.CLOUD_EHI_SIGN_KEY});
  const raw=await transport({...request,kind:"ehi",maxBytes:MAX_REMOTE_BYTES});
  return unwrapEhiResponse(raw,{responseKey:env.CLOUD_EHI_RESPONSE_KEY});
}
export async function downloadNur({env=process.env,transport=downloadApproved}={}) {
  if (!nurConfigured(env)) fail("REMOTE_NOT_CONFIGURED");
  const raw=await transport({
    url:env.CLOUD_NUR_CATALOG_URL,kind:"nur",method:"GET",
    // Match NUR_TUNNEL_SERVERS.py: urllib has only these two outbound headers.
    headers:{"User-Agent":"NUR TUNNEL VPN","Accept-Encoding":"identity"},
    maxBytes:MAX_NUR_BYTES,
  });
  if (!Buffer.isBuffer(raw) || !raw.length || raw.length>MAX_NUR_BYTES)
    fail("REMOTE_RESPONSE_INVALID");
  return raw;
}
