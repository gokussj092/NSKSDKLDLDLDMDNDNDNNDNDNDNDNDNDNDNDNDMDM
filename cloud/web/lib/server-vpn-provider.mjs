/**
 * C8 public VPN catalog broker. Fixed approved providers ONLY.
 * DNS is revalidated, every HTTPS connection is bound to one vetted IPv4,
 * redirects are constrained to the original HTTPS origin, and only temporary
 * socket errors may retry on another validated IP (NUR C3.5 policy).
 */
import dns from "node:dns/promises";
import https from "node:https";
import {publicIpv4} from "./c35-provider.mjs";

const PROVIDERS = Object.freeze({
  "24clan-green": {
    url:"https://24clanvpn.com/updater/6d5d4a5fb3d053300c1a89f85dbf05",
    agent:"24clan VPN Green/3.3",
  },
  "hx-tunnel": {
    url:"https://ctxrelay.online/updater/e7aa9907021632c39b0e0573e11861",
    agent:"HX Tunnel VPN/Hx-Build14",
  },
  "mkk-hyper": {
    url:"https://f005.backblazeb2.com/file/mkkhyper/api_server.json",
    agent:"MKK Hyper VPN/2.9.2",
  },
  "my-tunnel-proxy": {
    url:"https://mfmpro.xyz/api/app?json=3c9a2a29f3a4180271da",
    agent:"My Tunnel Proxy/2.3",
  },
});
const MAX_BYTES=8*1024*1024;
const DEADLINE_MS=30000;
const CONNECT_MS=10000;
const RETRY_CODES=new Set(["ECONNRESET","ETIMEDOUT","ESOCKETTIMEDOUT","ECONNREFUSED","EHOSTUNREACH","ENETUNREACH","EPIPE"]);

export class VpnProviderError extends Error {
  constructor(code) {super(code);this.code=code;}
}
function fail(code){throw new VpnProviderError(code);}
export function providerEnabled(id,env=process.env){
  return Object.hasOwn(PROVIDERS,id) && env.CLOUD_SERVER_VPN_ENABLED==="true";
}
export function providerIds(){return Object.keys(PROVIDERS);}

async function vettedIpv4(host) {
  let list;
  try{list=await dns.lookup(host,{all:true,family:4,verbatim:true});}
  catch{fail("REMOTE_NETWORK_DENIED");}
  if(!Array.isArray(list)||!list.length||list.length>32||
     list.some(item=>item.family!==4||!publicIpv4(item.address)))
    fail("REMOTE_NETWORK_DENIED");
  return [...new Set(list.map(item=>item.address))].slice(0,8);
}

function pinnedGet(url,ip,agent,timeout){
  return new Promise((resolve,reject)=>{
    const parsed=new URL(url);
    let settled=false,bytes=0;
    const chunks=[];
    const finish=(err,data)=>{
      if(settled)return;settled=true;
      if(err)reject(err);else resolve(data);
    };
    const req=https.request(parsed,{
      method:"GET",agent:false,rejectUnauthorized:true,minVersion:"TLSv1.2",
      timeout,
      headers:{"User-Agent":agent,"Accept-Encoding":"identity","Connection":"close"},
      lookup:(host,options,callback)=>{
        if(host!==parsed.hostname)return callback(Object.assign(new Error("hostname"),{code:"EHOSTUNREACH"}));
        if(options?.all)return callback(null,[{address:ip,family:4}]);
        return callback(null,ip,4);
      },
    },res=>{
      const status=res.statusCode||0;
      if([301,302,307,308].includes(status)){
        const location=res.headers.location;
        res.resume();
        return finish(null,{redirect:location});
      }
      if(status!==200){res.resume();return finish(new VpnProviderError("REMOTE_PROVIDER_UNAVAILABLE"));}
      if((res.headers["content-encoding"]||"identity")!=="identity"){
        res.resume();return finish(new VpnProviderError("REMOTE_RESPONSE_INVALID"));
      }
      res.on("data",part=>{
        bytes+=part.length;
        if(bytes>MAX_BYTES){
          finish(new VpnProviderError("REMOTE_TOO_LARGE"));req.destroy();
          return;
        }
        chunks.push(part);
      });
      res.on("error",err=>finish(err));
      res.on("end",()=>finish(null,{data:Buffer.concat(chunks)}));
    });
    req.on("timeout",()=>req.destroy(Object.assign(new Error("timeout"),{code:"ETIMEDOUT"})));
    req.on("error",err=>finish(err));
    req.end();
  });
}

export async function downloadVpnCatalog(id){
  const provider=PROVIDERS[id];
  if(!provider)fail("UNSUPPORTED_FORMAT");
  if(!providerEnabled(id))fail("REMOTE_NOT_CONFIGURED");
  const initial=new URL(provider.url);
  if(initial.protocol!=="https:"||initial.port||initial.username||initial.password||
     initial.hash)fail("REMOTE_NETWORK_DENIED");
  const deadline=Date.now()+DEADLINE_MS;
  let target=initial.href;
  const visited=new Set();
  for(let hop=0;hop<3;hop++){
    if(visited.has(target))fail("REMOTE_NETWORK_DENIED");
    visited.add(target);
    const dest=new URL(target);
    if(dest.protocol!=="https:"||dest.host!==initial.host||dest.username||
       dest.password||dest.search!==initial.search||dest.hash||dest.port)fail("REMOTE_NETWORK_DENIED");
    const addresses=await vettedIpv4(dest.hostname);
    let redirected=false;
    for(const ip of addresses){
      const remaining=deadline-Date.now();
      if(remaining<=0)fail("REMOTE_PROVIDER_UNAVAILABLE");
      let answer;
      try{answer=await pinnedGet(target,ip,provider.agent,Math.min(CONNECT_MS,remaining));}
      catch(error){
        if(error instanceof VpnProviderError)throw error;
        // TLS/certificate errors and definitive HTTP statuses never retry.
        if(!RETRY_CODES.has(error?.code))fail("REMOTE_PROVIDER_UNAVAILABLE");
        continue;
      }
      if(answer.redirect!==undefined){
        const next=answer.redirect;
        if(typeof next!=="string"||next.length>2048)fail("REMOTE_NETWORK_DENIED");
        target=new URL(next,dest).href;
        redirected=true;
        break;
      }
      if(!Buffer.isBuffer(answer.data)||answer.data.length===0||
         answer.data.length>MAX_BYTES)fail("REMOTE_RESPONSE_INVALID");
      return answer.data;
    }
    if(!redirected)fail("REMOTE_PROVIDER_UNAVAILABLE");
  }
  fail("REMOTE_NETWORK_DENIED");
}
