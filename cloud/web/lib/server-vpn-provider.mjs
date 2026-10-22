/**
 * C8 public VPN catalog broker. Fixed approved providers ONLY.
 * DNS is revalidated, every HTTPS connection is bound to one vetted IPv4,
 * redirects are constrained to the original HTTPS origin, and only temporary
 * socket errors may retry on another validated IP (NUR C3.5 policy).
 */
import dns from "node:dns/promises";
import https from "node:https";
import {publicIpv4} from "./c35-provider.mjs";

const SOCKETCLAY_SOURCES=Object.freeze({
  servers:"https://dl.dropboxusercontent.com/scl/fi/vh319xyu0ck84ks0wdqw8/ServersSC?rlkey=b9g57byy0igz2jitqix31t4i4&st=evmzpf11&dl=1",
  users:"https://dl.dropboxusercontent.com/scl/fi/yas4u26xnhdpz4f8qxkp0/UsersSC?rlkey=jtdh2g84uj6y5j9zp4ca929xk&st=hp49nv1g&dl=1",
});
const WAKKO_SOURCES=Object.freeze({
  "servers": "https://dl.dropboxusercontent.com/scl/fi/a6grfye2vx80gxxydc6aw/ServersWK2?rlkey=ulmj9oxy1xx3fedhrtnzdwrxm&st=93x7687n&dl=1",
  "users": "https://dl.dropboxusercontent.com/scl/fi/2sc3ud954k0ai07trkdhj/UsersWK?rlkey=k4wqqaawxcddx0kc1sfanof9r&st=dwrzwrmv&dl=1"
});
const V2PLUS_SOURCES=Object.freeze({
  base64:"https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
  raw:"https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
});
const PAIRED_SOURCES=Object.freeze({"http-socketclay":SOCKETCLAY_SOURCES,"http-wakko":WAKKO_SOURCES,"v2ray-tunnel-plus":V2PLUS_SOURCES});
const PROVIDERS = Object.freeze({
  "megatunnel": {url:"https://raw.githubusercontent.com/SpkHexX/HexX/refs/heads/main/MegaTunnel.js",agent:"MegaTunnel/1.17.1"},
  "http-internet-infinito": {url:"https://raw.githubusercontent.com/nemygoku/nemy/refs/heads/main/httpinfi",agent:"HTTP Internet Infinito/1.3.9"},
  "freedom-vpn": {url:"https://raw.githubusercontent.com/geko2023/shield/refs/heads/master/free",agent:"FreedomVPN/1.0.29"},
  "focus-vpn-cloud": {url:"https://raw.githubusercontent.com/Rotdtd/Upagost17/refs/heads/main/NewSepFocass",agent:"Focus VPN Cloud/5.0"},
  "v2ray-tunnel-plus": {url:V2PLUS_SOURCES.base64,agent:"V2ray Tunnel Plus/10.0.0"},
  "http-wakko": {url:WAKKO_SOURCES.servers,agent:"HTTP Wakko/4.9"},
  "http-socketclay": {
    url:SOCKETCLAY_SOURCES.servers,
    agent:"HTTP SocketClay/3.4.0",
  },
  "tunneltweak": {
    url:"https://tunneltweak.com/api/servers",
    agent:"TunnelTweak/1.0 (Android)",
    headers:{"ngrok-skip-browser-warning":"true","x-app-version":"51","x-cfg-keyed":"1"},
  },
  "http-jireh": {
    url:"https://raw.githubusercontent.com/alvarofelizzola/GEN-JIREH/refs/heads/main/GENERADOR",
    agent:"HTTP Jireh/2.0",
  },
  "http-fenixvpn": {
    url:"https://raw.githubusercontent.com/Fenix1998x/GEN-SERVIDORES-NUEVO-24-08-2027/refs/heads/main/Fenix",
    agent:"HTTP FenixVPN/19.4",
  },
  "austroplus-vpn": {
    url:"https://raw.githubusercontent.com/SpkHexX/HexX/refs/heads/main/AustroPlusVPN.json",
    agent:"AustroPlus VPN/13.0.1",
  },
  "ac-tunnel-vpn": {
    url:"https://rttunnelv2ray.xyz/api/files/app?json=7ef7a9a142eb1f77a56f",
    agent:"AC TUNNEL VPN/1.4",
  },
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
  "ksh-vpn": {
    url:"https://raw.githubusercontent.com/yannaing86tt/ksh_server/main/servers.json",
    agent:"KSH VPN/1.3.2",
  },
  "my-tunnel-proxy": {
    url:"https://mfmpro.xyz/api/app?json=3c9a2a29f3a4180271da",
    agent:"My Tunnel Proxy/2.3",
  },
  "robust-tunnel": {
    url:"https://xkingvpn.xyz/api/files/app?json=beae113e6e46d674a068",
    agent:"Robust Tunnel VPN/isvsoft 16.4.7",
  },
  "trv-tunnel": {
    url:"https://trmrelay.store/updater/b67b57c85f49c34ee09fd87f2d6915",
    agent:"TRV TUNNEL/2.4",
  },
  "4u-tunnel-lite": {
    url:"https://ctxrelay.online/updater/08f9aa63574a055cffdac66783b05b",
    agent:"4U TUNNEL LITE/2.2",
  },
});
// All MKK sources are approved literals; no user-supplied download targets.
const MKK_SOURCES=Object.freeze({
  servers:"https://f005.backblazeb2.com/file/mkkhyper/api_server.json",
  static:"https://flashvpn.sgp1.digitaloceanspaces.com/static.json",
  subscriptions:"https://f005.backblazeb2.com/file/mkkhyper/subscriptions.json",
  "legacy-subscriptions":"https://raw.githubusercontent.com/Tunzen665/flash-vpn/refs/heads/main/sub.json",
});
export function mkkSourceIds(){return Object.keys(MKK_SOURCES);}
const MAX_BYTES=8*1024*1024;
const DEADLINE_MS=30000;
const CONNECT_MS=10000;
const RETRY_CODES=new Set(["ECONNRESET","ETIMEDOUT","ESOCKETTIMEDOUT","ECONNREFUSED","EHOSTUNREACH","ENETUNREACH","EPIPE"]);

export class VpnProviderError extends Error {
  constructor(code,{retryable=false}={}) {super(code);this.code=code;this.retryable=retryable;}
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

function pinnedGet(url,ip,agent,timeout,headers={}){
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
      headers:{...headers,"User-Agent":agent,"Accept-Encoding":"identity","Connection":"close"},
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
      if(status!==200){
        res.resume();
        // Retry only transient upstream throttling/outages, never auth, TLS or
        // a redirected origin. The bound IP, TLS hostname and deadline remain.
        const retryable=[429,500,502,503,504].includes(status);
        return finish(new VpnProviderError("REMOTE_PROVIDER_UNAVAILABLE",{retryable}));
      }
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

export async function downloadVpnCatalog(id,source=id==="v2ray-tunnel-plus"?"base64":"servers"){
  const provider=PROVIDERS[id];
  if(!provider)fail("UNSUPPORTED_FORMAT");
  if(!providerEnabled(id))fail("REMOTE_NOT_CONFIGURED");
  if(id!=="mkk-hyper" && !Object.hasOwn(PAIRED_SOURCES,id) && source!=="servers")fail("UNSUPPORTED_FORMAT");
  if(id==="mkk-hyper" && !Object.hasOwn(MKK_SOURCES,source))fail("UNSUPPORTED_FORMAT");
  if(Object.hasOwn(PAIRED_SOURCES,id) && !Object.hasOwn(PAIRED_SOURCES[id],source))fail("UNSUPPORTED_FORMAT");
  const initial=new URL(id==="mkk-hyper"?MKK_SOURCES[source]:
    Object.hasOwn(PAIRED_SOURCES,id)?PAIRED_SOURCES[id][source]:provider.url);
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
    // A single-address CDN sometimes drops one request. Retry once on the
    // *same revalidated public IPv4* only for temporary HTTP/socket errors.
    const attempts=addresses.length===1?[addresses[0],addresses[0]]:addresses;
    for(const ip of attempts){
      const remaining=deadline-Date.now();
      if(remaining<=0)fail("REMOTE_PROVIDER_UNAVAILABLE");
      let answer;
      try{answer=await pinnedGet(target,ip,provider.agent,Math.min(CONNECT_MS,remaining),provider.headers);}
      catch(error){
        if(error instanceof VpnProviderError){
          if(!error.retryable)throw error;
          continue;
        }
        // TLS/certificate errors and definitive HTTP statuses never retry.
        if(!RETRY_CODES.has(error?.code))fail("REMOTE_PROVIDER_UNAVAILABLE");
        continue;
      }
      if(answer.redirect!==undefined){
        if(["focus-vpn-cloud","freedom-vpn","http-internet-infinito","megatunnel"].includes(id)||Object.hasOwn(PAIRED_SOURCES,id))fail("REMOTE_NETWORK_DENIED");
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
