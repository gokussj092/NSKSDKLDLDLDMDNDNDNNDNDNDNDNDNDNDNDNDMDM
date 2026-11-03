/**
 * C8 public VPN catalog broker. Fixed approved providers ONLY.
 * DNS is revalidated and every connection is bound to one vetted IPv4.
 * HTTPS is required except the fixed JyFast APK URLs on HTTP port 85.
 * Redirects stay on the original origin (paired sources refuse all redirects);
 * only temporary socket errors may retry on a vetted IP (NUR C3.5 policy).
 */
import dns from "node:dns/promises";
import https from "node:https";
import http from "node:http";
import {ALFAISAL_SOURCE,ALFAISAL_METADATA,alfaisalConfigured,alfaisalRequest} from "./alfaisal-protocol.mjs";
import {HALCON_SOURCE,halconConfigured,halconRequest} from "./halcon-protocol.mjs";
import {publicIpv4} from "./c35-provider.mjs";

const ABOWAGED_SOURCES=Object.freeze({
  servers:"https://raw.githubusercontent.com/th3fre/Testing/refs/heads/main/Elk.txt",
  udp:"https://raw.githubusercontent.com/janatshaban/REMOTEUPDATER/refs/heads/main/pickerver",
});
const TURBOMX_SOURCES=Object.freeze({
  servers:"https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/turbomx/servr_turbomx_sv5c",
  users:"https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/turbomx/user_turbomx_sv5c",
});
const SUPERFLASH_SOURCES=Object.freeze({
  servers:"https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/supervpn/servr_superflash_sv5c",
  users:"https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/supervpn/user_superflash_sv5c",
});
const ONSPACE_SOURCES=Object.freeze({
  servers:"https://raw.githubusercontent.com/El-Patron-Oficial2003/Metodos/refs/heads/main/OnSpace%20VPN",
  users:"https://raw.githubusercontent.com/El-Patron-Oficial2003/User-Pass-New/refs/heads/main/OnSpace%20VPN",
});
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
// Original APK 9 source uses HTTP on port 85; this exception is restricted
// to these two fixed vendor paths and is never selected by a client URL.
const JYFAST_SOURCES=Object.freeze({
  free:"http://dev.jenrri.shop:85/ignix_update.php?cfg=free",
  premium:"http://dev.jenrri.shop:85/ignix_update.php?cfg=premium",
});
const PAIRED_SOURCES=Object.freeze({"jyfast-vpn-ultra":JYFAST_SOURCES,"abowaged-vpn":ABOWAGED_SOURCES,"turbomx-vpn":TURBOMX_SOURCES,"superflash-vpn":SUPERFLASH_SOURCES,"onspace-vpn":ONSPACE_SOURCES,"http-socketclay":SOCKETCLAY_SOURCES,"http-wakko":WAKKO_SOURCES,"v2ray-tunnel-plus":V2PLUS_SOURCES});
const PROVIDERS = Object.freeze({
  "fnf-tunnel-bd": {url:"https://raw.githubusercontent.com/pipoyrichards/FNFTUNNELBD/refs/heads/main/FEB52025",agent:"FNF TUNNEL BD/PrinceBuild35"},
  "alsaher-vip": {url:"https://raw.githubusercontent.com/Skytells0/Alsaher/main/jihadvip.json",agent:"okhttp/4.12.0"},
  "halcon-r-net": {url:HALCON_SOURCE,agent:"Dalvik/2.1.0"},
  // ResourceUpdater GET; Volley uses Android's default Dalvik agent family.
  "ha-tunnel-plus": {url:"https://www.hatunnel.me/resources/main.txt",agent:"Dalvik/2.1.0"},
  "ultra-tunnel": {url:"https://strongteam.co/api/ultrasystem/ultrav3.txt",agent:"Ultra Tunnel"},
  "mm-tunnel": {url:"https://strongteam.co/api/mmtunnel/",agent:"Go-http-client/1.1",
    headers:{"Content-Type":"application/x-www-form-urlencoded"},
    method:"POST",body:Buffer.from("hash=xsandokUpdatex")},
  "zig-tunnel": {url:"https://zimbotunnel.co.zw/default_config.hs",agent:"okhttp/5.3.2"},
  "enaa-tunnel": {url:"https://strongteam.co/api/wolftunnellite/enaav1.txt",agent:"Enaa Tunnel"},
  "alfaisal-tunnel-plus": {url:ALFAISAL_SOURCE,agent:"ALFAISAL Tunnel+/39"},
  "izph-vpn-pro": {url:"https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/izph49",agent:"IZPH VPN PRO/6.0"},
  "vip-snipher-pro": {
    url:"https://raw.githubusercontent.com/Civ3snipher/NEW-VIP-SNIPHER-PRO-3/refs/heads/main/update.json?ref=main",
    agent:"VIP Snipher Pro/2.9",
    headers:{"Accept":"application/json","X-GitHub-Api-Version":"2022-11-28"},
  },
  "netcol-vpn": {url:"https://raw.githubusercontent.com/jdavidag/setting/main/tO6oD1drTvL2.json",agent:"Netcol VPN/14.2"},
  "wolf-custom-vpn": {url:"https://strongteam.co/api/wolfcustom/newv1.txt",agent:"Wolf Custom VPN"},
  "jyfast-vpn-ultra": {url:JYFAST_SOURCES.free,agent:"JyFast VPN Ultra/9",headers:{"X-IGNIX-SIG":"10c7440b8feac5cee6a54959e7599ff26bd27153"}},
  "tunneldoom-vpn": {url:"https://panel.tunneldoom.space/config.json",agent:"Dalvik/2.1.0"},
  "mtm-tunnel-lite": {url:"https://xtmtunnel.xyz/updater/527543543860c45bf4238f2a1b56c3",agent:"Dalvik/2.1.0"},
  "mnr-tunnel-plus": {url:"https://raw.githubusercontent.com/buttacuore2025/up/refs/heads/main/plusfast",agent:"MNR TUNNEL PLUS/3.1"},
  "bd-net-vpn": {url:"https://raw.githubusercontent.com/panigbatanc/BDNET2023/main/JSONDEC2025",agent:"BD NET VPN/PrinceBuild111"},
  "aura-net-vpn": {url:"https://strongteam.co/api/kidvpn/v4/aurav1.txt",agent:"Aura Net VPN"},
  "apna-vpn": {url:"https://paperonboard.com/updater/3c3c4c58d864ca394da16656b4d0c4",agent:"Dalvik/2.1.0"},
  "any-vpn": {url:"https://free-panel.myprotectionservices.com/uploads/json/1e760370dff563b8fa00.json",agent:"okhttp/5.0.0-alpha.12"},
  "speicers-pro-vpn": {url:"https://raw.githubusercontent.com/satanas66666/Aplicaciones/refs/heads/main/speicerspro/servidores_pro",agent:"Speicers Pro/104.1.17"},
  "tx-tunnel": {url:"https://strongteam.co/api/txtunnel/v1/?appcode=27.0",agent:"Tx Tunnel"},
  "abowaged-vpn": {url:ABOWAGED_SOURCES.servers,agent:"AboWaged VPN/1.0"},
  "7net-vpn": {url:"https://raw.githubusercontent.com/MAKE-MONEY-MILLION-DOLLAR-PER-DAY/7net-Team/refs/heads/main/7net%2BAll_Team.js",agent:"7NET VPN/5.6"},
  "xhypher-tunnel-pro": {url:"https://raw.githubusercontent.com/XyrussProject/infinite88/refs/heads/main/xhyphertunnelpro888.hs",agent:"Xhypher Tunnel Pro/43"},
  "turbomx-vpn": {url:TURBOMX_SOURCES.servers,agent:"TurboMX VPN/143.1.26"},
  "superflash-vpn": {url:SUPERFLASH_SOURCES.servers,agent:"SuperFlash VPN/184.0.1"},
  "rmp-tunnel-pro": {url:"https://raw.githubusercontent.com/pipoyrichards/RMPSYSTEM/refs/heads/main/RMPPRO",agent:"RMP TUNNEL PRO/RMP-5"},
  "rjc-tunnel-pro": {url:"https://raw.githubusercontent.com/pipoyrichards/RJCPRO/refs/heads/main/FEBRUARY",agent:"RJC TUNNEL PRO/RJC-6"},
  "onspace-vpn": {url:ONSPACE_SOURCES.servers,agent:"OnSpace VPN/4.2"},
  "mx-tunnel-pro": {url:"https://rasedpanel.xyz/updater/750b71355b025b19884ee835b759d6",agent:"Mx Tunnel PRO/Mx-Build48"},
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
    // Build 13 moved NETWORK to Dropbox; the former GitHub URL is stale.
    // Use the fixed raw-content host so no cross-origin redirect is needed.
    url:"https://dl.dropboxusercontent.com/scl/fi/9p6vvoa8jfch3ribneckq/HTTPJIREH1117?rlkey=05z97u9cg8tv4k5xem9m1uxu2&st=huezcplw&dl=1",
    agent:"HTTP Jireh/2.2",
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
  if(!Object.hasOwn(PROVIDERS,id) || env.CLOUD_SERVER_VPN_ENABLED!=="true")return false;
  if(id==="halcon-r-net")return halconConfigured(env);
  if(id==="alfaisal-tunnel-plus")return alfaisalConfigured(env);
  if(id!=="vip-snipher-pro")return true;
  const authorization=env.SPDECODE_VIP_SNIPHER_AUTHORIZATION;
  return typeof authorization==="string" && authorization.length<=2048 &&
    /^(Bearer|token) [!-~]+$/.test(authorization) && !/[\r\n]/.test(authorization);
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

function pinnedRequest(url,ip,agent,timeout,headers={}, {method="GET",body=null}={}){
  return new Promise((resolve,reject)=>{
    const parsed=new URL(url);
    let settled=false,bytes=0;
    const chunks=[];
    const finish=(err,data)=>{
      if(settled)return;settled=true;
      if(err)reject(err);else resolve(data);
    };
    const transport=parsed.protocol==="http:"?http:https;
    const req=transport.request(parsed,{
      method,agent:false,
      ...(parsed.protocol==="https:"?{rejectUnauthorized:true,minVersion:"TLSv1.2"}:{}),
      timeout,
      headers:{...headers,...(body?{"Content-Length":String(body.length)}:{}),"User-Agent":agent,"Accept-Encoding":"identity","Connection":"close"},
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
    req.end(body??undefined);
  });
}

// The build39 app uses metadata policy + a signed POST, not a public GET.
async function downloadAlfaisal(provider){
  const config={SPDECODE_ALFAISAL_API_KEY:process.env.SPDECODE_ALFAISAL_API_KEY,
    SPDECODE_ALFAISAL_SIGNING_KEY:process.env.SPDECODE_ALFAISAL_SIGNING_KEY,
    SPDECODE_ALFAISAL_DEVICE_UUID:process.env.SPDECODE_ALFAISAL_DEVICE_UUID};
  const deadline=Date.now()+DEADLINE_MS;
  async function request(url,headers,options={}){
    const dest=new URL(url);
    // Both paths are build39 literals. Never follow metadata-provided URLs.
    if(dest.origin!==new URL(ALFAISAL_SOURCE).origin ||
       ![ALFAISAL_METADATA,ALFAISAL_SOURCE].includes(dest.origin+dest.pathname))fail("REMOTE_NETWORK_DENIED");
    const addresses=await vettedIpv4(dest.hostname);
    const remaining=deadline-Date.now();
    if(remaining<=0)fail("REMOTE_PROVIDER_UNAVAILABLE");
    let answer;
    try{answer=await pinnedRequest(url,addresses[0],provider.agent,
      Math.min(options.method==="POST"?20000:10000,remaining),headers,options);}
    catch(error){
      if(error instanceof VpnProviderError)throw error;
      fail("REMOTE_PROVIDER_UNAVAILABLE");
    }
    // A signed POST is never retried with a reused nonce, even on a 503.
    if(Object.hasOwn(answer,"redirect"))fail("REMOTE_NETWORK_DENIED");
    if(!Buffer.isBuffer(answer.data)||!answer.data.length)fail("REMOTE_RESPONSE_INVALID");
    return answer.data;
  }
  const metadata=new URL(ALFAISAL_METADATA);
  metadata.searchParams.set("json_client_capability","2");
  metadata.searchParams.set("device_uuid",config.SPDECODE_ALFAISAL_DEVICE_UUID);
  const raw=await request(metadata.href,{Accept:"application/json"});
  if(raw.length>1024*1024)fail("REMOTE_RESPONSE_INVALID");
  let policy;
  try{policy=JSON.parse(raw.toString("utf8"));}catch{fail("REMOTE_RESPONSE_INVALID");}
  if(!policy||Array.isArray(policy)||(policy.success!==undefined&&policy.success!==true)||policy.json_requires_integrity!==false)
    fail("REMOTE_PROVIDER_UNAVAILABLE");
  const signed=alfaisalRequest(config);
  const data=await request(ALFAISAL_SOURCE,signed.headers,{method:"POST",body:signed.body});
  if(data.subarray(0,64).toString("utf8").trimStart().startsWith("<"))fail("REMOTE_RESPONSE_INVALID");
  return data;
}

async function downloadHalcon(provider){
  const dest=new URL(HALCON_SOURCE);
  const addresses=await vettedIpv4(dest.hostname);
  const signed=halconRequest();
  let answer;
  try{answer=await pinnedRequest(HALCON_SOURCE,addresses[0],provider.agent,DEADLINE_MS,
    signed.headers,{method:"POST",body:signed.body});}
  catch(error){
    if(error instanceof VpnProviderError)throw error;
    fail("REMOTE_PROVIDER_UNAVAILABLE");
  }
  // Never forward signed headers to another path/origin or retry a signed POST.
  if(Object.hasOwn(answer,"redirect"))fail("REMOTE_NETWORK_DENIED");
  if(!Buffer.isBuffer(answer.data)||!answer.data.length||
     answer.data.subarray(0,64).toString("utf8").trimStart().startsWith("<"))fail("REMOTE_RESPONSE_INVALID");
  return answer.data;
}

export async function downloadVpnCatalog(id,source=id==="jyfast-vpn-ultra"?"free":id==="v2ray-tunnel-plus"?"base64":"servers"){
  const provider=PROVIDERS[id];
  if(!provider)fail("UNSUPPORTED_FORMAT");
  if(!providerEnabled(id))fail("REMOTE_NOT_CONFIGURED");
  if(id==="halcon-r-net"){
    if(source!=="servers")fail("UNSUPPORTED_FORMAT");
    return downloadHalcon(provider);
  }
  if(id==="alfaisal-tunnel-plus"){
    if(source!=="servers")fail("UNSUPPORTED_FORMAT");
    return downloadAlfaisal(provider);
  }
  // Read the secret per request, only for the fixed VIP updater. Never expose it
  // in the public catalog, worker payload, provider switches or error messages.
  const headers=id==="vip-snipher-pro" ?
    {...provider.headers,Authorization:process.env.SPDECODE_VIP_SNIPHER_AUTHORIZATION} : provider.headers;
  if(id!=="mkk-hyper" && !Object.hasOwn(PAIRED_SOURCES,id) && source!=="servers")fail("UNSUPPORTED_FORMAT");
  if(id==="mkk-hyper" && !Object.hasOwn(MKK_SOURCES,source))fail("UNSUPPORTED_FORMAT");
  if(Object.hasOwn(PAIRED_SOURCES,id) && !Object.hasOwn(PAIRED_SOURCES[id],source))fail("UNSUPPORTED_FORMAT");
  const initial=new URL(id==="mkk-hyper"?MKK_SOURCES[source]:
    Object.hasOwn(PAIRED_SOURCES,id)?PAIRED_SOURCES[id][source]:provider.url);
  const jyfast=id==="jyfast-vpn-ultra";
  if((jyfast ? (initial.protocol!=="http:"||initial.port!=="85"||initial.hostname!=="dev.jenrri.shop")
               : (initial.protocol!=="https:"||initial.port)) || initial.username||initial.password||
     initial.hash)fail("REMOTE_NETWORK_DENIED");
  const deadline=Date.now()+DEADLINE_MS;
  let target=initial.href;
  const visited=new Set();
  for(let hop=0;hop<3;hop++){
    if(visited.has(target))fail("REMOTE_NETWORK_DENIED");
    visited.add(target);
    const dest=new URL(target);
    if(dest.protocol!==initial.protocol||dest.host!==initial.host||dest.username||
       dest.password||dest.search!==initial.search||dest.hash||dest.port!==initial.port)fail("REMOTE_NETWORK_DENIED");
    const addresses=await vettedIpv4(dest.hostname);
    let redirected=false;
    // A single-address CDN sometimes drops one request. Retry once on the
    // *same revalidated public IPv4* only for temporary HTTP/socket errors.
    const attempts=addresses.length===1?[addresses[0],addresses[0]]:addresses;
    for(const ip of attempts){
      const remaining=deadline-Date.now();
      if(remaining<=0)fail("REMOTE_PROVIDER_UNAVAILABLE");
      let answer;
      try{answer=await pinnedRequest(target,ip,provider.agent,Math.min(CONNECT_MS,remaining),headers,
        {method:provider.method??"GET",body:provider.body??null});}
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
        if(["fnf-tunnel-bd","alsaher-vip","ha-tunnel-plus","ultra-tunnel","mm-tunnel","zig-tunnel","enaa-tunnel","izph-vpn-pro","vip-snipher-pro","netcol-vpn","wolf-custom-vpn","tunneldoom-vpn","mtm-tunnel-lite","mnr-tunnel-plus","bd-net-vpn","aura-net-vpn","apna-vpn","any-vpn","speicers-pro-vpn","7net-vpn","xhypher-tunnel-pro","focus-vpn-cloud","freedom-vpn","http-internet-infinito","megatunnel","mx-tunnel-pro","rjc-tunnel-pro","rmp-tunnel-pro","http-jireh"].includes(id)||Object.hasOwn(PAIRED_SOURCES,id))fail("REMOTE_NETWORK_DENIED");
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
