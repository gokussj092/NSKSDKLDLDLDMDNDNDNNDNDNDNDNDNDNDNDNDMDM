import {iconFor} from "../../../../../lib/server-vpn-catalog.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
const reply=(body,status=200)=>Response.json(body,{status,headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
export async function POST(request) {
  let id;
  try {
    if(Number(request.headers.get("content-length")||0)>2048) throw Error("body");
    const data=await request.json();
    if(!data || Object.keys(data).length!==1 || typeof data.id!=="string" ||
       !/^[a-z0-9-]{1,48}$/.test(data.id)) throw Error("schema");
    id=data.id;
  }catch{return reply({error:{code:"INVALID_REQUEST"}},400);}
  try {
    const icon=iconFor(id);
    if(!icon)return reply({error:{code:"NOT_FOUND"}},404);
    return reply({apiVersion:"v1",id,sha256:icon.sha256,mimeType:"image/png",
      contentBase64:icon.bytes.toString("base64")});
  }catch{return reply({error:{code:"SERVICE_UNAVAILABLE"}},503);}
}
