import {decodeServerVpn} from "../../../../../lib/server-vpn-gateway.mjs";
export const runtime="nodejs";
export async function POST(request){return decodeServerVpn(request);}
