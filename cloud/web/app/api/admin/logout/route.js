import { logoutRequest } from "../../../../lib/c6-admin-api.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function POST(request){return logoutRequest(request);}
