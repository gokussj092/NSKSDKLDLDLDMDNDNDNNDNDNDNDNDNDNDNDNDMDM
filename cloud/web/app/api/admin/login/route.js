import { loginRequest } from "../../../../lib/c6-admin-api.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export const maxDuration=15;
export function POST(request){return loginRequest(request);}
