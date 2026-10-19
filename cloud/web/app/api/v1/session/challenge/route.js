import { enabled, notEnabled, challengeRequest } from "../../../../../lib/c3-gateway.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function POST(request){return enabled()?challengeRequest(request):notEnabled();}
