import {webhookRequest} from "../../../../../lib/commerce/api.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export async function POST(request,context){const {provider}=await context.params;return webhookRequest(request,provider);}
