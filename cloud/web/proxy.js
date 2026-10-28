import { legacyApiRetired } from "./lib/v2-config.mjs";
export function proxy(request) {
  if(legacyApiRetired(new URL(request.url).pathname))
    return Response.json({error:{code:"CLIENT_UPDATE_REQUIRED"}},{status:410,
      headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
}
export const config={matcher:["/api/v1/:path*"]};
