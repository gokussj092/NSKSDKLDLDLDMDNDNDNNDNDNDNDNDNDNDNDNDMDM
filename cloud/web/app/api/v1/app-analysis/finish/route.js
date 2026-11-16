import {safe,reply,jsonBody,requireOrigin} from '../../../../../lib/commerce/config.mjs';
import {requireAccount} from '../../../../../lib/commerce/auth.mjs';
import {finishJob} from '../../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Verifies the full SHA-256, then runs the pre-analysis gate (blocked apps
// and the VPN-manifest check) before queueing for Yamada.
export const POST=request=>safe(async()=>{
 const session=await requireAccount(request);
 requireOrigin(request);
 const body=await jsonBody(request,4096);
 return reply(await finishJob(session.user.id,body));
});
