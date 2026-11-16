import {safe,reply,jsonBody,requireOrigin} from '../../../../../lib/commerce/config.mjs';
import {requireAccount} from '../../../../../lib/commerce/auth.mjs';
import {startJob} from '../../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Creates the job and reserves 1 credit. No consent is required here:
// Pedro removed both checkboxes (P2) — the server must NOT return a
// CONSENT_REQUIRED 403 for app analysis.
export const POST=request=>safe(async()=>{
 const session=await requireAccount(request);
 requireOrigin(request);
 const body=await jsonBody(request,4096);
 return reply(await startJob(session.user.id,body),201);
});
