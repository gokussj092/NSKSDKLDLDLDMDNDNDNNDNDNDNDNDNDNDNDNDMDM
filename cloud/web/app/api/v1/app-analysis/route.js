import {safe,reply} from '../../../../lib/commerce/config.mjs';
import {requireAccount} from '../../../../lib/commerce/auth.mjs';
import {listJobs} from '../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Account history ("Aplicaciones"): the user's own jobs, newest first.
// Each completed job carries a fresh 24 h signed downloadUrl.
export const GET=request=>safe(async()=>{
 const session=await requireAccount(request);
 return reply(await listJobs(session.user.id));
});
