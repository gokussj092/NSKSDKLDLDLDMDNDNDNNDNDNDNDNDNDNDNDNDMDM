import {safe,reply} from '../../../../../lib/commerce/config.mjs';
import {requireAccount} from '../../../../../lib/commerce/auth.mjs';
import {getJob} from '../../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Durable job state for reconnection (Postgres, 30 days). The client renders
// ONE status card from phaseCode/progressPercent; events[] is internal record
// only and must never be rendered as a list or timeline.
export const GET=async(request,{params})=>safe(async()=>{
 const session=await requireAccount(request);
 const {jobId}=await params;
 return reply(await getJob(session.user.id,jobId));
});
