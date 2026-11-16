import {safe,reply,jsonBody} from '../../../../../../lib/commerce/config.mjs';
import {verifyBotToken,completeJob} from '../../../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Bot-only (Yamada): close with the deliverable. Charges the held credit
// (COMPLETED or COMPLETED_PARTIAL), stores result.zip privately, and records
// a catalog candidate (pending) when the method is new. Never echoes
// icon_ref or catalog refs back to the client.
export const POST=async(request,{params})=>safe(async()=>{
 verifyBotToken(request);
 const {jobId}=await params;
 const body=await jsonBody(request,48*1024*1024);
 return reply(await completeJob(jobId,body));
});
