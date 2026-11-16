import {safe,reply,jsonBody} from '../../../../../../lib/commerce/config.mjs';
import {verifyBotToken,failJob} from '../../../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Bot-only (Yamada): close as failed. Releases the held credit.
export const POST=async(request,{params})=>safe(async()=>{
 verifyBotToken(request);
 const {jobId}=await params;
 const body=await jsonBody(request,16*1024);
 return reply(await failJob(jobId,body));
});
