import {safe,reply,jsonBody} from '../../../../../../lib/commerce/config.mjs';
import {verifyBotToken,recordEvent} from '../../../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Bot-only (Yamada): publish progress. ANALYSIS_STARTED enforces the
// ANALYZING concurrency cap (429 APP_ANALYSIS_BUSY when full).
export const POST=async(request,{params})=>safe(async()=>{
 verifyBotToken(request);
 const {jobId}=await params;
 const body=await jsonBody(request,16*1024);
 return reply(await recordEvent(jobId,body));
});
