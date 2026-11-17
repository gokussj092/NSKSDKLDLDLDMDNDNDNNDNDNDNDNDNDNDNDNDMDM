import {inputDownloadRequest} from '../../../../../../lib/app-analysis-input.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export async function GET(request,{params,...options}){
 const {jobId}=await params;
 return inputDownloadRequest(request,jobId,options);
}
export const HEAD=GET;
