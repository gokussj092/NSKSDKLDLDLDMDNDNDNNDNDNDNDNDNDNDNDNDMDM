export const routes=Object.freeze({
  4:"npvs/identity",5:"decode/file",6:"decode/text",7:"decode/import/cloud",
  8:"decode/import/http-custom",9:"decode/import/catalog/remote",10:"server-vpn/catalog",
  11:"server-vpn/icon",12:"server-vpn/decode",13:"server-vpn/watch",14:"whats-new",15:"telemetry",17:"notifications",18:"feedback",19:"server-vpn/manifest",20:"server-vpn/chunk",
  21:"apk-qa/start",22:"apk-qa/chunk",23:"apk-qa/finish",24:"apk-qa/result",
  25:"app-analysis/preflight",26:"app-analysis/start",27:"app-analysis/chunk",
  28:"app-analysis/finish",29:"app-analysis/status",30:"app-analysis/history",
});
// The route taxonomy is security-sensitive: none of these operations may
// spend the decoder's per-device or daily quota. Metadata remains authenticated,
// PoP-bound and replay protected, with an independent high safety ceiling.
export const metadata=new Set([10,11,13,14,15,16,17,18,19,20,24,25,29,30]);
export const uploads=new Set([22,27]);
export const analysisJobs=new Set([21,23,26,28]);
export const decodeWork=new Set([4,5,6,7,8,9,12]);
export const rateClass=op=>metadata.has(op)?"metadata":uploads.has(op)?"upload":
  analysisJobs.has(op)?"analysis":decodeWork.has(op)?"decode":"admission";
export const bodyLimit=op=>op===22||op===27?3*1024*1024:op===5?11*1024*1024:op===6?1024*1024:op===2?80000:op===18?16384:4096;
