export const routes=Object.freeze({
  4:"npvs/identity",5:"decode/file",6:"decode/text",7:"decode/import/cloud",
  8:"decode/import/http-custom",9:"decode/import/catalog/remote",10:"server-vpn/catalog",
  11:"server-vpn/icon",12:"server-vpn/decode",13:"server-vpn/watch",14:"whats-new",15:"telemetry",17:"notifications",18:"feedback",19:"server-vpn/manifest",20:"server-vpn/chunk",
});
export const metadata=new Set([10,11,13,14,16,17,19,20]);
export const bodyLimit=op=>op===5?11*1024*1024:op===6?1024*1024:op===2?80000:op===18?16384:4096;
