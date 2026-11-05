#!/usr/bin/env node
/**
 * Operator-only C8 verification. Never logs remote response bytes, credentials,
 * endpoint URLs or decoded VPN data. No state changes unless --enable-mm.
 *
 * This checks download transport only; a received ciphertext is NOT evidence
 * that the current vendor format still decodes correctly.
 */
import {createHash} from "node:crypto";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {providerOverview,providerPrerequisite,updateProvider,updateMethodState} from "../lib/c12-provider-controls.mjs";

const IDS=["mm-tunnel","tunneldoom-vpn"];
const FLAGS=new Set(["--enable-mm","--probe","--mm-only","--tunneldoom-only"]);
const SAFE_ERRORS=new Set(["REMOTE_NOT_CONFIGURED","REMOTE_NETWORK_DENIED",
  "REMOTE_PROVIDER_UNAVAILABLE","REMOTE_RESPONSE_INVALID","REMOTE_TOO_LARGE",
  "UNSUPPORTED_FORMAT"]);

export function parseArgs(argv){
  if(argv.some(arg=>!FLAGS.has(arg))||
     (argv.includes("--mm-only")&&argv.includes("--tunneldoom-only")))
    throw Error("USAGE: node scripts/catalog-provider-check.mjs [--enable-mm] [--probe] [--mm-only|--tunneldoom-only]");
  return {enableMM:argv.includes("--enable-mm"),probe:argv.includes("--probe"),
    ids:argv.includes("--mm-only")?[IDS[0]]:argv.includes("--tunneldoom-only")?[IDS[1]]:IDS};
}

export async function audit(options={},services={}){
  const {enableMM=false,probe=false,ids=IDS}=options;
  if(!Array.isArray(ids)||!ids.length||ids.some(id=>!IDS.includes(id)))
    throw Error("INVALID_PROVIDER_SELECTION");
  const api={downloadVpnCatalog,providerOverview,providerPrerequisite,
    updateProvider,updateMethodState,...services};
  let mmStateChanged=false;
  if(enableMM){
    if(!api.providerPrerequisite("mm-tunnel"))
      throw Error("MM_PREREQUISITES_DISABLED");
    // Keep every other provider unchanged. The method's independent
    // maintenance flag must also be cleared for effective availability.
    await api.updateProvider("mm-tunnel",true);
    await api.updateMethodState("mm-tunnel","maintenance",false);
    mmStateChanged=true;
  }
  const overview=await api.providerOverview();
  const providers=[];
  for(const id of ids){
    const state=overview.providers.find(entry=>entry.id===id);
    const method=overview.methodStatuses.find(entry=>entry.id===id);
    const item={id,configured:state?.configured===true,enabled:state?.enabled===true,
      maintenance:method?.maintenance??null};
    if(!probe)item.download={state:"not_requested"};
    else if(!item.enabled)item.download={state:"skipped_provider_disabled"};
    else{
      try{
        const bytes=await api.downloadVpnCatalog(id);
        if(!Buffer.isBuffer(bytes)||!bytes.length)throw Error("INVALID_REMOTE_BYTES");
        item.download={state:"received_not_decoded",bytes:bytes.length,
          sha256:createHash("sha256").update(bytes).digest("hex")};
      }catch(error){
        item.download={state:"failed",code:SAFE_ERRORS.has(error?.code)?
          error.code:"LOCAL_CHECK_FAILED"};
      }
    }
    providers.push(item);
  }
  return {mmStateChanged,catalogVersion:overview.catalogVersion,providers};
}

if(process.argv[1]&&fileURLToPath(import.meta.url)===resolve(process.argv[1])){
  try{
    const result=await audit(parseArgs(process.argv.slice(2)));
    process.stdout.write(JSON.stringify(result)+"\n");
    if(result.providers.some(item=>item.download.state==="failed"||
      (item.download.state==="skipped_provider_disabled"&&process.argv.includes("--probe"))))
      process.exitCode=1;
  }catch(error){
    const allowed=new Set(["MM_PREREQUISITES_DISABLED","INVALID_PROVIDER_SELECTION"]);
    process.stderr.write(JSON.stringify({status:"error",code:allowed.has(error?.message)?
      error.message:"OPERATOR_CHECK_FAILED"})+"\n");
    process.exitCode=1;
  }
}
