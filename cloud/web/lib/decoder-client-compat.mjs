/** C15: old APKs cannot display credential prompts added by later releases.
 *
 * Explicit feature negotiation: old clients never send this header, and
 * parsing app-version strings would incorrectly treat custom or stale builds
 * as prompt-aware. This is UX negotiation, NOT an authorization mechanism.
 */
export const CREDENTIAL_PROMPTS_HEADER="x-spdecode-credential-prompts";
export const CREDENTIAL_PROMPTS_VERSION="1";

export function supportsCredentialPrompts(request){
  return request.headers.get(CREDENTIAL_PROMPTS_HEADER)===CREDENTIAL_PROMPTS_VERSION;
}

const legacyProtectedFiles=new Set(["1ftnl","tut"]);
const onefText=["1FTnl.","1FT1.","1ftunnel://1FTnl/","1ftunnel://1FT1/"];
const npvText=["npvt://","npvt-ssh://","npvt-vless://","npvt-vmess://","npv://"];

function isNewProtectedText(text){
  if(typeof text!=="string")return false;
  const value=text.trim();
  return onefText.some(prefix=>value.startsWith(prefix) && value.length>prefix.length) ||
    npvText.some(prefix=>value.toLowerCase().startsWith(prefix) && value.length>prefix.length);
}

/**
 * Return an already-known error code for a legacy APK, or null to keep
 * the actual worker response. Never forge success or retry encryption.
 * The modern worker's precise error remains available for internal metrics.
 */
export function legacyCredentialError(request,kind,payload,workerCode){
  if(supportsCredentialPrompts(request) ||
      !["PASSWORD_REQUIRED","AUTH_FAILED"].includes(workerCode))return null;
  if(kind==="file"){
    // Old SP-DECODE already maps this code to a localized NPVS-specific
    // protection message; the old APK cannot enter a password for NPVS.
    if(payload?.format==="npvs")return "NPVS_PROTECTION_UNSUPPORTED";
    // Old 1FTunnel/Tunneltweak APK routes do not have a credential UI.
    if(legacyProtectedFiles.has(payload?.format))return "UNSUPPORTED_FORMAT";
  }
  if(kind==="text" && isNewProtectedText(payload?.text))
    return "UNSUPPORTED_FORMAT";
  // HTTP Custom and Ultra Custom have preexisting password/HWID dialogs;
  // they must keep PASSWORD_REQUIRED and AUTH_FAILED unchanged.
  return null;
}
