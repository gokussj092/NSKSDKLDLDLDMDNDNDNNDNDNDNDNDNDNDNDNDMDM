import {isDeepStrictEqual} from "node:util";

const record=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);

// A complete authenticated revision-57 document may preserve one opaque slot.
// This exception never permits a truncated result or arbitrary partial route.
export function allowsHcPartial(kind,payload,result){
  if(kind!=="file"||payload?.format!=="hc"||result?.format!=="hc"||
     result.isPartial!==true||!Array.isArray(result.warnings)||
     result.warnings.length!==1||result.warnings[0]!=="HC_UNRESOLVED_FIELDS")return false;
  const report=result.structuredJson,config=report?.Config,metadata=report?.Metadata;
  if(!record(report)||!record(config)||Object.keys(config).length!==32||
     Object.values(config).some(x=>typeof x!=="string")||!record(report.Protections)||
     !record(metadata)||!record(metadata.envelope)||!record(metadata.config)||
     metadata.envelope.verCfg!==57||![564,565].includes(metadata.config.verApp)||
     !/^[0-9a-fA-F]{32}$/.test(config.psiphon))return false;
  if(!isDeepStrictEqual(report.UnresolvedFields,[{index:17,field:"psiphon",status:"encrypted_unresolved"}]))return false;
  try{return isDeepStrictEqual(JSON.parse(result.rawText),report);}
  catch{return false;}
}
