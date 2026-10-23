/** Public file-extension metadata, never decoder implementation. */
import {readFileSync} from 'node:fs';
import {join} from 'node:path';

export function publicFormats(){
  const location=join(process.cwd(),'content','file-formats.json');
  const data=readFileSync(location,'utf8');
  if(data.length>262144)throw Error('FORMATS_SIZE_LIMIT');
  const parsed=JSON.parse(data);
  if(parsed.schemaVersion!==1 || !Array.isArray(parsed.formats) || parsed.formats.length<1 || parsed.formats.length>1024)throw Error('FORMATS_INVALID');
  return parsed.formats;
}
