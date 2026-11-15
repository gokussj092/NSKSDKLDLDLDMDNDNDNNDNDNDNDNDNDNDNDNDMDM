/** Independent Node UTF-8/JSON reference; no imports from production code. */
import fs from "node:fs";
const data=fs.readFileSync(process.argv[2]);
const doc=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(data));
if(doc?.success!==true||!Array.isArray(doc.servers)||!doc.servers.length)throw Error("schema");
process.stdout.write(JSON.stringify(doc));
