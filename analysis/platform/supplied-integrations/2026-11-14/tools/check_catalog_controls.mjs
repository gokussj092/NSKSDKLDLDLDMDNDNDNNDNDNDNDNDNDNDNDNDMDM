/** Reproduce the administrative control checks without contacting vendors. */
import {spawnSync} from "node:child_process";
import {mkdirSync,writeFileSync} from "node:fs";
const root=new URL("../../../../../",import.meta.url);
const test="tests/catalog-pending-controls.test.mjs";
const result=spawnSync(process.execPath,["--test","--test-reporter=tap",test],{
  cwd:new URL("cloud/web/",root),encoding:"utf8",timeout:30000,
});
if(result.status!==0){process.stderr.write(result.stderr||result.stdout);process.exit(1);}
const count=key=>Number(result.stdout.match(new RegExp("# "+key+" (\\d+)"))?.[1]);
const proof={schemaVersion:1,scope:"Administrative defaults, persistent overrides and technical availability; no remote decoder validation",
  node:process.version,command:"node --test --test-reporter=tap "+test,
  cwd:"cloud/web",tests:count("tests"),passed:count("pass"),failed:count("fail"),network:false};
if(proof.tests!==5||proof.passed!==5||proof.failed!==0)throw Error("CONTROL_TEST_REPORT_INVALID");
const directory=new URL("../generated/",import.meta.url);mkdirSync(directory,{recursive:true});
writeFileSync(new URL("catalog-controls-proof.json",directory),JSON.stringify(proof,null,2)+"\n");
console.log("Catalog controls: "+proof.passed+"/"+proof.tests+" passed; proof saved.");
