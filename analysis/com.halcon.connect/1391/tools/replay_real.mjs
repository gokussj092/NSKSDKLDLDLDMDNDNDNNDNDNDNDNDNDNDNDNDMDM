/** Real bytes + real worker result through Node broker/contract; simulated network. */
import assert from "node:assert/strict";
import fs from "node:fs";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {createHash} from "node:crypto";
import {downloadVpnCatalog} from "../../../../cloud/web/lib/server-vpn-provider.mjs";
import {HALCON_SOURCE} from "../../../../cloud/web/lib/halcon-protocol.mjs";
import {fetchWorker} from "../../../../cloud/web/lib/c3-gateway.mjs";

const [responseFile,recipeFile,workerFile]=process.argv.slice(2);
const real=fs.readFileSync(responseFile),recipe=JSON.parse(fs.readFileSync(recipeFile,"utf8"));
const worker=JSON.parse(fs.readFileSync(workerFile,"utf8"));
process.env.CLOUD_SERVER_VPN_ENABLED="true";
process.env.SPDECODE_HALCON_REQUEST_SECRET=recipe.request_secret;
process.env.SPDECODE_HALCON_CATALOG_PASSWORD=recipe.catalog_password;
process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
const lookup=dns.lookup,request=https.request;
let calls=0;
try {
  dns.lookup=async()=>[{address:"93.184.216.34",family:4}];
  https.request=(url,options,callback)=>{
    assert.equal(url.href,HALCON_SOURCE);assert.equal(options.method,"POST");
    assert.equal(options.rejectUnauthorized,true);
    const req=new EventEmitter();req.destroy=()=>{};
    req.end=body=>queueMicrotask(()=>{
      calls++;
      const stamp=options.headers["X-Timestamp"];
      const digest=createHash("sha256").update(stamp+recipe.request_secret).digest("hex");
      assert.equal(options.headers["X-Auth-Hash"],digest);
      assert.equal(body.toString(),`hash=${digest}&timestamp=${stamp}`);
      const res=new EventEmitter();res.statusCode=200;res.headers={};res.resume=()=>{};
      callback(res);res.emit("data",real);res.emit("end");
    });return req;
  };
  const bytes=await downloadVpnCatalog("halcon-r-net");
  assert.deepEqual(bytes,real);
  const result=await fetchWorker("server-vpn",{providerId:"halcon-r-net",dataBase64:bytes.toString("base64")},
    {workerToken:"synthetic-internal-token-for-replay"},{fetchImpl:async()=>Response.json(worker)});
  const parsed=await result.json();
  assert.deepEqual(parsed.structuredJson,worker.structuredJson);
  assert.equal(parsed.structuredJson.servers.length,101);
  console.log(JSON.stringify({transport:"SIMULATED_HTTP_REAL_BYTES",provider:"halcon-r-net",calls,
    complete_worker_contract_equal:true,version:parsed.structuredJson.version,servers:parsed.structuredJson.servers.length}));
} finally {dns.lookup=lookup;https.request=request;}
