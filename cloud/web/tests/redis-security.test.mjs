import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import {throttle,reserveSlot,releaseSlot} from "../lib/c3-store.mjs";

// CI-only, local disposable Redis. No production URL or credentials are accepted.
function command(args) {return new Promise((resolve,reject)=>{
  const socket=net.connect({host:"127.0.0.1",port:6379});let text="";
  socket.setTimeout(3000,()=>socket.destroy(Error("Redis test timeout")));
  socket.on("error",reject);
  socket.on("connect",()=>socket.write("*"+args.length+"\r\n"+args.map(x=>"$"+Buffer.byteLength(String(x))+"\r\n"+x+"\r\n").join("")));
  socket.on("data",chunk=>{text+=chunk.toString();const end=text.indexOf("\r\n");if(end<0)return;
    if(text[0]===":"||text[0]==="+"){socket.end();resolve(text[0]===":"?Number(text.slice(1,end)):text.slice(1,end));}
    else if(text[0]==="-"){socket.destroy();reject(Error(text));}
  });
});}
const redis={eval:(script,{keys,arguments:args})=>command(["EVAL",script,keys.length,...keys,...args]),
  zRem:(k,id)=>command(["ZREM",k,id])};
const enabled=process.env.REDIS_SECURITY_TEST==="true";
test("atomic throttle remains bounded under concurrent calls and always has expiry",{skip:!enabled},async()=>{
  const key="spsec:test:"+crypto.randomUUID();
  const accepted=await Promise.all(Array.from({length:40},()=>throttle(redis,key,10,60)));
  assert.equal(accepted.filter(Boolean).length,10);assert(await command(["TTL",key])>0);
  await command(["DEL",key]);
});
test("a 61-second live job retains its slot and global capacity covers different sessions",{skip:!enabled},async()=>{
  await command(["DEL","spsec:active:global","spc3:active:lease-test"]);
  try {
    const old=Date.now()-61000;
    for(const id of ["a","b"]){await command(["ZADD","spc3:active:lease-test",old,id]);await command(["ZADD","spsec:active:global",old,id]);}
    assert.equal(await reserveSlot(redis,"lease-test","c"),false);
    await releaseSlot(redis,"lease-test","a");await releaseSlot(redis,"lease-test","b");
    const allowed=await Promise.all(Array.from({length:12},(_,i)=>reserveSlot(redis,"multi-"+i,"job-"+i)));
    assert.equal(allowed.filter(Boolean).length,4);
    for(let i=0;i<12;i++)await releaseSlot(redis,"multi-"+i,"job-"+i);
  } finally {await command(["DEL","spsec:active:global","spc3:active:lease-test"]);}
});
