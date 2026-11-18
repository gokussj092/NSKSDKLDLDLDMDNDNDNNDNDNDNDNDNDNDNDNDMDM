import test from "node:test";
import assert from "node:assert/strict";
import {reserveSlot} from "../lib/c3-store.mjs";
import {workBudget} from "../lib/device-security.mjs";

// No live Redis or user identifiers. These results mirror the atomic Lua
// contract (1 = granted, 0 = this session full, -1 = global workers full).
const slotRedis = result => ({
  eval: async (_script,{keys,arguments:args}) => {
    assert.deepEqual(keys[1],"spsec:active:global");
    assert.equal(args[1],"2");
    assert.equal(args[5],"4");
    return result;
  },
});

test("an available decode slot remains usable",async()=>{
  assert.equal(await reserveSlot(slotRedis(1),"session-a","job-a"),true);
});

test("a session occupying its own slots is rate-limited independently",async()=>{
  assert.equal(await reserveSlot(slotRedis(0),"session-a","job-b"),false);
});

test("other sessions occupying global worker capacity never count as personal rate abuse",async()=>{
  await assert.rejects(reserveSlot(slotRedis(-1),"new-session","job-c"),{
    code:"ENGINE_UNAVAILABLE"
  });
});

test("global work budget exhaustion is a transient service-capacity error",async()=>{
  const seen=[];
  const redis={eval:async (_script,{keys})=>{
    seen.push(keys[0]);
    return keys[0]==="spsec:work:global"?121:1;
  }};
  await assert.rejects(workBudget(redis,{key:null}),{code:"ENGINE_UNAVAILABLE"});
  assert.deepEqual(seen,["spsec:work:global"]);
});

test("global work budget under capacity accepts anonymous-account devices",async()=>{
  const redis={eval:async()=>1};
  assert.equal(await workBudget(redis,{key:null}),true);
});
