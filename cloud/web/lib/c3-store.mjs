import { createHash } from "node:crypto";
import { settings } from "./c3-config.mjs";
let promise;
export async function store() {
  if (!settings().configured) throw Error("C3_NOT_CONFIGURED");
  if (!promise) {
    promise = import("redis").then(async ({ createClient }) => {
      const client = createClient({ url: settings().redisUrl, socket: { connectTimeout: 3000, reconnectStrategy: false } });
      client.on("error", () => {}); // Do not log Redis URLs or private sessions.
      await client.connect();
      return client;
    }).catch(error => { promise = undefined; throw error; });
  }
  return promise;
}
const digest = data => createHash("sha256").update(data).digest("hex");
export function ipKey(request) {
  // ONLY trusted Nginx is permitted to supply X-Real-IP. It must overwrite
  // incoming headers. Missing/invalid values share a global restrictive pool.
  const source = request.headers.get("x-real-ip") || "unknown";
  const ip = /^[a-fA-F0-9.:]{3,45}$/.test(source) ? source : "unknown";
  return digest("spdecode-ip:v1:" + ip);
}
export async function throttle(redis, key, limit, seconds) {
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, seconds);
  return count <= limit;
}
export async function reserveChallenge(redis, id, nonce, ip) {
  const value = JSON.stringify({ nonce, ip, created: Date.now() });
  return (await redis.set("spc3:challenge:" + id, value, { EX: 120, NX: true })) === "OK";
}
export async function consumeChallenge(redis, id, ip) {
  const raw = await redis.getDel("spc3:challenge:" + id);
  if (!raw) return null;
  const parsed = JSON.parse(raw);
  if (parsed.ip !== ip || Date.now() - parsed.created > 120_000 || parsed.created > Date.now() + 5000) return null;
  return parsed;
}
export async function rememberSession(redis, jti, exp) {
  return (await redis.set("spc3:session:" + jti, "1", { EX: Math.max(1, exp - Math.floor(Date.now()/1000)), NX: true })) === "OK";
}
export async function sessionExists(redis, jti) {
  return (await redis.get("spc3:session:" + jti)) === "1";
}
/* Redis Lua ensures that at most 2 C3 worker requests per session run at
 * the same time, including if multiple Next.js instances are serving traffic.
 * Every lease has a TTL so a crash cannot hold the slot indefinitely.
 */
const reserveScript = `
local key = KEYS[1]
local value = ARGV[1]
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', key, '-inf', tonumber(ARGV[3]))
if redis.call('ZCARD', key) >= limit then return 0 end
redis.call('ZADD', key, ARGV[4], value)
redis.call('EXPIRE', key, 60)
return 1
`;
export async function reserveSlot(redis, jti, requestId) {
  return (await redis.eval(reserveScript, {
    keys: ["spc3:active:" + jti],
    arguments: [requestId, "2", String(Date.now() - 60000), String(Date.now())],
  })) === 1;
}
export async function releaseSlot(redis, jti, requestId) {
  await redis.zRem("spc3:active:" + jti, requestId);
}
