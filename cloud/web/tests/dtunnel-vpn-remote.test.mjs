import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import http2 from "node:http2";
import {EventEmitter} from "node:events";
import {downloadVpnCatalog,providerIds} from "../lib/server-vpn-provider.mjs";

const UUID = "11111111-2222-3333-4444-555555555555";

function environment(t, extra = {}) {
  for (const [key, value] of Object.entries({CLOUD_SERVER_VPN_ENABLED: "true", ...extra})) {
    const old = process.env[key];
    process.env[key] = value;
    t.after(() => { if (old === undefined) delete process.env[key]; else process.env[key] = old; });
  }
}

// A canned unary gRPC response: one DATA frame carrying the protobuf
// {data: "<bytes>"} (field 1, tag 0x0A), trailers grpc-status 0.
function grpcResponse(data) {
  const message = Buffer.concat([Buffer.from([0x0a, data.length]), data]);
  const header = Buffer.alloc(5);
  header[0] = 0;
  header.writeUInt32BE(message.length, 1);
  return Buffer.concat([header, message]);
}

function network(t, payload) {
  const calls = [];
  t.mock.method(dns, "lookup", async () => [{address: "93.184.216.34", family: 4}]);
  t.mock.method(http2, "connect", (authority, options) => {
    calls.push({authority, options});
    const client = new EventEmitter();
    client.destroy = () => {};
    client.request = (headers) => {
      const stream = new EventEmitter();
      stream.close = () => {};
      stream.end = (frame) => {
        calls.push({headers, frame});
        queueMicrotask(() => {
          stream.emit("response", {":status": 200});
          stream.emit("data", grpcResponse(payload));
          stream.emit("trailers", {"grpc-status": "0"});
          stream.emit("end");
        });
      };
      return stream;
    };
    // The pinned lookup must resolve the authority to the vetted IP.
    options.lookup("grpc.dtunnel.com.br", {}, (error, address) => {
      calls.push({lookup: address});
    });
    return client;
  });
  return calls;
}

test("DTunnel VPN is a registered broker provider", () => {
  assert(providerIds().includes("dtunnel-vpn"));
});

test("DTunnel VPN download fails closed without the server secret", async (t) => {
  environment(t);
  const old = process.env.SPDECODE_DTUNNEL_VPN_REQUEST_ID;
  delete process.env.SPDECODE_DTUNNEL_VPN_REQUEST_ID;
  t.after(() => { if (old === undefined) delete process.env.SPDECODE_DTUNNEL_VPN_REQUEST_ID; else process.env.SPDECODE_DTUNNEL_VPN_REQUEST_ID = old; });
  await assert.rejects(() => downloadVpnCatalog("dtunnel-vpn"), {code: "REMOTE_NOT_CONFIGURED"});
  process.env.SPDECODE_DTUNNEL_VPN_REQUEST_ID = "not-a-uuid";
  await assert.rejects(() => downloadVpnCatalog("dtunnel-vpn"), {code: "REMOTE_NOT_CONFIGURED"});
});

test("DTunnel VPN download returns the response data field over mocked gRPC", async (t) => {
  environment(t, {SPDECODE_DTUNNEL_VPN_REQUEST_ID: UUID});
  const calls = network(t, Buffer.from("SYNTHETIC-DATA"));
  const data = await downloadVpnCatalog("dtunnel-vpn");
  assert.deepEqual(data, Buffer.from("SYNTHETIC-DATA"));
  assert.equal(calls[0].authority, "https://grpc.dtunnel.com.br");
  assert.equal(calls.find((c) => c.lookup)?.lookup, "93.184.216.34");
  const request = calls.find((c) => c.headers);
  assert.equal(request.headers[":method"], "POST");
  assert.equal(request.headers[":path"], "/com.app.config.ConfigService/getConfigsV2");
  assert.equal(request.headers["content-type"], "application/grpc");
  assert.equal(request.headers["client-version"], "4.5.8");
  // gRPC frame: 0x00 + length + protobuf {user_id}; the frame carries the UUID.
  assert.equal(request.frame[0], 0);
  assert(request.frame.includes(Buffer.from(UUID, "utf8")));
});
