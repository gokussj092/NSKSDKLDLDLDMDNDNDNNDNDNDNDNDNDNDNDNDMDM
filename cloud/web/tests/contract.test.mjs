import assert from "node:assert/strict";
import { test } from "node:test";
import { capabilities, clientConfig, disabledEndpoint, live, ready } from "../lib/public-contract.mjs";
import {
  GET as healthRoute,
} from "../app/api/v1/health/route.js";
import { GET as readyRoute } from "../app/api/v1/ready/route.js";
import { GET as capabilitiesRoute } from "../app/api/v1/capabilities/route.js";
import { GET as configRoute } from "../app/api/v1/config/route.js";
import { POST as fileRoute } from "../app/api/v1/decode/file/route.js";
import { POST as textRoute } from "../app/api/v1/decode/text/route.js";
import { POST as cloudImportRoute } from "../app/api/v1/decode/import/cloud/route.js";
import { POST as catalogImportRoute } from "../app/api/v1/decode/import/catalog/route.js";
import { POST as sessionRoute } from "../app/api/v1/session/route.js";
import { POST as jobsRoute } from "../app/api/v1/jobs/route.js";
import { GET as jobRoute, DELETE as cancelJobRoute } from "../app/api/v1/jobs/[id]/route.js";

test("health is alive but readiness stays explicitly unavailable", async () => {
  const health = healthRoute();
  assert.equal(health.status, 200);
  assert.equal((await health.json()).status, "alive");
  assert.equal(health.headers.get("cache-control"), "no-store, max-age=0");
  const readiness = readyRoute();
  assert.equal(readiness.status, 503);
  assert.equal((await readiness.json()).status, "not_ready");
  assert.equal(readiness.headers.get("x-content-type-options"), "nosniff");
});

test("capabilities never suggest Android catalog means cloud support", async () => {
  const result = capabilitiesRoute();
  const data = await result.json();
  assert.equal(data.decodingEnabled, false);
  assert.deepEqual(data.enabledFormats, []);
  assert.equal(data.fileDecoderCatalog.catalogRoutes, 239);
  assert.equal(data.fileDecoderCatalog.additionalSolidRoute, 1);
  assert.equal(data.fileDecoderCatalog.exporterVersionsCertified, 0);
  assert.equal(data.textDecodingEnabled, false);
  assert.equal(data.nurCatalogEnabled, false);
});

test("public config includes libspdecode.so but no credentials or internal URL", async () => {
  const result = configRoute();
  assert.equal(result.status, 200);
  const data = await result.json();
  assert.equal(data.androidNativeLibrary, "libspdecode.so");
  assert.equal(data.transport, "https");
  assert.ok(!JSON.stringify(data).includes("decoder-worker"));
  assert.ok(!JSON.stringify(data).includes("secret"));
});

test("every future decoding/auth/job endpoint fails closed with 503", async () => {
  for (const action of [
    fileRoute, textRoute, cloudImportRoute, catalogImportRoute,
    sessionRoute, jobsRoute, jobRoute, cancelJobRoute,
  ]) {
    const result = action();
    assert.equal(result.status, 503);
    assert.equal(result.headers.get("retry-after"), "3600");
    const data = await result.json();
    assert.equal(data.error.code, "CLOUD_NOT_READY");
  }
});

test("responders ignore payloads; no decoder dispatch exists in C1", async () => {
  assert.equal((await disabledEndpoint().json()).error.code, "CLOUD_NOT_READY");
  assert.equal(live().status, 200);
  assert.equal(ready().status, 503);
  assert.equal(clientConfig().status, 200);
  assert.equal(capabilities().status, 200);
});
