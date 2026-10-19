import { jsonReply, unavailable } from "./responses.mjs";
import { settings } from "./c3-config.mjs";
import { ehiConfigured, nurConfigured } from "./c35-provider.mjs";

/** Liveness is not readiness: the Cloud API intentionally cannot decode in C1. */
export function live() {
  return jsonReply({
    apiVersion: "v1",
    service: "spdecode-cloud",
    status: "alive",
    phase: "C1",
  });
}

export function ready() {
  return jsonReply({
    apiVersion: "v1",
    status: "not_ready",
    reason: "DECODER_WORKERS_DISABLED",
  }, 503, { "Retry-After": "60" });
}

export function capabilities() {
  return jsonReply({
    apiVersion: "v1",
    status: "not_ready",
    phase: "C1",
    decodingEnabled: false,
    enabledFormats: [],
    fileDecoderCatalog: { catalogRoutes: 239, additionalSolidRoute: 1, exporterVersionsCertified: 0 },
    textDecodingEnabled: false,
    cloudImportsEnabled: false,
    nurCatalogEnabled: false,
    note: "Las rutas son un inventario, no una certificación ni una habilitación.",
  });
}

export function clientConfig() {
  const active = settings().configured;
  return jsonReply({
    apiVersion: "v1",
    status: active ? "configured" : "not_ready",
    transport: "https",
    androidNativeLibrary: "libspdecode.so",
    minimumClientVersion: null,
    features: { decodeFiles: active, decodeTexts: active, importCloud: active && ehiConfigured(), importCatalog: active, importNurRemote: active && nurConfigured() },
  });
}

/** All privileged flows deny requests before even reading the request body. */
export function disabledEndpoint() {
  return unavailable();
}
