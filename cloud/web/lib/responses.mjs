/** C1 fail-closed API replies. No authentication, uploads or decoding is enabled. */
const headers = Object.freeze({
  "Cache-Control": "no-store, max-age=0",
  "Pragma": "no-cache",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
});

export function jsonReply(payload, status = 200, extraHeaders = {}) {
  return Response.json(payload, {
    status,
    headers: { ...headers, ...extraHeaders },
  });
}

export function unavailable() {
  return jsonReply(
    {
      apiVersion: "v1",
      status: "unavailable",
      error: {
        code: "CLOUD_NOT_READY",
        message: "El servicio de descifrado aún no está habilitado.",
      },
    },
    503,
    { "Retry-After": "3600" },
  );
}
