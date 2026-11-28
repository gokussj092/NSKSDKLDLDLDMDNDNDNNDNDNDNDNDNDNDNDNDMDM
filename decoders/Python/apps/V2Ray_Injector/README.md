# V2Ray Injector 1.4.2 — server catalog (CAT 103)

- **App:** V2Ray Injector ("v2ray injector", V2K), package
  `tech.docnet.xraytunnel`, versionCode 16, versionName 1.4.2.
- **Catalog (live):** `GET
  https://xraytunnel-config.admin6795.workers.dev/api/config` with
  `Accept: application/json`, `User-Agent: XrayTunnel/1.0` and the
  app's fixed `X-API-KEY` header. `servers` and `configs` are
  AES-256-GCM envelopes (`base64(IV).base64(ct+tag)`, fixed 32-byte
  app key). Result: version, catalogSource, catalogReleaseId,
  catalogSnapshotId, timestamp, servers, configs — no download APIs.
- **Live verification 2026-11-28:** Version 1.0.0, 1,233 servers,
  63 configs (08:28); re-run 11:10: 1,216 servers, 63 configs, same
  release/snapshot ids — the live feed churns; configs byte-identical.
- **Bridge:** `server_catalog_decoder.run(bytes)` decodes a
  broker-downloaded response (no network in `run()`).
  `v2ray_injector.py` also decodes `.v2k` files, Xray JSON and
  vmess/vless/trojan/ss links; those file/text routes are delivered
  here but NOT wired in this catalog-only delivery.
- **Icon:** `v2ray-injector.png`, 432×432 (foreground of the adaptive
  launcher icon; no 512×512 raster exists in the APK).
