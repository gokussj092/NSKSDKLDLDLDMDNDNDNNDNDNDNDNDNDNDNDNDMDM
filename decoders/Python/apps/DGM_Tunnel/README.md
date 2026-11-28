# DGM Tunnel 15.11.2026 — rotating public-feed catalog (CAT 103)

- **App:** DGM Tunnel, package `com.dgmtunnel.app`, versionCode 17,
  versionName 15.11.2026.
- **Catalog (live):** the app's "free servers" list is a public
  plain-text subscription feed, not an encrypted endpoint:
  `GET https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt`
  with `User-Agent: DGMTunnel/1.5`, 15 s timeouts, no redirects.
  The app parses the first 500 profiles, filters, dedupes and takes
  the first 40.
- **Rotating feed, no catalog version:** the feed changes daily, so
  a later re-fetch returns a different 40. The snapshot is
  identified by `fetched_at`, not by a version number. This is the
  app's own behaviour. Precedent: Sentinel Tunnel (CAT 102) is also
  a public rotating feed (VPNGate) served as a card.
- **Live verification 2026-11-28:** feed 8,880 lines / 8,873 entries,
  500 parsed, 57 rejected, 40 profiles, all Shadowsocks (10:05 UTC);
  re-run 11:12 UTC reproduced the identical 40 (only `fetched_at`
  differs).
- **Bridge:** `server_catalog_decoder.run(bytes)` decodes
  broker-downloaded feed bytes (no network in `run()`).
  `dgm_tunnel.py` also decodes links/files and sealed
  `DGMTUNNEL_SHARE` v2 shares; those file/text routes are delivered
  here but NOT wired in this catalog-only delivery.
- **Icon:** `dgm-tunnel.png`, 512×512.
