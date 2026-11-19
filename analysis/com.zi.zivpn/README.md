# com.zi.zivpn — ZIVPN Tunnel

| Build | Version | Observed | Status | Scope |
| --- | --- | --- | --- | --- |
| 184 | 2.2.5 | 2026-11-14/15 (online dossier) | PARTIAL | Catalog (live, VERIFIED_REAL), files (synthetic), text (no own scheme in APK), export pending |
| 184 | 2.2.5 | 2026-11-18/19 (this dossier) | PARTIAL | **Offline app**: `.ziv` files + `zivpn://` text, native C++ (synthetic-verified); catalog out of scope |

The 2026-11-14/15 online dossier (`analysis/com.zi.zivpn/184/` in the
online branch) is the research basis: the `.ziv` format (LF1 + DES +
Properties XML, export/import asymmetry) and the live catalog. This
offline dossier adapts it for the offline Android app: the same build
(2.2.5 / 184, confirmed still current on Google Play 2026-11-19), a
native decoder in `android/app/src/main/cpp/spdecode_zivpn.cpp`, and its
own synthetic test evidence. The catalog is deliberately NOT ported to
the offline app.

Open items (both dossiers): a real `.ziv` exported by the app, a real
`zivpn://` link.
