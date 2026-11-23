# XVEON Tunnel Pro 8.1 — SP-DECODE

Package: `com.xveon.tunnelpro` · version 8.1 (code 8) · minSdk 21, target 36.
APK: 744,015 B, SHA256 `f5d036708185a4c00fbae8174285f8665f8812bf77989072c71bcdd64a06ce29`
(one `classes.dex`, no native libraries, no `assets/`, no `lib/`).

Provider id: `xveon-tunnel-pro` · catalog state: `FILE_ONLY` (no catalog,
no provider card, no broker). Server-side only; no Android change.

## What the app is

A thin, bring-your-own-config tunnel client (own code, heavily obfuscated):
SSH + SlowDNS + Xray (vmess/vless/trojan/ss/socks) + OpenVPN + UDP Custom,
with HTTP/WS payloads, rotating proxy, SNI/TLS, UDPGW and Shizuku support.
It has **no built-in server catalog**: no catalog URL, API host, Firebase,
ads or billing SDK exists anywhere in the DEX strings or resources. Server
lists only arrive as **user-supplied V2Ray/Xray subscription URLs** or as
imported configs. There are no premium tiers, no VIP catalog and no
in-app purchase in this build.

## Format: `.xveon` / `.xvn` files and `xveontunnel://` links

```
xveontunnel://XVN1:<flag>:<base64 salt 16 B>:<base64 IV 12 B>:<base64 ciphertext>
flag "0" = unlocked, "1" = creator-locked (password, first 15 chars used)
```

- Key: PBKDF2-HMAC-SHA256, 10,000 iterations, 32 bytes. The passphrase is
  built from three fixed app constants plus `"::"` plus the password
  (empty when unlocked). The constants are stored obfuscated in the DEX
  (`Lb1` string table) and are deobfuscated at runtime by `xveon.py`.
- Cipher: AES-256-GCM, 128-bit tag, AAD = `"XVN1:<flag>"`.
- Plaintext: GZIP-compressed JSON envelope (v2) with `creator`, `locked`,
  hide flags, `expiryTimestamp`, `creatorNote` and `profiles[]`.
- A `.xveon`/`.xvn` file contains exactly the same 5-part string (the
  `xveontunnel://` prefix is optional). The app also accepts the
  `xveon://` and `xvn://` prefixes.
- The app imports only `profiles[0]`; this decoder returns all profiles
  present in the envelope.

## Verification status

- **VERIFIED_REAL** — a real `xveontunnel://` link supplied by Pedro
  decrypts with this decoder to a v2 envelope with 1 SSH profile
  (SSH + payload + rotating proxy + SNI, TLS 1.3). The link's host,
  username and password are NOT reproduced in this README; they appear
  only in the decoder's output and in the internal evidence dossier.
- **VERIFIED_SYNTHETIC** — `xveon://` / `xvn://` prefixes and
  `.xveon` / `.xvn` files: same 5-part string as the link body
  (same code path, `Lb0.Il11` / `Lb0.I0O0`); round-trip
  encode → file → decode is verified by `--self-test` and by
  `tests/test_xveon.py`. No real `.xveon` file has been supplied yet.
- Live catalog: **NOT APPLICABLE** — the app ships no catalog endpoint.
  `xveon_catalog.py` (local only, NOT wired into the repo) implements
  the app's real mechanism (user-supplied subscription URL) and reports
  FAILED instead of inventing servers when a URL returns nothing
  parseable. There is no repo precedent for wiring a user-URL fetcher
  as a catalog, and the worker never fetches a user-supplied URL.
- Premium: none found in this build (no tiers, no premium catalog).

## Files

| File | What it is |
|---|---|
| `xveon.py` | Original decoder + encoder for `xveontunnel://` links and `.xveon`/`.xvn` files, kept verbatim. `--self-test` runs 6 checks. |
| `file_decoder.py` | Thin worker adapter over `xveon.py`: `decode(raw, password)` (supplied-bridge route), `run(bytes)` (engine file route), `decode_text(str)` (text-bridge route), plus the standalone CLI. |
| `manifest.json` | Integration manifest (provider, format, icon hash, no-catalog note). |
| `requirements.txt` | `pycryptodome==3.23.0` (`cryptography` is an accepted alternative for AES-GCM). |
| `README.md` | This file. |
| `TESTING.md` | How to run the checks. |

## Usage

```bash
python3 xveon.py decode 'xveontunnel://XVN1:0:...' [--password PW] [--summary] [--redact]
python3 xveon.py decode file.xveon [--password PW]
python3 xveon.py encode envelope.json [--password PW] [--out out.xveon]
python3 xveon.py --self-test
python3 file_decoder.py file.xveon            # engine CLI (password JSON on stdin)
python3 file_decoder.py < file.xveon           # stdin data, no password
```

Python 3.8+; `cryptography` or `pycryptodome` for AES-GCM
(`hashlib.pbkdf2_hmac` is stdlib).

## Registry wiring (applied by the coordinator; see `edits-xveon.md`)

- `cloud/web/content/file-formats.json`: `xveon` + `xvn`
  (`XVEON Tunnel Pro 8.1`, `credentialFields: ["password"]`,
  `offlineSupported: false`, `cloudSupported: true`).
- `cloud/web/content/text-formats.json`: `xveontunnel://`, `xveon://`,
  `xvn://` (suffix `xveon`, kind `text`).
- `cloud/web/content/supplied-integrations.json`: `xveon-tunnel-pro`
  (`FILE_ONLY`, `fileModule: file_decoder.py`, `requests: []`).
- `cloud/workers/python/engine.py`: `_C8_FILE_ENGINES` entries for
  `xveon`/`xvn` + `password` allowlisted for both suffixes in
  `decode_file` and for the three schemes in `decode_text`.
- `cloud/workers/python/text_bridge.py`: explicit dispatch for the
  three schemes + password gate for them in `main()`.
- `cloud/web/lib/supplied-integrations.mjs`: inventory count pin
  82 → 83.
- `cloud/web/tests/text-format-catalog.test.mjs`: file-format count pin
  279 → 281.
- `cloud/web/public/server-vpn-icons/xveon-tunnel-pro.png`: app icon.

No change to `server-vpn-catalog.mjs` (no card: `FILE_ONLY` items are
excluded from `SUPPLIED_CATALOG_ITEMS`), no `CATALOG_VERSION` bump
here (the coordinator bumps it once to 98 for the whole batch), no
change to `c3-gateway.mjs`, `server-vpn-provider.mjs`,
`catalog_vpn_bridge.py`, `switches.json`, `decoders.json` or `android/`.

## Evidence dossier

`analysis/com.xveon.tunnelpro/8/` (ANALYSIS.md, EVIDENCE.md, METHOD.md,
RESULTS.md, REPRODUCE.md, MANIFEST.json, tests with pytest). Local only —
nothing pushed to Git, nothing integrated into the repo until this batch.
