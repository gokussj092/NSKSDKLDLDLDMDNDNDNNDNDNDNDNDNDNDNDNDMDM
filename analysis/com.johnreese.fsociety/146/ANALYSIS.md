# REESE TUNNEL 3.23.28 — re-analysis (build 146)

- **App:** REESE TUNNEL 3.23.28, versionCode 146, package
  `com.johnreese.fsociety`, 40.2 MB
- **APK:** `REESE_TUNNEL_3.23.28_1_s3ua.apk`, SHA-256
  `b45dd9993e973f62fbd80cf39f108f07e3445dd5dbd689d59082c1d3939b5dee`
- **Date:** 2026-11-27. **Base:** 3.23.12 / vc 129, already in the repo.
- **Result:** the file format is a NEW RSE5 variant (0xC6); the repo
  script's C3/C4 + legacy readers are preserved, not dropped.

## 1. No catalog — VERIFIED_ABSENT

Reese Tunnel has no server catalog. Evidence (all verified in the APK,
not inferred):

- The string "catalog" does not appear in `dex_strings.txt` (27,156
  lines); no catalog URL, endpoint, or server list in assets (only
  `dexopt`, `geoip*.dat`, `geosite.dat`, `slowdns`, `vault_cover.jpg`).
- The only URLs in the DEX are the update check
  `https://raw.githubusercontent.com/REESETUNNEL/REESE-TUNNEL/main/latest.json`
  (versionCode 146 / versionName 3.23.28 / release notes only), the
  GitHub releases page, `https://reesetunnel.com`, WhatsApp/Telegram
  links, and connectivity-check URLs.
- Web search 2026-11-27 found no Reese Tunnel server catalog.
- The app is a **user-config client** (like HTTP Custom): the user types
  their own SSH host/user/password, payload, SNI and proxy, or pastes
  V2Ray profiles; it also has SlowDNS and UDP-Custom. DEX strings:
  "Add a V2Ray server first", "SSH target (host:port@user:pass)",
  "Proxy (server.com:80 or any port)".

Consequence: no catalog card, no broker, no supplied `requests`. The
deliverable is the `.RT`/`.reese` file decoder + the text-link parsers
+ the 16 built-in payload preset templates (recorded in the batch
`catalogo-completo.json`, which has `"catalog": null`, `"servers": []`).

## 2. What changed vs 3.23.12 — the RSE5 diff

The repo script (3.23.12) reads RSE5 **C3/C4** variants plus legacy
RSE1–RSE4. The 3.23.28 native library (`librse5.so`, `rse5Seal`
0x2696c / `rse5Open` 0x25e10) speaks a **different RSE5 variant, 0xC6**:

| Aspect | Repo 3.23.12 (C3/C4) | 3.23.28 (0xC6, this build) |
| --- | --- | --- |
| Version byte | 0xC3 / 0xC4 | **0xC6** |
| PBKDF2-HMAC-SHA256 iters | 32,768 | **600,000** |
| Flags | up to 7 (bit 4 = APK-signer binding) | **1–3 only** (1 = HWID, 2 = password, 3 = both) |
| Key material | `REESE-CUSTOM/RSE5\|<hwid>\|<password>[|SIG:<signer>]` | `REESE-CUSTOM/RSE5\|<hwid>\|<password>` (no signer slot) |
| Salt / nonce | 16 B / 12 B (same layout) | 16 B / 12 B (same layout) |
| Cipher | AES-256-GCM, AAD = 34-byte header (same) | AES-256-GCM, AAD = 34-byte header |
| Error codes | Script-level strings (`HWID_REQUIRED`, `AUTH_FAILED`, …) | **Native codes 1–6** (1 bad format, 2 password missing, 3 HWID missing, 4 auth failure, 5 seal without credentials, 6 wrong device) |
| Open key rule | HWID slot always the supplied HWID (when flags&1); password slot when used | HWID slot only when flags&1 (extra HWID on a password-only file is IGNORED); password slot ALWAYS the supplied password (extra password on an HWID-only file breaks the key → 0x04) |
| Padding | `[1B v] + rand(v+16) + BE32(len) + data + rand` (repo `_unpad_random`) | Same shape; **correction 2026-11-27:** the first byte is `nextInt(256)`, not `16 + nextInt(256)` (verified in `ReeseFile.g`) |
| Interior | Envelope JSON → raw DEFLATE(1) → pad → seal (same) | Same |

The 0xC6 method was verified **byte-identical against the native
oracle** (Unicorn, `dbg6.FastEmu`, `test_oracle.py`): **36/36 checks
PASS** — Python sealing == oracle sealing (same salt/nonce), flags 1/2/3,
both-direction opens, full Envelope round-trip, deterministic vector
(header `a719d24cc602...`, salt `e13b032e112a32b579080f08b1f7ed4c`,
110 bytes for 60 bytes of text), and the full native error-code matrix
(1–6).

**Merge decision (this patch):** the staged script is the new 0xC6
implementation **plus the repo's C3/C4 and RSE1–RSE4 readers preserved
as fallback** (never drop old versions). The legacy paths are carried
over from the repo script, not re-verified against a real legacy file
in this batch. The staged script also keeps the engine-compatible
`decode()` / `run()` entry points and the positional-file CLI
(`reese_tunnel.py <file> [--hwid] [--password-file|--ask-password]`,
credentials also accepted as JSON on stdin), which the analyst's
subcommand-only CLI (`file` / `text` / `seal` / `selftest`) did not
provide — both CLI forms are supported.

## 3. Files verified (.RT / .reese)

- Envelope: `{"meta": {...13 fields...}, "config": {...57 fields...}}`
  with `v2rayProfiles` (22 fields per profile). The script includes the
  Kotlin-constructor field orders for sealing new Envelopes.
- Sample: `test_sample.rt` (269,189 bytes; sealed by the script, HWID
  `ABC-123`, password `test123`; open with
  `reese_tunnel.py file test_sample.rt --hwid abc-123 --password test123`).
  It is synthetic (TEST-NET `203.0.113.10`, `user1` / `s3cret`,
  `example.com`) and is included as `tests/fixtures/sample_synthetic.rt`.
- Kotlin import checks after open (`ReeseFile.k`): `Meta.hwid` must match
  the supplied HWID (trim, case-insensitive); `Meta.expiresAt` is
  enforced; `config.allowedHwids` must contain the HWID (uppercased).
- `.reese` suffix added alongside `.rt` (same script; the manifest
  intent filters list `.RT` / `.rt` / `.reese`, MIME
  `application/x-reese`).

## 4. Texts verified (vmess / vless / trojan / JSON)

Parser `Lb7/x` reimplemented and tested with synthetic samples:

- `vmess://` (base64 JSON) → VMESS profile.
- `vless://uuid@host:port?query#remark` → VLESS profile.
- `trojan://pass@host:port?query#remark` → TROJAN profile (password in
  the `id` field).
- V2Ray JSON with `outbounds` (vmess/vless/trojan, `vnext`/`servers`,
  `streamSettings`, `tlsSettings`/`realitySettings`) → first valid profile.
- Base64 blob (JSON or link) and the app's exact error messages
  ("Nothing pasted.", "Unknown format. Paste vmess://, vless://,
  trojan:// links or a JSON config", "The vless link is missing the
  '@'...").
- **No own scheme:** the app defines no `reese://`; vmess/vless/trojan
  are paste-only, not intent filters. No new text-format entries are
  needed (vmess/vless/trojan are already registered).

Verified bytecode quirks (documented in the script): in vless/trojan
links `security` is always `"aes-128-gcm"` (the parameter only decides
TLS); `allowInsecure` is `params["allowInsecure"] != "0"` (absent counts
as True); `transportKey` is `seed` or `key`; in JSON vmess the cipher
is normalized by `i()`: `chacha20-poly1305` stays, anything else →
`aes-128-gcm`.

## 5. Password/HWID handling

Reuse of the existing internal flows: the engine passes credentials as
JSON on stdin (the staged script reads them when piped) or via
`--password-file` / `--ask-password` on the CLI. No auth function from
the newly supplied script is used for anything else. Note: the engine
currently does not plumb HWID/password credentials for the `rt`/`reese`
suffixes (same limitation as the 3.23.12 script) — protected files open
via the CLI or via a future engine plumbing change, not via this patch.

## HMAC audit

No HMAC observed for file/text integrity, transport MAC, or connection
authentication in the reviewed material. The RSE5 format authenticates
with an AES-GCM tag; HWID/password binding is by PBKDF2 key derivation,
not HMAC. The Kotlin import checks are application-level checks after
decryption.
