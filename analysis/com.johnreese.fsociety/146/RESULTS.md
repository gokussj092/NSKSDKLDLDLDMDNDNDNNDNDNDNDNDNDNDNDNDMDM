# Results — REESE TUNNEL 3.23.28 (build 146)

## Status: VERIFIED (files + texts) / VERIFIED_ABSENT (catalog)

| Check | Result |
| --- | --- |
| Catalog | VERIFIED_ABSENT — no catalog URL/endpoint/list in DEX, strings, or assets |
| RSE5 0xC6 vs native oracle | 36/36 checks PASS (batch 15, `test_oracle.py`) |
| Staged script selftest | OK (re-run 2026-11-27) |
| Synthetic sample `sample_synthetic.rt` | Opens with HWID `ABC-123` / password `test123` (engine CLI, subcommand CLI, and `decode()` all verified) |
| Text parsers | vmess/vless/trojan/JSON verified with synthetic links (selftest + CLI) |
| Legacy readers (C3/C4, RSE1–RSE4) | Preserved from the 3.23.12 script; negative paths verified (truncated RSE1 header → clean error); no real legacy file in this batch |
| Synthetic unit tests | `python3 analysis/com.johnreese.fsociety/146/tests/test_method.py -v` — 8 tests, all OK |

## Synthetic unit tests (run 2026-11-27)

```bash
python3 analysis/com.johnreese.fsociety/146/tests/test_method.py -v
```

Expected: 8 tests OK (sample opens via `decode()`, wrong password →
error 4, missing credentials → error 2/3, bad magic → error 1,
truncated legacy header → clean error, vless/trojan/vmess synthetic
parsing, `.reese` engine entry presence is checked in the fragment).

## Negative / boundary cases

- Wrong password or wrong HWID → native error 4 (auth failure).
- Missing HWID on an HWID-only file → error 3; missing password on a
  password file → error 2.
- Garbage bytes → error 1 (bad format); `run()` returns None.
- Extra HWID on a password-only file is ignored (opens); extra password
  on an HWID-only file breaks the key (error 4) — both per the native
  rule, verified in the selftest.
- A profile with a device-local vault is refused (needs the original
  Android Keystore).

## Update 2026-11-28 — lote 20: two real `.RT` files VERIFIED_REAL + decoder fix

Two real `.RT` files exported by REESE TUNNEL 3.23.28 were verified
in lote 20 (batch work dir `~/workspace/batch20-work/reese-rt/`):

| File | Size | Result |
| --- | --- | --- |
| `Airtel_5_______0_rc5x.RT` | 313,456 B | Opens with the export password; complete profile (Airtel Kenya, SSH `indo.dewi-wulan.biz.id:80`, user `Popkid`, proxies `cdn-cf.zoom.us:80` and `listen.noice.id:80`) |
| `100mbs_Airtel_4___1_fny4.RT` | 321,393 B | Opens with the export password; same profile shape |

- **Format:** RSE5 0xC6, PBKDF2 600,000 iterations, AES-256-GCM,
  AAD 34 B header. Both files are password-sealed (flags=2); without
  a password the decoder correctly answers `PASSWORD_REQUIRED`.
- **The export password is NOT recorded in this dossier** (per the
  standing rule: passwords are never written into scripts or
  dossiers; it was delivered to Pedro in chat only).
- **Both files expire 2026-11-30 ~08:59 UTC** (the size ~313–321 KB
  is random RSE5 padding + a JPEG banner).
- **What was NOT verified is now verified:** the "no real `.RT`
  file" gap from the previous section is closed for RSE5. Legacy
  readers (RSE1–RSE4 / C3/C4) remain synthetic-verified only.

### Decoder fix (lote 20, pending authorization)

The repo decoder had two real bugs, fixed in the batch script
`~/workspace/batch20-work/reese-rt/reese_rt_fixed.py` (the fix is
NOT yet integrated into the repo — it is staged here as a note
only):

1. **Unified `PASSWORD_REQUIRED`:** all paths now return
   `{"workerError": "PASSWORD_REQUIRED"}` with exit code 3 (before,
   some paths returned a different error).
2. **stdin hang fixed:** the "engine" form of the repo decoder
   blocked forever reading stdin without EOF (hung >125 s). The
   fixed script reads stdin only if data is available (select
   timeout 0).
3. **`config.bannerImage` ignored:** the banner is a base64 JPEG
   (~29 KB), not needed; `bannerImageEnabled` is kept. The
   `.descifrado.json` outputs were regenerated (56 fields, was 57).
4. **`APK_SIGNER_SHA256` corrected:** the repo constant
   (`D834BF8D…`) does not match the real APK signing certificate
   (`C7662695…` = SHA-256 of the real certificate, recorded in
   `meta.signer`). Only the legacy C3/C4 path is affected.

Verification of the fixed script: `reese_rt_fixed.py selftest` OK;
outputs identical to the repo decoder with the same password.

No new dossier was created (this is not a new app version); only
this RESULTS.md is updated. No tools are copied for REESE in this
dossier (out of scope for the lote-20 fix note).

## What was NOT verified

- No real `.RT` file exported by the app: the Envelope JSON shape is
  oracle-verified, but a real-world export is still unconfirmed.
- No real vmess/vless/trojan link from another app was tested.
- No real legacy (RSE1–RSE4 / C3/C4) file was available; those readers
  are preserved code, not re-verified files.
