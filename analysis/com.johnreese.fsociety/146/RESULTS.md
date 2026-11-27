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

## What was NOT verified

- No real `.RT` file exported by the app: the Envelope JSON shape is
  oracle-verified, but a real-world export is still unconfirmed.
- No real vmess/vless/trojan link from another app was tested.
- No real legacy (RSE1–RSE4 / C3/C4) file was available; those readers
  are preserved code, not re-verified files.
