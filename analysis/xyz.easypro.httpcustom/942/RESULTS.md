# Results — offline n19 port (build 942), 2026-11-27

Status: **PARTIAL** — implemented and host-verified as below; not yet
verified on-device, and the real password-protected sample still needs a
positive open with the correct password supplied at runtime.

## Environment actually used

- Host: Linux x86_64, g++ 13.3.0, CMake 3.28.3.
- Harness: direct g++ build of the exact production sources
  (`spdecode_http_custom.cpp.new` as `spdecode_http_custom.cpp` +
  `spdecode_http_custom_legacy.cpp` from remote head f75c6751…) with
  Mbed TLS 3.6.7 (prebuilt static lib from the earlier n15 harness build,
  SHA-256 pinned `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`),
  nlohmann/json 3.11.3 headers (deb in apt cache) and system libargon2
  (reference implementation). `-Wall -Wextra -Werror`, clean build, exit 0.
- Reference oracle: `tools/ref_oracle/codec.py` via
  `/home/hatch/workspace/http-custom-update/venv/bin/python`
  (CPython 3.12.3, PyCryptodome 4.4.0, argon2-cffi 25.1.0).
- No Android SDK/NDK exists in this VM (`ANDROID_NDK_HOME` unset):
  **no Gradle build and no on-device test were possible**. The system
  libmbedtls-dev here is 2.28.8, whose API is incompatible with the
  production code (targets Mbed TLS 3.6.7); the prebuilt 3.6.7 static
  library was used instead.

## Real samples — host harness vs Python reference (8/8 checks)

Runner: `tools/run_real_checks.py` (exit 0).

| File | Result (C++ harness, new) | Original binary |
| --- | --- | --- |
| test_open_2_7xqg.hc (4,529 B) | OPEN, 2 profiles, **full JSON MATCH** vs Python reference, `app_version` 8.1.5 (942), banner `{"version": 1, "style": "custom", "content": "annsksk"}` | `HC_UNRECOGNIZED_FORMAT` (no n19) |
| test_bloqueo_normal_1_aflj.hc (4,935 B) | OPEN, 2 profiles, **full JSON MATCH**, same banner | `HC_UNRECOGNIZED_FORMAT` |
| test_bloqueo_normal_con_contrase_a_0_m46a.hc (4,981 B) | `PASSWORD_REQUIRED` (no password); `AUTH_FAILED` (wrong password) — matches reference behaviour | `HC_UNSUPPORTED_SCHEMA` |
| test_solo_whid_1_7zzx.hc (n16) | `HC_UNSUPPORTED_SCHEMA` | identical |
| test_solo_whid_y_pass_0_k9v4.hc (n16) | `HC_UNSUPPORTED_SCHEMA` | identical |
| Gjost_0_d9lo.hc | `HWID_REQUIRED` | identical |
| 884_0_wvd2.hc | `HC_UNSUPPORTED_SCHEMA` | identical |

"Full JSON MATCH" means the complete decoded JSON (profiles, main,
protections incl. V4 map + expanded banner, other_sections,
app_version) is identical between the C++ harness and the Python
reference. No field differed in either opened file.

## Synthetic fixtures — password branch, HPR1, V4 map, tamper (12/12)

Runner: `tools/make_synthetic_n19.py` (exit 0, `ALL OK`). Fixtures are
synthetic only (deterministic seed/nonces/profiles; synthetic password
`s3cret-pw`; Argon2id l=2, m=8*1024*1024). The Python reference opens
them too, so the fixtures are independently valid n19/n15 files, not
just self-consistent. Stored fixtures: `tests/fixtures/`.

| Check | Result |
| --- | --- |
| n19 plain: C++ == Python ref (full JSON) | PASS |
| n19 plain: V4 keys present (remoteProxyUnlocked, expiryRequiresAutomaticTime, countryCodes, unknown key `z` kept) | PASS |
| n19 plain: sidecar + profile payload | PASS |
| n19 protected: C++ == Python ref (correct pw) | PASS |
| n19 protected: wrong pw → AUTH_FAILED | PASS |
| n19 protected: missing pw → PASSWORD_REQUIRED | PASS |
| n19 HPR1 + string banner: C++ == Python ref | PASS |
| n19 tampered (1 byte flipped) → rejected | PASS |
| n15 synthetic: new == orig (byte-identical stdout) | PASS |
| n15 synthetic: == Python ref | PASS |
| n15 synthetic: historical 13-key map kept (no V4 keys, `x` unexpanded) | PASS |
| n15 protected synthetic: new == orig | PASS |

Dossier unit tests: `python -m unittest tests.test_hc_n19 -v` —
**8 tests, OK** (covers all rows above).

## Sanitizers

ASan+UBSan build (`-fsanitize=address,undefined
-fno-sanitize-recover=all`) run over both real 942 files, the protected
wrong-password case and the synthetic n19 fixture with unknown key:
exit codes as expected, **stderr empty, no sanitizer report**.

## Regression — n11/n12/legacy unchanged

Repo test `tests/test_offline_hc_native_parity.py` (stale worktree copy)
against the repo CLI (`native_http_custom_cli.cpp`, built with the same
Mbed TLS 3.6.7), run for BOTH binaries:

- New binary (n19 port): **136 checks pass**, then aborts at check 137.
- Original binary: **136 checks pass**, then aborts at the identical
  check 137.

The failing check is the `utf8_ignored` legacy field variant
(`legacy_http_custom_field_file("utf8_ignored")` → both binaries return
`HC_UNRECOGNIZED_FORMAT` while the stale-worktree test expects it to
decode). It is **preexisting and unrelated to n19**: the original binary
fails identically, and the 136 checks before it (HCX4 n11/n12
locked/protected/tamper matrix, historical n1/n2/n7/n8, n2 HWID, legacy
old-format, Braille, separated_hex/latin1 fields) pass for both. No
regression attributable to this change. The suite aborts at the first
failure, so checks after line 279 never ran for either binary.

## Bug found and fixed during verification

First draft of `protectionsV4()` declared the map array with size 25
but only 24 initializers (a–x is 24 keys). The 25th pair was
`{nullptr, nullptr}`; comparing a protection key against it is
undefined behaviour and segfaulted the harness on a synthetic fixture
with an unknown key (`z`). Real files did not trigger it (all their keys
match before the null slot). Fixed to size 24; covered by the synthetic
unknown-key case above and by the ASan/UBSan run.

## What was NOT verified

1. **Positive open of the real password-protected n19 sample.**
   The correct password was not provided in this session. The protected
   branch is positively verified only on the synthetic fixtures above,
   which use the same Argon2id params as the real file (a1/l=2/
   m=67108864). Follow-up: run the harness with the password supplied at
   runtime (commands in REPRODUCE.md §6); the file must print 2 profiles
   and match `tools/ref_oracle/codec.py` with the same password. This
   also arbitrates the protected-key composition divergence documented
   in ANALYSIS.md §4 (cloud codec vs `hc942_banner.py`).
2. **Gradle build / on-device import.** Needs a machine with the Android
   SDK/NDK. The JNI password flow needs no code change: the offline
   flavor already prompts on `PASSWORD_REQUIRED` and retries.
3. **Verifier confirmation** of the `.cpp.new` against remote head
   f75c6751… before any merge (the file was written from the verified
   remote-head base, not from the stale worktree).

## HMAC audit outcome (§2.2)

- File: AEAD tags authenticate outer envelope, main, profiles, HPR1
  inner layer and sidecars on all opened samples — observed.
- Transport integrity: NOT_OBSERVED (no VPN transport exercised).
- Connection authentication: NOT_OBSERVED (no connection, no verifier).
