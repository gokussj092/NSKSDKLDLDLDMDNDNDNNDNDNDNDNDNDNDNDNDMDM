# Results — offline n15 (build 934), 2026-11-18

Status: **PARTIAL** — implemented and host-verified as below; not yet
verified on-device, and the 3 real password-protected samples still need a
positive open with the owner's test password supplied at runtime.

## Environment actually used

- Host: Linux x86_64, g++ 13.3.0, CMake 3.28.3.
- Harness: `tools/host_harness/` built out of tree to
  `/tmp/hc-n15-harness-build/hc_harness` — the exact production sources
  `spdecode_http_custom.cpp` + `spdecode_http_custom_legacy.cpp` compiled
  with Mbed TLS 3.6.7 (pinned tarball, SHA-256 verified by CMake),
  system nlohmann/json 3.11.3 and system libargon2 (reference
  implementation). `-Wall -Wextra -Werror`, clean build.
- Reference oracle: server codec `codec.py` via
  `/home/hatch/workspace/http-custom-update/venv/bin/python`
  (CPython 3.12.3, PyCryptodome 4.4.0, argon2-cffi 25.1.0).
- No Android SDK/NDK exists in this VM (`ANDROID_NDK_HOME` unset,
  `~/Android/Sdk` absent): **no Gradle build and no on-device test were
  possible**. The system libmbedtls-dev here is 2.28.8, whose API is
  incompatible with the production code (targets Mbed TLS 3.6.7), so the
  repo CI recipe (`apt install libmbedtls-dev` + direct g++) does not work
  on this VM; the FetchContent 3.6.7 harness is the working equivalent.

## Real samples — host harness vs Python reference (21/21 checks)

Full machine-readable report: `RESULTS_harness.json`
(run: `tools/run_harness.py`).

| File | Result (C++ harness) |
| --- | --- |
| Test Oppen.hc | OPEN, 2 profiles, **profile-for-profile MATCH** vs Python reference, `app_version` 8.0.22 Patch 2 (934) |
| Test bloquear usuário y contraseña.hc | OPEN, 2 profiles, MATCH |
| Test bloqueo de root2.hc | OPEN, 2 profiles, MATCH |
| Test bloqueo inicio de sesión con hwid.hc | OPEN, 2 profiles, MATCH |
| Test desbloqueo payload.hc | OPEN, 2 profiles, MATCH |
| Test bloqueo de operador.hc | `PASSWORD_REQUIRED` (no password); `AUTH_FAILED` (wrong password) — matches reference behaviour |
| Test bloqueo de root.hc | `PASSWORD_REQUIRED`; `AUTH_FAILED` |
| Test password2.hc | `PASSWORD_REQUIRED`; `AUTH_FAILED` |
| Test bloqueo password y hwid.hc (b=12/n16) | `HC_UNSUPPORTED_SCHEMA` |
| Test password.hc (b=13/n17) | `HC_UNSUPPORTED_SCHEMA` |
| Test hwid.hc (b=13/n18) | `HC_UNSUPPORTED_SCHEMA` |
| Test bloqueo ID de acceso.hc (b=9) | `HC_UNSUPPORTED_SCHEMA` |

" MATCH" means the decoded profiles (label, name, protocol, host, port,
username, password, payload, mode, flags, updated_at_ms, options,
sidecars) and `app_version` are identical between the C++ harness and the
Python reference. No profile field differed in any of the 5 opened files.

## Synthetic fixtures — password branch, positive verification

Fixtures are synthetic only (`tests/fixtures/`, deterministic seeded RNG,
synthetic seed/nonces/profiles; synthetic password
`synthetic-n15-test-password`; Argon2id l=2, m=67108864 — the same params
as the real protected 934 samples). The Python reference opens them too,
so the fixtures are independently valid n15 files, not just
self-consistent.

| Fixture | Result |
| --- | --- |
| synthetic_n15_open.hc | OPEN, 1 profile + sidecar, profiles identical to Python reference |
| synthetic_n15_protected.hc (+ synthetic password) | OPEN, 2 profiles (one HPR1-wrapped, so the `:r` section key works), profiles identical to Python reference |
| synthetic_n15_protected.hc (no password) | `PASSWORD_REQUIRED` |
| synthetic_n15_protected.hc (wrong password) | `AUTH_FAILED` |
| synthetic_n15_tampered.hc | Rejected (`HC_UNRECOGNIZED_FORMAT` — outer tag fails) |
| synthetic_n15_truncated.hc (39 B) | `HC_UNRECOGNIZED_FORMAT` |

Dossier unit tests: `python -m unittest tests.test_hc_n15 -v` —
**8 tests, OK** (covers all rows above).

## Regression — n11/n12/legacy unchanged

Repo test `tests/test_offline_hc_native_parity.py` against the repo CLI
(`tests/native_http_custom_cli.cpp`, built with the same Mbed TLS 3.6.7):

- With this change: **PASS, 97 cases** (HCX4 n11/n12 locked/protected/
  tamper matrix, historical n1/n2/n7/n8, legacy old-format).
- Baseline (change stashed, same build): **PASS, 97 cases**.

Equal counts, no regression. (The CI recipe's system libmbedtls-dev
2.28.8 cannot build this code on this VM — see environment note above;
the 3.6.7 static library from the harness build was used instead.)

## What was NOT verified

1. **Positive open of the 3 real password-protected samples.** The
   owner's test password was supplied in chat and passed at runtime in
   earlier sessions; no copy of it exists in any file or memory this
   session can read (checked: `http-custom-update/NOTES.md`,
   `test_allversion.py`, `codex-verify/*.py`, shell history, memory
   notes). The password branch is positively verified only on the
   synthetic fixtures above, which use the same Argon2id params as the
   real files. Follow-up: run the harness with the test password supplied
   at runtime (commands in REPRODUCE.md §3); each file must print 2
   profiles and match `tools/ref_decrypt.py` with the same password.
2. **Gradle build / on-device import.** Needs a machine with the Android
   SDK/NDK. The JNI password flow needs no code change: the offline
   flavor's `decodeAttempt()` already prompts on `PASSWORD_REQUIRED` and
   retries (verified by reading
   `android/app/src/offlineNative/java/com/ghostdeveloper/spdecode/offline/MainActivity.kt`).
3. **Main-flavor Kotlin n15.** The cloud/main flavor routes `.hc`
   through Kotlin-only ports (`HcHccfgPort`, n1/n2/n7/n8); n15 is not
   covered there. A Kotlin port needs a pure-Kotlin SHA-256-from-state
   implementation and is pending future work; the protected-import dialog
   was left untouched on purpose.

## HMAC audit outcome (§2.2)

- File: AEAD tags authenticate outer envelope, main, profiles, HPR1
  inner layer and sidecars on all opened samples — observed.
- Transport integrity: NOT_OBSERVED (no VPN transport exercised).
- Connection authentication: NOT_OBSERVED (no connection, no verifier).
