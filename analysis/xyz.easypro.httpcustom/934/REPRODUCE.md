# Reproduce — offline n15 (host harness)

No Android SDK/NDK is installed in this VM, so there is no Gradle build to
reproduce here. The verification path is a host-side build of the exact
production C++ sources with the system compiler.

## Prerequisites

- `g++` 13.3.0, `cmake` 3.28.3, `python3` (venv below for the reference).
- Network for one-time FetchContent download of the pinned Mbed TLS 3.6.7
  tarball. nlohmann/json and Argon2 come from the system packages when
  present (`apt-get install -y nlohmann-json3-dev libargon2-dev`), else
  from the same pinned git sources as the app (see the harness
  `CMakeLists.txt`).
- Real `.hc` samples live outside this repo at
  `/home/hatch/workspace/http-custom-update/drive/` (owner-supplied, not
  committed). The Python reference venv is
  `/home/hatch/workspace/http-custom-update/venv/bin/python`.

## 1. Build the harness

From the worktree root (`offline/hc-n15`):

```sh
cmake -S analysis/xyz.easypro.httpcustom/934/tools/host_harness \
      -B /tmp/hc-n15-harness-build -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/hc-n15-harness-build -j
# produces /tmp/hc-n15-harness-build/hc_harness
```

## 2. Regenerate the synthetic fixtures (optional; committed copies exist)

```sh
/home/hatch/workspace/http-custom-update/venv/bin/python \
  analysis/xyz.easypro.httpcustom/934/tools/make_synthetic_n15.py
```

This rebuilds `tests/fixtures/synthetic_n15_{open,protected,tampered,truncated}.hc`
deterministically (seeded RNG, synthetic data only). The synthetic protected
fixture uses password `synthetic-n15-test-password` (a synthetic test
constant, not a real credential) and Argon2id params l=2, m=67108864 — the
same params as the real protected 934 samples.

## 3. Run the comparison (12 real samples + synthetic fixtures)

```sh
/home/hatch/workspace/http-custom-update/venv/bin/python \
  analysis/xyz.easypro.httpcustom/934/tools/run_harness.py
# writes analysis/xyz.easypro.httpcustom/934/RESULTS_harness.json
```

For the 3 real password-protected samples this run only checks the negative
behaviour (`PASSWORD_REQUIRED` without a password, `AUTH_FAILED` with a
wrong password). To positively open them, supply the owner's test password
at runtime (never write it to a file):

```sh
H=/tmp/hc-n15-harness-build/hc_harness
"$H" "/home/hatch/workspace/http-custom-update/drive/Test bloqueo de operador.hc" '<test-password>'
"$H" "/home/hatch/workspace/http-custom-update/drive/Test bloqueo de root.hc" '<test-password>'
"$H" "/home/hatch/workspace/http-custom-update/drive/Test password2.hc" '<test-password>'
```

Each must print JSON with 2 profiles and exit 0, matching the Python
reference (`tools/ref_decrypt.py <file> '<test-password>'`).

## 4. Run the repo tests

```sh
cd analysis/xyz.easypro.httpcustom/934
/home/hatch/workspace/http-custom-update/venv/bin/python \
  -m unittest tests.test_hc_n15 -v
```

The test file drives the built harness binary (default
`/tmp/hc-n15-harness-build/hc_harness`, overridable with `HC_HARNESS`)
against the synthetic fixtures and the real samples' negative behaviour.
It never needs the real test password.

## 5. Single-file manual check

```sh
/tmp/hc-n15-harness-build/hc_harness <file.hc> [password] [hwid]
# stdout: decoded JSON; stderr: "ERROR <code>"; exit 0 on success, 1 on decode failure
```

## On-device / Gradle (NOT reproduced here)

No Android SDK/NDK exists in this VM (`ANDROID_NDK_HOME` unset,
`~/Android/Sdk` absent). A Gradle build and an on-device import test remain
pending for a machine with the Android SDK.
