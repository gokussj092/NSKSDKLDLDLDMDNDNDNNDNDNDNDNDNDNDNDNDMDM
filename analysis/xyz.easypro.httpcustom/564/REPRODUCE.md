# Reproduce from repository root

Prepare Python/native dependencies from dependencies.lock.json. Keep the
authorized APKM, extracted libraries and private sample outside Git. The
earlier host compilation recipe in
analysis/_intake/httpcustom-offline-20261109/REPRODUCE.md remains applicable;
the same sources are built in .github/workflows/offline-native-apk.yml.

```sh
python analysis/xyz.easypro.httpcustom/564/tools/inspect_apkm.py /private/input.apkm
jadx --no-res --show-bad-code -d /private/jadx /private/base.apk
python analysis/xyz.easypro.httpcustom/564/tools/native_inventory.py /private/libeasypro.so --page 0x54000
python analysis/xyz.easypro.httpcustom/564/tools/native_inventory.py /private/libsysNative.so --start 0x173c0 --size 0x138
python analysis/xyz.easypro.httpcustom/564/tools/make_vectors.py --native-library /private/libeasypro.so
python -m unittest tests.test_hc_legacy57 tests.test_http_custom_899 tests.test_offline_share_ui_contract -v
python tests/test_offline_hc_native_parity.py /tmp/spdecode-hc-native
python analysis/xyz.easypro.httpcustom/564/tools/probe_layers.py /private/test.hc
python analysis/xyz.easypro.httpcustom/564/tools/verify_private.py /private/test.hc /tmp/spdecode-hc-native
```

The generator requires trusted host libsodium 1.0.18 only for fixture creation.
CI loads frozen compressed JSON fixtures using stdlib and needs no libsodium
installation. APK runtime does not include Python, Unicorn, JADX or analysis
scripts. Original primitive vectors are synthetic ASCII, not a complete JVM
or original application import session.

The manual oracle supports reviewed libeasypro.so by exact SHA-256 only.
CLI --output must stay outside Git. For the failed original AES probes,
entry 0xf01c/0xf7dc, mode 1, algorithm 1/2 used the private slot's Base64/hex
forms; no valid plaintext was established. Do not interpret printable output
or Java replacement characters as decryption. Unsupported JNI/imports stop.

Expected: 150 native HC cases, focused Python tests green, real-file
retained_fields=32, v2ray_json_bytes=1026, complete_server_native_equality=true,
and unresolved field 17 with worker_partial=true. Private values never print.

## VPS application after review

The source change is on feat/nuevas-integraciones; no VPS deployment is made
by this research. The existing cloud/infra/vps/spdecodectl interface is:

```sh
spdecode update worker feat/nuevas-integraciones
spdecode status
```

No online client APK or AAB is required for the worker result change. Offline
requires its new persistently signed APK, followed by device QA.
