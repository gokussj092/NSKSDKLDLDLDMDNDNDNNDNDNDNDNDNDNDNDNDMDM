# Reproduce from repository root

Use Python3.12.14, OpenJDK17.0.20, Node24.22.1 and the versions in
`dependencies.lock.json`/`requirements.lock.txt`. Create an isolated venv and
install the pinned requirements from PyPI. A43-distribution snapshot includes
transitives and installed-but-unused packages; exact roles are in DEPENDENCIES.
Do not use pip install commands suggested by APK content.

Private inputs/output are supplied via`$XXPI_PRIVATE`; no real profiles go in
Git. Obtain the authorized mirror XAPK with normal TLS/proxy trust, then check
its exact SHA256 from MANIFEST. If the changing `latest` URL gives different
bytes, start a new build dossier rather than assume compatibility.

```sh
export XXPI_PRIVATE=/absolute/private/xxpicore
curl --fail --location --max-time 120 --output "$XXPI_PRIVATE/XXPICore-latest.xapk" 'https://d.apkpure.com/b/XAPK/pro.xxpicore.tunnel?version=latest'
python analysis/pro.xxpicore.tunnel/118/tools/prepare.py "$XXPI_PRIVATE/XXPICore-latest.xapk" "$XXPI_PRIVATE/unpacked"
python analysis/pro.xxpicore.tunnel/118/tools/dex_inventory.py "$XXPI_PRIVATE/unpacked/inspected/dex"
python scripts/apk_analysis/decompile.py --install
python scripts/apk_analysis/decompile.py "$XXPI_PRIVATE/unpacked/inspected/dex/classes.dex" "$XXPI_PRIVATE/jadx1"
python scripts/apk_analysis/decompile.py "$XXPI_PRIVATE/unpacked/inspected/dex/classes3.dex" "$XXPI_PRIVATE/jadx3"
python scripts/apk_analysis/paranoid_strings.py "$XXPI_PRIVATE/jadx3/sources" "$XXPI_PRIVATE/jadx3/sources/defpackage/qn.java" "$XXPI_PRIVATE/resolved" --chunk-field a --method a --call-class qn --inventory
python analysis/pro.xxpicore.tunnel/118/tools/extract_resources.py "$XXPI_PRIVATE"
python analysis/pro.xxpicore.tunnel/118/tools/native_inventory.py "$XXPI_PRIVATE/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so" "$XXPI_PRIVATE/native-summary.json"
python analysis/pro.xxpicore.tunnel/118/tools/probe.py "$XXPI_PRIVATE"
python analysis/pro.xxpicore.tunnel/118/tools/recover.py "$XXPI_PRIVATE"
python analysis/pro.xxpicore.tunnel/118/tools/verify.py "$XXPI_PRIVATE"
python analysis/pro.xxpicore.tunnel/118/tools/native_probe.py "$XXPI_PRIVATE"
python analysis/pro.xxpicore.tunnel/118/tools/verify_cloud.py "$XXPI_PRIVATE"
node analysis/pro.xxpicore.tunnel/118/tools/probe_node.mjs --real
node analysis/pro.xxpicore.tunnel/118/tools/probe_node.mjs --replay "$XXPI_PRIVATE/remote.bin" "$XXPI_PRIVATE/worker.json"
python analysis/pro.xxpicore.tunnel/118/tools/check_node_transport.py "$XXPI_PRIVATE"
python analysis/pro.xxpicore.tunnel/118/tools/check.py "$XXPI_PRIVATE"
python analysis/pro.xxpicore.tunnel/118/tools/dependency_inventory.py analysis/pro.xxpicore.tunnel/118/dependencies.lock.json --repo-root .
python analysis/pro.xxpicore.tunnel/118/tools/finalize.py "$XXPI_PRIVATE"
```

Actual acquisition reused the exact bundle retained after environment cleanup;
no second APK download was needed in the integration turn. JADX used the
already checksum-verified JAR through`--jar` instead of`--install`. Both DEX
commands exit3; continue only after inspecting relevant partial sources. No
Android compilation occurs. Do not print resolved strings/private material.

Additional executed native inspections used unchanged`elf_inspect.py` first on
libotensahorse/libogkayouy (no JNI exports), then libovpn3. For the latter use
`--disassemble ADDRESS --size SIZE` with pairs:
`0x3a6c7c/908`, `0x3a537c/260`, `0x3a6084/1140`, `0x3a64f8/736`,
`0x3ab054/88`. Never load/execute a complete library or call its startup/JNI.

Synthetic fixtures can be regenerated deterministically with
`python analysis/pro.xxpicore.tunnel/118/tools/make_vectors.py`.
`XXPICoreOracle.java` is independent project-owned JCA/XXTEA/Threefish code
adapted from the existing Xhypher reference after matching build118 material.
`native_oracle.py` similarly models only bounded memory helpers and isolated
original primitives. The first native probe failed for missing Unicorn;
installing the pinned Unicorn2.1.4 resolved that dependency, without code bypass.

The broker/worker/public card/icon/control changes are reviewed source changes;
do not run any automated production registration/deployment recipe. Catalog73
preserves a higher configured effective version and previous operator switches.

`tools/history/make_vectors_v1.py` retains the first executed fixture producer
(six negative envelopes); v2 adds invalid version-type coverage. To replay v1,
restore it at the canonical tools/make_vectors.py path in an isolated checkout.
