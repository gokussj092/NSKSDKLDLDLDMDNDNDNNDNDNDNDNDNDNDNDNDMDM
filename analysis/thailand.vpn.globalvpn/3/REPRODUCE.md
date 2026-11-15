# Reproduce from repository root

Set PRIVATE_DIR to a restricted directory outside the checkout; do not commit APKs, tokens or catalog data.
Use Python3.12.14 with versions in dependencies.lock.json, Java21.0.13, JADX1.5.6 (official zip hash in lock), Node22+ and npm ci in cloud/web.

```bash
python analysis/_intake/thailand-kham-arpro-2026-11-09/tools/acquire.py thailand.vpn.globalvpn "$PRIVATE_DIR/thailand.vpn.globalvpn"
python analysis/_intake/thailand-kham-arpro-2026-11-09/tools/inspect_apk.py "$PRIVATE_DIR/thailand.vpn.globalvpn/base.apk" "$PRIVATE_DIR/thailand.vpn.globalvpn"
python analysis/_intake/thailand-kham-arpro-2026-11-09/tools/inspect_splits.py "$PRIVATE_DIR/thailand.vpn.globalvpn"
JAVA_OPTS='-Xmx1300m' jadx --no-res -j 2 -d "$PRIVATE_DIR/thailand.vpn.globalvpn/jadx" "$PRIVATE_DIR/thailand.vpn.globalvpn/base.apk"
```

JADX global errors are expected and must be reviewed, not hidden. Run one bounded decompilation at a time. Original acquisition source is d.apkpure.net/b/XAPK/thailand.vpn.globalvpn?version=latest; verify the returned identity against generated/identity.json before interpreting build-specific offsets.

KHAM: run resolve_kham_strings.py then probe_kham.py with its private folder. Thailand: run probe_thailand.py; the analytical FIS installation is deleted best effort. AR PRO: resolve_arpro_strings.py SOURCE OUTPUT, then recover_arpro.py PRIVATE_APP and probe_arpro.py PRIVATE_APP. The native file hash is checked before using offsets. A 195-byte HTML response is a failure, not a decoded catalog.

```bash
python analysis/_intake/thailand-kham-arpro-2026-11-09/tools/make_fixtures.py
python -m unittest tests.test_thailand_kham_vpn -v
python analysis/_intake/thailand-kham-arpro-2026-11-09/tools/verify_real.py "$PRIVATE_DIR"
node analysis/_intake/thailand-kham-arpro-2026-11-09/tools/verify_node.mjs "$PRIVATE_DIR"
cd cloud/web
npm ci --ignore-scripts --no-audit --no-fund
npm run icons:prepare
node --test --test-concurrency=4 tests/*.test.mjs
npm run build
```

verify_real compares whole documents with Java/stdlib reference, both CLI inputs and isolated worker. verify_node labels real transport separately from simulated HTTP replay. generated/ stores only counts/hashes/status; original decoded profiles remain private. No production deployment is performed.
