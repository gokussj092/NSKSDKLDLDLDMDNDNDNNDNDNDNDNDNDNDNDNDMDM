# Reproducción limitada, sin build Android

Desde raíz del repositorio; usar Python del venv. Originales y salidas reales
en directorio privado. No subir APK, bibliotecas, claves o catálogos descifrados.

```sh
python3.12 -m venv /ruta/privada/venv
/ruta/privada/venv/bin/pip install -r analysis/noob.arpro.vpn/2/requirements.lock.txt
curl --fail --location --max-time 180 'https://d.apkpure.com/b/XAPK/noob.arpro.vpn?version=latest' -o /ruta/privada/arpro/ARPRO-latest.xapk
python analysis/noob.arpro.vpn/2/tools/prepare.py /ruta/privada/arpro/ARPRO-latest.xapk /ruta/privada/arpro/unpacked
python scripts/apk_analysis/decompile.py /ruta/privada/arpro/unpacked/inspected/dex/classes.dex /ruta/privada/arpro/jadx1 --jar /ruta/al/jadx-1.5.6-all.jar
python analysis/noob.arpro.vpn/2/tools/resolve_strings.py /ruta/privada/arpro/jadx1/sources /ruta/privada/arpro/resolved
python analysis/net.catnet.vpn/27/tools/dex_trace.py /ruta/privada/arpro/unpacked/inspected/dex/classes.dex /ruta/privada/arpro/string-dex.json --class-prefix 'LO60;'
python scripts/apk_analysis/elf_inspect.py /ruta/privada/arpro/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so --disassemble 0x47f660 --size 180
python scripts/apk_analysis/elf_inspect.py /ruta/privada/arpro/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so --jni-table 0x822c48 --count 10
python scripts/apk_analysis/elf_inspect.py /ruta/privada/arpro/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so --disassemble 0x47b0a4 --size 1000
python scripts/apk_analysis/elf_inspect.py /ruta/privada/arpro/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so --disassemble 0x47a4b8 --size 1400
python scripts/apk_analysis/elf_inspect.py /ruta/privada/arpro/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libovpn3.so --disassemble 0x47a8d0 --size 180
python analysis/noob.arpro.vpn/2/tools/probe.py /ruta/privada/arpro/remote
```

Extraer los recursos exactos antes de recover. El wrapper conserva el paso
ejecutado inicialmente inline; la revisión fallida sin extensión se conserva
en tools/history y no debe usarse como receta actual:

```sh
python analysis/noob.arpro.vpn/2/tools/extract_resources.py /ruta/privada/arpro
python analysis/noob.arpro.vpn/2/tools/recover.py /ruta/privada/arpro
python analysis/noob.arpro.vpn/2/tools/probe_configured_sources.py /ruta/privada/arpro
python analysis/noob.arpro.vpn/2/tools/verify_pending.py /ruta/privada/arpro
python -m unittest discover -s analysis/noob.arpro.vpn/2/tests -v > /ruta/privada/arpro/checks.log 2>&1
python analysis/com.halcon.connect/1391/tools/dependency_inventory.py analysis/noob.arpro.vpn/2/dependencies.lock.json --repo-root .
python analysis/noob.arpro.vpn/2/tools/finalize.py /ruta/privada/arpro
```

Exigir hashes de MANIFEST: latest puede cambiar de build/variante en el futuro.
Version2.0/code2; JADX exit3/38 errores,8190 arrays/329 fuentes. Se usó JAR ya
disponible verificado, sin instalar ni esperar workflow alguno. Otros rangos
inspeccionados:0x479d14/180,0x47a940/64,0x47aa94/160; readelf -Ws en libovpn3,
libnoobzicore y libtoolChecker. No ejecutar SO/JNI ni modificar controles.

Esperado remoto: ambas fuentes de catálogo200/HTML195bytes, no éxito. Metadata
Pastebin200/JSON3436bytes, sin descargar su APK. Esperado incluido: XTS abre1/1;
tres metadatos GCM válidos. Eso no acredita campos completos ni oráculo XTS.
Las5 pruebas pasan; no equivalen a compatibilidad remota. El expediente queda
PENDING/PARTIAL y el catálogo público72/66/256 se conserva sin proveedor nuevo.


# Recheck 2026-11-09

# Reproduce from repository root

Set PRIVATE_DIR to a restricted directory outside the checkout; do not commit APKs, tokens or catalog data.
Use Python3.12.14 with versions in dependencies.lock.json, Java21.0.13, JADX1.5.6 (official zip hash in lock), Node22+ and npm ci in cloud/web.

```bash
python analysis/_intake/thailand-kham-arpro-2026-11-09/tools/acquire.py noob.arpro.vpn "$PRIVATE_DIR/noob.arpro.vpn"
python analysis/_intake/thailand-kham-arpro-2026-11-09/tools/inspect_apk.py "$PRIVATE_DIR/noob.arpro.vpn/base.apk" "$PRIVATE_DIR/noob.arpro.vpn"
python analysis/_intake/thailand-kham-arpro-2026-11-09/tools/inspect_splits.py "$PRIVATE_DIR/noob.arpro.vpn"
JAVA_OPTS='-Xmx1300m' jadx --no-res -j 2 -d "$PRIVATE_DIR/noob.arpro.vpn/jadx" "$PRIVATE_DIR/noob.arpro.vpn/base.apk"
```

JADX global errors are expected and must be reviewed, not hidden. Run one bounded decompilation at a time. Original acquisition source is d.apkpure.net/b/XAPK/noob.arpro.vpn?version=latest; verify the returned identity against generated/identity.json before interpreting build-specific offsets.

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
