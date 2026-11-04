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
