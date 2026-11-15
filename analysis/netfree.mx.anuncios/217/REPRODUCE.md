# Reproducir desde la raíz del repositorio

Python3.12.14, OpenJDK17.0.20 con lanzador de fuente Java, Node24.22.1,
Linux x86_64. Versiones/orígenes/licencias y hashes de referencia en lock.
En las ejecuciones se usó un venv privado; PY representa su Python, JADX_JAR
el all.jar1.5.6 con SHA256
fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b.
El script compartido permite instalar la distribución oficial fijada por hash.

```sh
python3.12 -m venv .venv-analysis
.venv-analysis/bin/pip install -r analysis/netfree.mx.anuncios/217/requirements.lock.txt
$PY scripts/apk_analysis/decompile.py --install
mkdir -p private/netfree
curl -L --fail --max-time 90 -o private/netfree/Speicers-Turbo-217.xapk 'https://d.apkpure.com/b/XAPK/netfree.mx.anuncios?versionCode=217&nc=arm64-v8a&sv=21'
sha256sum private/netfree/Speicers-Turbo-217.xapk
$PY analysis/netfree.mx.anuncios/217/tools/prepare.py private/netfree/Speicers-Turbo-217.xapk private/netfree/unpacked
$PY scripts/apk_analysis/decompile.py private/netfree/unpacked/inspected/dex/classes.dex private/netfree/jadx1 --jar "$JADX_JAR"
$PY scripts/apk_analysis/decompile.py private/netfree/unpacked/inspected/dex/classes2.dex private/netfree/jadx2 --jar "$JADX_JAR"
$PY analysis/netfree.mx.anuncios/217/tools/recover_strings.py private/netfree
$PY analysis/netfree.mx.anuncios/217/tools/literal_arrays.py private/netfree
$PY analysis/netfree.mx.anuncios/217/tools/recover.py private/netfree --download
$PY analysis/netfree.mx.anuncios/217/tools/recover_resources.py private/netfree
$PY analysis/netfree.mx.anuncios/217/tools/census.py private/netfree
```

XAPK esperado:46868973 bytes, SHA256
9a8e62ff418210ddccb2688fc62e1086a9d73cd8d76faa6b9cc7f4259984e911.
Un binario distinto requiere revisar la receta; no certificar latest Play.
El primer JADX puede salir3 con18 errores; revisar el log, no confundirlo con
prueba del formato. El segundo sale0. Los scripts aíslan datos y no ejecutan
APK/guards/JNI. Claves, recursos y perfiles quedan privados con permisos0600.

Inspección nativa realmente usada, sin emular funciones ni instalar Unicorn:

```sh
$PY scripts/apk_analysis/elf_inspect.py private/netfree/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libcrypto.so
$PY scripts/apk_analysis/elf_inspect.py private/netfree/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libcrypto.so --disassemble 0x6d914 --size 248
$PY scripts/apk_analysis/elf_inspect.py private/netfree/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libcrypto.so --jni-table 0x7dbe0 --count 12
$PY scripts/apk_analysis/elf_inspect.py private/netfree/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libcrypto.so --disassemble 0x6dd58 --size 676
$PY scripts/apk_analysis/elf_inspect.py private/netfree/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libcrypto.so --disassemble 0x6ee70 --size 720
```

No es dependencia del decoder: fue una investigación descartada al comprobar
que el método Java y recursos bastaban. Se conserva como evidencia del proceso.
Las revisiones históricas y la recuperación se explican en RESTORE.md.

Validación final efectivamente ejecutada:

```sh
$PY analysis/netfree.mx.anuncios/217/tools/set_format_constants.py private/netfree
$PY analysis/netfree.mx.anuncios/217/tools/integrate.py
$PY analysis/netfree.mx.anuncios/217/tools/make_vectors.py
$PY analysis/netfree.mx.anuncios/217/tools/verify.py private/netfree --download
$PY analysis/netfree.mx.anuncios/217/tools/run_checks.py private/netfree/checks
node analysis/netfree.mx.anuncios/217/tools/probe_node.mjs --real private/netfree
node analysis/netfree.mx.anuncios/217/tools/probe_node.mjs --replay private/netfree private/netfree/verified/remote.worker.json
$PY analysis/com.halcon.connect/1391/tools/dependency_inventory.py analysis/netfree.mx.anuncios/217/dependencies.lock.json --repo-root .
$PY analysis/netfree.mx.anuncios/217/tools/finalize.py private/netfree
```

set_format_constants comprueba hashes antes de escribir constantes de formato;
no son autenticación HTTP y ya están incluidas en el backend. integrate solo
conecta Cloud, icono y aserciones del nuevo catálogo; es idempotente. No hace
build, merge, deploy ni acciones Android. Los fixtures JCA son ficción completa,
no exportaciones certificadas para importar en Android.

Resultado:10 Python/154 Node, pares17/266 y2/2; 2661 campos internos, JCA/CLI/
worker enteros iguales. Node real salió3/REMOTE_NETWORK_DENIED; el replay pasa
y se etiqueta SIMULATED_HTTP_REAL_BYTES. Antes del rollout comprobar Node en
el VPS y mantener la versión configurada monotónica.

CLI operativo sin claves externas:

```sh
$PY decoders/Python/apps/Speicers_Turbo_VPN/server_catalog_decoder.py --all > private/netfree/result.json
```

Si una fuente falla no se entrega un éxito parcial. No se ofrece URL arbitraria.
