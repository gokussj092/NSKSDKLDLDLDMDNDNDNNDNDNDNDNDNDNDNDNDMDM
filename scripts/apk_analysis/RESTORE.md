# Recuperar herramientas después de perder el entorno

Las fuentes están versionadas en `Gh0stDeveloper/SP-DECODE`, rama
`feat/austroplus-vpn-13-0-1-decoders`, PR #96. Una vez publicado el commit,
no dependen de los archivos temporales del entorno de trabajo.

```bash
git clone --branch feat/austroplus-vpn-13-0-1-decoders \
  https://github.com/Gh0stDeveloper/SP-DECODE.git
cd SP-DECODE
python -m venv .venv
. .venv/bin/activate
python -m pip install -r scripts/apk_analysis/requirements.txt
python scripts/apk_analysis/decompile.py --install
```

También se necesita **JDK 17+** (`java -version`). El bootstrap verifica los
checksums fijados del ZIP y JAR de JADX 1.5.6. Las referencias Java se ejecutan
con `java archivo.java`, sin requerir un comando `javac` separado.

## Herramientas y referencias

- Preparación, PNG original y DEX: `inspect_apk.py`.
- Descompilación reproducible: `decompile.py`.
- Cadenas confirmadas: `paranoid_strings.py`, `stringfog_strings.py` y
  `random_strings.py`; sus patrones y parámetros están en `README.md`.
- ELF/JNI y primitivas ARM64 offline: `elf_inspect.py`, `arm64_function.py`.
- Catálogos 7NET completos: `sevennet_verify.py`, referencias JDK y ARM64 en
  `tests/golden/sevennet*`, y lectores en `decoders/Python/apps/SevenNET_VPN/`.
- Referencias de otras apps: sus carpetas y `TESTING.md`, incluidas Xhypher,
  UT Loop, TurboMX y SuperFlash. No se deduce compatibilidad por compartir nombre.

## Ejemplo 7NET 5.6

Se requiere de nuevo una copia autorizada del APKS: los binarios originales y
catálogos reales no se suben al repositorio. La ruta `scripts/apk_analysis/work/`
está ignorada por Git y se destina al material privado de análisis.

```bash
python scripts/apk_analysis/inspect_apk.py '7NET VPN_5.6.apks' \
  scripts/apk_analysis/work/7net --native libovpn3.so
python scripts/apk_analysis/decompile.py \
  scripts/apk_analysis/work/7net/dex/classes3.dex scripts/apk_analysis/work/7net-jadx3
python scripts/apk_analysis/decompile.py \
  scripts/apk_analysis/work/7net/dex/classes2.dex scripts/apk_analysis/work/7net-jadx2
python scripts/apk_analysis/paranoid_strings.py \
  scripts/apk_analysis/work/7net-jadx3/sources \
  scripts/apk_analysis/work/7net-jadx2/sources/defpackage/pp.java \
  scripts/apk_analysis/work/7net-clear --chunk-field a --method a --inventory
python tests/golden/sevennet_vpn_generate.py
python scripts/apk_analysis/sevennet_verify.py copia-catalogo.txt --runtime
```

DEX 2 puede terminar con errores generales de JADX; revisar el log y confirmar
las rutas necesarias. No desactivar la validación de checksums para continuar.
El verificador admite `--native ruta/libovpn3.so` para los casos ARM64 con hash
exacto; los tests habituales no requieren ese binario ni un catálogo real.
Las pruebas y los metadatos completos de la muestra están en `TESTING.md` y
`manifest.json` de la aplicación. El runtime Cloud solo necesita Python y la
dependencia de su carpeta, no las herramientas de descompilación.

## AM TUNNEL LITE VPN build 63 — continuación pendiente

Las herramientas recuperan los campos conocidos y la primera capa nativa de
LIAPP. **No recuperan todavía el DEX protegido ni el catálogo completo.**

```bash
python scripts/apk_analysis/inspect_apk.py 'AM TUNNEL LITE VPN_AM.apks' \
  scripts/apk_analysis/work/am --asset pdrv2.json --asset .efuyxx.dex \
  --native libputils.so --native libefuyxx.so
python scripts/apk_analysis/decompile.py \
  scripts/apk_analysis/work/am/dex/classes2.dex scripts/apk_analysis/work/am-jadx2
python scripts/apk_analysis/paranoid_strings.py \
  scripts/apk_analysis/work/am-jadx2/sources \
  'scripts/apk_analysis/work/am-jadx2/sources/org/lsposed/lsparanoid/Deobfuscator$AMTUNNELLITE$app.java' \
  scripts/apk_analysis/work/am-clear2 --inventory
python scripts/apk_analysis/liapp_wrapper.py \
  scripts/apk_analysis/work/am/native/split_config.arm64_v8a/libefuyxx.so \
  scripts/apk_analysis/work/am-core.so
python tests/golden/am_tunnel_lite_generate.py
python tests/golden/am_tunnel_lite_native_oracle.py \
  scripts/apk_analysis/work/am/native/split_config.arm64_v8a/libputils.so
python scripts/apk_analysis/am_liapp_metadata.py \
  scripts/apk_analysis/work/am/apks/base.apk
python tests/golden/am_liapp_generate.py scripts/apk_analysis/work/am-core.so
python scripts/apk_analysis/am_liapp_native_probe.py \
  scripts/apk_analysis/work/am-core.so scripts/apk_analysis/work/am/apks/base.apk \
  scripts/apk_analysis/work/am/apks/split_config.arm64_v8a.apk
python -m unittest tests.test_am_liapp_metadata tests.test_am_tunnel_lite -v
```

El extractor acepta únicamente el hash conocido y no ejecuta el protector.
Revisar `decoders/Python/apps/AM_TUNNEL_LITE_VPN/ANALYSIS.md` antes de continuar.
La ficha está desactivada: ni los tests del auxiliar ni recuperar un ELF del
wrapper autorizan afirmar paridad de un catálogo aún no abierto.

El lector estático y el checkpoint ARM64 recuperan los mismos **213 bytes de
metadatos** y comprueban su relación interna. `--buffers --output carpeta-nueva`
en el probe permite conservar el checkpoint posterior y sus asignaciones,
con permiso 0600. Son datos privados de investigación, no un DEX recuperado.
El probe modela archivos y contexto; no ejecuta Android/JNI ni accede a red/OS.
Las rutas `/input` y `/output` son virtuales, no rutas reales del equipo.
Paquete y SHA-1 se verifican localmente en PUtils; no se ha demostrado que el
servidor exija identidad en cabeceras. Ver el flujo y los límites en ANALYSIS.md.
