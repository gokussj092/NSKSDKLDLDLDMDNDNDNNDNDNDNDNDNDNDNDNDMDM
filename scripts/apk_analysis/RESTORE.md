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
