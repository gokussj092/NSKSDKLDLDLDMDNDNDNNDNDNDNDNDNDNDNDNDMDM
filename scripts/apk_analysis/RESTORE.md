# Recuperar herramientas después de perder el entorno

## AboWaged VPN 1.0 (1) — 2026-10-23

Restaurar el checkout y dependencias con la sección general de este archivo.
El runtime del lector necesita PyCryptodome y los scripts de la app; no el APK.
Para repetir la investigación, volver a aportar el APKS autorizado con el hash
de `decoders/Python/apps/AboWaged_VPN/ANALYSIS.md`. No guardar sus copias ni
las salidas reales en Git. `work/` y `cache/` están ignorados.

```bash
python scripts/apk_analysis/inspect_apk.py /ruta/AboWaged.apks \
  scripts/apk_analysis/work/abo --native libwg-pro.so --resource res/raw/noobdev.js
env JAVA_TOOL_OPTIONS=-XX:-UsePerfData python scripts/apk_analysis/decompile.py \
  scripts/apk_analysis/work/abo/dex/classes.dex scripts/apk_analysis/work/abo-jadx1
env JAVA_TOOL_OPTIONS=-XX:-UsePerfData python scripts/apk_analysis/decompile.py \
  scripts/apk_analysis/work/abo/dex/classes2.dex scripts/apk_analysis/work/abo-jadx2
env JAVA_TOOL_OPTIONS=-XX:-UsePerfData python scripts/apk_analysis/paranoid_strings.py \
  scripts/apk_analysis/work/abo-jadx1/sources \
  'scripts/apk_analysis/work/abo-jadx2/sources/org/lsposed/lsparanoid/Deobfuscator$AboWagedVPN10$app.java' \
  scripts/apk_analysis/work/abo-clear --call-class Deobfuscator.AboWagedVPN10.app --inventory
python tests/golden/abowaged_generate.py
python -m unittest tests.test_abowaged_vpn tests.test_cloud_c8_vpn_registry -v
python scripts/apk_analysis/abowaged_verify.py --worker \
  --catalog scripts/apk_analysis/work/abo/resources/res/raw/noobdev.js \
  --native scripts/apk_analysis/work/abo/native/split_config.arm64_v8a/libwg-pro.so
```

DEX 1 termina con 27 errores generales de JADX, DEX 2 con código 0. Inspeccionar
el log y los métodos pertinentes. No omitir la verificación del checksum de
JADX: si una caché temporal queda truncada, retirarla y reinstalar la versión
oficial mediante `decompile.py --install`; no cambiar los hashes fijados.

Para copias privadas del catálogo remoto y selector, añadir al verificador
`--catalog /ruta/Elk.txt --udp /ruta/pickerver`; el CLI de
`apps/AboWaged_VPN/server_catalog_decoder.py` descarga las dos fuentes exactas
sin argumentos. No imprime resúmenes: guardar su JSON completo en una ruta
privada. `abowaged_verify.py` sí imprime únicamente conteos y paridad.
`--file /ruta/perfil.awg` permite incorporar una exportación real futura.
El verificador siempre incluye dos fixtures sintéticos; no pedir contraseña:
`MyPass` es un bloqueo del importador después de abrir el JSON. Se preservan
`Server` como cadena y todos los campos, sin aplicar lógica de conexión.

No se modifica AM pendiente, los lectores NPV ni las novedades C11 como parte
de esta integración. Catálogo mínimo 35 / 37 fichas; C8 efectivo 249 / C0 240.

Continuación normal/textos: `npvs_verify.py /ruta/normal.npvs --worker` comprueba
app-key sin objeto de credenciales. Kurdo v5: 20 registros / 12 campos npvs1,
JSON entero igual a JDK, CLI y worker. `apps/NPV_Tunnel/text_decoder.py` funciona
por archivo/stdin, con cinco prefijos explícitos y sin registro de rutas.
`python -m unittest tests.test_npv_text -v` reproduce sus cinco pruebas;
documentación de las dependencias y de los cuatro aliases no certificados en
`docs/NPV_TEXT_AND_NORMAL_FILE.md`. No habilitarlo automáticamente: el usuario
solicitó integrar esos textos en otro chat.

## Actualización NPV Tunnel 124.0.37 — 2026-10-22

El lector canónico sigue en `decoders/Python/npvs.py`. Retomar primero
`docs/NPVS_V5_INVESTIGATION_HANDOFF.md` y `docs/NPVS_PROTECTED_FILES.md`.
Reutilizar las tablas existentes mientras los hashes de SO/rt.dat coincidan.
Los siguientes comandos se ejecutan después de restaurar repo/dependencias
como se indica en la sección general de abajo. Archivos privados fuera de Git.

```bash
python scripts/apk_analysis/inspect_apk.py /ruta/Npv.apks \
  scripts/apk_analysis/work/npv --asset rt.dat \
  --native libnpvtunnel.so --native libgojni.so
python scripts/apk_analysis/go_inspect.py /ruta/libgojni.so \
  --filter '(\.parseCompactHeader|\.openSourcePassphrase)$'
python scripts/apk_analysis/go_inspect.py /ruta/libgojni.so \
  --disassemble npv-tunnel-core/MobileLibrary/libnpvtunnel.openSourcePassphrase
python tests/golden/npvs_protected_generate.py > /tmp/npvs-synthetic.json
python -m unittest tests.test_npvs_protected tests.test_npvs_v5.PrimitiveTests \
  tests.test_npvs_v5_embedded tests.test_cloud_c8_npvs_error_classification -v
python scripts/apk_analysis/npvs_verify.py /ruta/protegido.npvs \
  --credentials-stdin --worker < /ruta/credenciales-privadas.json
```

El JSON privado puede contener `password` y `publicKey`; el verificador elige
el dato correspondiente a cada método al recibir varios archivos. No imprime
sus valores. El modo recipient se contrasta solo como diagnóstico ECDSA y
coincidencia de fingerprint; requiere la privada para descifrar. Ver los hashes
de los dos adjuntos idénticos antes de creer que son casos distintos.

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

## 1FTunnel 0.6.99 / build 125

Después de restaurar el checkout del PR #96 y el entorno descrito arriba,
volver a aportar el APK/perfil autorizados con hashes de
`decoders/Python/apps/OneFTunnel/ANALYSIS.md`. No se necesitan para usar el lector
ni ejecutar sus fixtures; solo para repetir la comprobación privada/nativa.

```bash
python scripts/apk_analysis/inspect_apk.py /ruta/1FTunnel.apk \
  scripts/apk_analysis/work/oneftunnel --native liboneftunnel-security.so
env JAVA_TOOL_OPTIONS=-XX:-UsePerfData python scripts/apk_analysis/decompile.py \
  scripts/apk_analysis/work/oneftunnel/dex/classes.dex \
  scripts/apk_analysis/work/oneftunnel-jadx
java -XX:-UsePerfData tests/golden/oneftunnel_oracle.java > /tmp/oneftunnel_vectors.json
python -m unittest tests.test_oneftunnel tests.test_cloud_c8_vpn_registry -v
python scripts/apk_analysis/oneftunnel_verify.py --worker
python scripts/apk_analysis/oneftunnel_verify.py --input /ruta/perfil.1ftnl \
  --library /ruta/liboneftunnel-security.so --worker
```

El SO debe ser ARM64 y coincidir con el SHA fijado. La herramienta nativa no
se ejecuta con otros layouts; solo modela HMAC JNI y memoria. El verificador
no imprime datos descifrados ni claves. Para un perfil con contraseña, añadir
`--credentials` y pasar `{"password":"..."}` por stdin privado. No guardar
APK/SO, fuentes JADX, inventarios ni resultados reales en Git. Conservar AM
pendiente; este lector no depende de quitar LIAPP ni usa sus herramientas.
