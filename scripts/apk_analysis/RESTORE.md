# Recuperar herramientas después de perder el entorno

## Tx Tunnel, Tx v2.17 (70) — 2026-10-24

Continuar en la rama del PR #99, conservando MM. Runtime: checkout completo,
PyCryptodome y argon2-cffi. Aportar el APKS con hash de `apps/Tx_Tunnel/ANALYSIS.md`
para repetir ingeniería inversa. JDK 17+ y dependencias de análisis; libsodium
para el oracle independiente. Material privado fuera de Git.

```bash
python scripts/apk_analysis/inspect_apk.py /ruta/Tx-Tunnel.apks \
  scripts/apk_analysis/work/tx-tunnel --asset configfile.json --native libgojni.so
python scripts/apk_analysis/decompile.py --install
python scripts/apk_analysis/decompile.py scripts/apk_analysis/work/tx-tunnel/dex/classes3.dex scripts/apk_analysis/work/tx-jadx3
python scripts/apk_analysis/go_inspect.py \
  scripts/apk_analysis/work/tx-tunnel/native/split_config.arm64_v8a/libgojni.so \
  --filter '^github.com/2dust/AndroidLibXrayLite.(EO|DOO)$'
python scripts/apk_analysis/dex_method.py scripts/apk_analysis/work/tx-tunnel/dex/classes3.dex \
  'Lcom/v2ray/ang/adapter/NetworkAdapter;' u scripts/apk_analysis/work/tx-export.json
python scripts/apk_analysis/dex_method.py scripts/apk_analysis/work/tx-tunnel/dex/classes3.dex \
  'Lrk1;' g scripts/apk_analysis/work/tx-appcode.json
python -m unittest tests.test_tx_tunnel tests.test_mm_tunnel tests.test_ultra_sandok -v
python scripts/apk_analysis/tx_tunnel_verify.py --worker \
  --catalog scripts/apk_analysis/work/tx-tunnel/assets/configfile.json
```

DEX3/1: salida 3 con 7/41 errores generales, revisar métodos concretos. No
confundir clase nativa declarada con cuerpo recuperado. EO/DOO: 0x1012e70 y
0x1013290; constante igual al perfil txtunnel existente, sin letra insertada.
El GET oficial y User-Agent se obtuvieron del APK; appcode 27.0 procede solo
del tamaño de este base.apk. Descargador sin argumentos para fuente fija.

Asset real 2.0 (23/66/657 campos) y remoto 65.62 (27/643/4231) completos iguales
a libsodium/JDK y worker, sin datos reales publicados. Pendiente `.tx` real.
Ficha operativa en código, mínimo catálogo 40/40, switches conservados; no
significa que la VPS esté desplegada. C0 240 / C8 250, sin APK o C11 automáticos.
Guías de apoyo aportadas por el usuario: `https://github.com/morluto/rea`,
`docs/android-analysis.md` y `docs/native-investigation.md` de ese repositorio.
No instalar ni ejecutar herramientas externas sin inspeccionar su procedencia.

## MM Tunnel v1.10.11.1 (45) — 2026-10-24

Rama nueva `feat/mm-tunnel-1-10-11-1-decoders`, desde main; no retomar el PR #96
para este trabajo. Runtime: Python, PyCryptodome y argon2-cffi. Para repetir el
análisis, aportar APKS con SHA-256 de `apps/MM_Tunnel/ANALYSIS.md`, JDK 17+ y las
dependencias de análisis. El oracle requiere libsodium del sistema. Las
herramientas se conservan en Git; no subir APK/SO, assets o resultados reales.

```bash
python scripts/apk_analysis/inspect_apk.py /ruta/MM-Tunnel.apks \
  scripts/apk_analysis/work/mm-tunnel --asset configfile.json --native libgojni.so
python scripts/apk_analysis/decompile.py --install
python scripts/apk_analysis/decompile.py scripts/apk_analysis/work/mm-tunnel/dex/classes.dex scripts/apk_analysis/work/mm-jadx1
python scripts/apk_analysis/decompile.py scripts/apk_analysis/work/mm-tunnel/dex/classes2.dex scripts/apk_analysis/work/mm-jadx2
python scripts/apk_analysis/paranoid_strings.py scripts/apk_analysis/work/mm-jadx2/sources \
  'scripts/apk_analysis/work/mm-jadx2/sources/org/lsposed/lsparanoid/Deobfuscator$MMTunnel$app.java' \
  scripts/apk_analysis/work/mm-clear2 --inventory
python scripts/apk_analysis/go_inspect.py \
  scripts/apk_analysis/work/mm-tunnel/native/split_config.arm64_v8a/libgojni.so \
  --filter '^github.com/2dust/AndroidLibXrayLite.(Encrypt|decrypt|DO|EO|CU)$'
python scripts/apk_analysis/dex_method.py scripts/apk_analysis/work/mm-tunnel/dex/classes2.dex \
  'Lcom/v2ray/ang/adapter/NetworkAdapter;' u scripts/apk_analysis/work/mm-export-method.json
python -m unittest tests.test_mm_tunnel tests.test_go_pclntab tests.test_ultra_sandok -v
python scripts/apk_analysis/mm_tunnel_verify.py --worker \
  --catalog scripts/apk_analysis/work/mm-tunnel/assets/configfile.json
```

DEX1/2 tienen 42/31 errores generales de JADX; revisar cuerpos concretos. La
pclntab f1 está en `.data.rel.ro`; no adivinar direcciones ni textStart. Para
resolver DEX1, repetir `paranoid_strings.py` con `--call-class Deobfuscator.MMTunnel.app`
y la misma clase de chunks DEX2. La tabla completa contiene 36659 funciones.

El catálogo inicial v1.01 (34/555/3335 campos) es real y está validado completo.
El POST oficial devuelve HTTP 403; no habilitar la tarjeta por tener un asset
funcional. `.mmt` requiere una exportación real futura; seis documentos
sintéticos iguales a libsodium/JDK/CLI/worker no prueban una importación en un
móvil. No añadir esquemas de texto inventados. C0 240 / C8 250, mínimo catálogo
39 / 39 fichas, switches persistentes intactos. Sin despliegue, fusión o APK.

## Hex Custom 10.6.1 (101) — pendiente, 2026-10-23

Solicitud solo de archivo. Recuperar el APKS con hash de `apps/Hex_Custom/ANALYSIS.md`
e instalar dependencias de análisis. No hay lector funcional que desplegar.

```bash
python scripts/apk_analysis/inspect_apk.py /ruta/Hex-Custom.apks scripts/apk_analysis/work/hex-custom --asset protection/kov-sec.dat --native libkovsec.so --native libkovsecvm.so
python scripts/apk_analysis/hex_custom_recover.py \
  scripts/apk_analysis/work/hex-custom/native/split_config.arm64_v8a/libkovsec.so \
  scripts/apk_analysis/work/hex-custom/assets/protection/kov-sec.dat \
  scripts/apk_analysis/work/hex-custom-recovery --verify-xor
python -m unittest tests.test_hex_custom_recovery tests.test_creeb_vpn tests.test_cloud_c8_vpn_registry
```

JADX DEX1/2/3: salida 3, 11/9/8 errores; DEX4/5: salida 0. Sus métodos native no
son cuerpos recuperados. Si hace falta, usar `decompile.py` con cada DEX y un
directorio distinto. Tabla classes7Init0(226), CustomServerShare, diez wrappers;
archivo `native-methods.json` guarda direcciones y hashes. Pool 546488 bytes
igual a XOR nativo aislado. Tres paquetes KVS1 **siguen opacos**, sin firma
Ed25519 verificada ni ejecución de la VM. No llamarlos DEX descifrados.

`hex_custom_recover.py` solo admite hashes de este build; directorio nuevo,
archivos 0600, sin sobrescritura. No publicar paquetes, pool, SO o APK. El ajuste
ELF de PLT 24 bytes usa relocaciones GOT, mantiene la regresión de cuatro
wrappers AboWaged. Extensión, cifrado exportado y contraseña siguen sin confirmar;
continuar desde los cuerpos VM y una exportación real, sin registrar una receta
basada en bibliotecas antiguas incluidas. C0/C8, Server VPN y C11 intactos.

## CREEB VPN 50.0 (50) — 2026-10-23

Runtime: checkout completo y PyCryptodome, sin APK/nativas. Para investigar de
nuevo aportar el APKS con hash en `apps/CREEB_VPN/ANALYSIS.md`; instalar las
dependencias de análisis de requirements.txt y JDK 17. No guardar datos reales.

```bash
python scripts/apk_analysis/inspect_apk.py /ruta/CREEB-VPN.apks scripts/apk_analysis/work/creeb-vpn --asset data.creeb --resource res/drawable/icons.xml
env JAVA_TOOL_OPTIONS=-XX:-UsePerfData python scripts/apk_analysis/decompile.py \
  scripts/apk_analysis/work/creeb-vpn/dex/classes.dex scripts/apk_analysis/work/creeb-vpn-jadx
python scripts/apk_analysis/dex_method.py scripts/apk_analysis/work/creeb-vpn/dex/classes.dex \
  'Lge6;' f scripts/apk_analysis/work/creeb-vpn-f.json
python scripts/apk_analysis/dex_method.py scripts/apk_analysis/work/creeb-vpn/dex/classes.dex \
  'Lj51;' onClick scripts/apk_analysis/work/creeb-vpn-password-check.json
python scripts/apk_analysis/vector_icon.py \
  scripts/apk_analysis/work/creeb-vpn/resources/res/drawable/icons.xml /tmp/creeb-vpn-icon.png
python tests/golden/creeb_vpn_generate.py > /tmp/creeb-vpn-vectors.json
python -m unittest tests.test_creeb_vpn tests.test_creeb_injector tests.test_cloud_c8_vpn_registry
python scripts/apk_analysis/creeb_vpn_verify.py \
  --catalog scripts/apk_analysis/work/creeb-vpn/assets/data.creeb --worker
```

JADX: salida 3, 52 errores generales; confirmar `ge6.f` con sus 58 instrucciones
Dalvik. Asset 1.0.0 real 1/1: igualdad de JSON completo JDK/CLI/worker, sin publicar
valores. `--file /ruta/real.crev` permite añadir la muestra que aún falta.
No adivinar claves ni omitir errores de campos internos: clave C para exterior
y Custom Tweak, S para servidores y otros ajustes. No tocar `.creeb` de INJECTOR.

`creeb_vpn_remote_probe.py` hace GET al endpoint fijo. `--empty-token-post`
repite solo la rama oficial de fallo de token con diagnóstico offline, nunca
una atestación falsa. `--output /ruta/privada` guarda respuesta 0600 sin
sobrescribir; no imprimir cuerpos. GET 200 HTML y POST 405 HTML observados;
remoto pendiente hasta recibir y validar catálogo oficial. Tarjeta desactivada,
36 / 38, switches conservados. No continuar AM/NPV ni publicar C11 por esto.

## CREEB INJECTOR 38.0 (40) — 2026-10-23

Restaurar checkout/dependencias con la sección general de este archivo.
El lector necesita únicamente Python y PyCryptodome. Para repetir el análisis,
aportar el APKS con hash de `apps/CREEB_INJECTOR/ANALYSIS.md`; no necesita SO.

```bash
python scripts/apk_analysis/inspect_apk.py /ruta/CREEB.apks scripts/apk_analysis/work/creeb
env JAVA_TOOL_OPTIONS=-XX:-UsePerfData python scripts/apk_analysis/decompile.py \
  scripts/apk_analysis/work/creeb/dex/classes.dex scripts/apk_analysis/work/creeb-jadx1
env JAVA_TOOL_OPTIONS=-XX:-UsePerfData python scripts/apk_analysis/decompile.py \
  scripts/apk_analysis/work/creeb/dex/classes2.dex scripts/apk_analysis/work/creeb-jadx2
python scripts/apk_analysis/dex_method.py scripts/apk_analysis/work/creeb/dex/classes.dex \
  'Lcom/creeb/injector/config/ConfigParser$1;' toString \
  scripts/apk_analysis/work/creeb-key-method.json
java -XX:-UsePerfData tests/golden/creeb_oracle.java --generate > /tmp/creeb_vectors.json
python -m unittest tests.test_creeb_injector tests.test_cloud_c8_vpn_registry -v
python -m unittest tests.test_abowaged_vpn -v
python scripts/apk_analysis/creeb_verify.py --worker
```

JADX informa 62/4 errores generales en DEX 1/2; no considerarlo una recuperación
completa. La clase anónima de la clave se verifica en las 64 instrucciones del
volcado Dalvik. `dex_method.py` requiere nombre exacto de clase y método, crea
salida 0600 y no sobrescribe un archivo existente. No guardar esas salidas en
Git. El oracle transcribe desplazamientos Java y usa DESKeySpec, Cipher("DES")
y Properties, sin ejecutar clases del APK.

`creeb_verify.py --worker /ruta/real.creeb` permitirá añadir una muestra real;
por ahora verifica tres DES/XML sintéticos y dos bundles JSON. Conservar
`raw_xml` exacto, entradas duplicadas y todas las propiedades/perfiles. El hash
de contraseña y HWID se preservan como contenido; no son secretos para abrir
estos formatos. No se descifra ni se adivina el password original.

Catálogo no identificado: el enlace de UpdateAsync solo contiene actualización
APK; Cloud Firestore requiere referencia de configuración y no es un catálogo.
No añadir ficha/proveedor por inferencia. Server VPN sigue 35 / 37; C8 250 / C0
240. Sin cambios C11, despliegue, APK o continuación de AM/NPV automática.

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

## FlexNet V 2.4 / build 46: concesiones de importación

Continuación en PR #99. No se abrieron las dos muestras online reales: falta
observar su importación en un Android instrumentable. El usuario confirmó que
la app oficial sí las importa. Layout, hashes, captura y uso privado completos
en [FLEXNET_V2_4_AUTHORIZED_IMPORT.md](../../docs/FLEXNET_V2_4_AUTHORIZED_IMPORT.md).

```bash
python scripts/apk_analysis/inspect_apk.py '/ruta/FlexNet V 2.4 .apk' \
  scripts/apk_analysis/work/flex-b46 --asset builtin_servers.dat --native libvpnbridge.so
python scripts/apk_analysis/decompile.py \
  scripts/apk_analysis/work/flex-b46/dex/classes.dex scripts/apk_analysis/work/flex-b46-jadx
java tests/golden/FlexB46VectorGenerator.java scripts/apk_analysis/work/flex-b46-jdk-grant
python scripts/apk_analysis/flexnet_b46_grant_oracle.py /ruta/libvpnbridge.so
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_flexnet_b46_grant tests.test_flexnet_b46 tests.test_flexnet_b42 -v
node --test tests/flexnet_b46_capture.test.mjs
```

Se necesita el entorno opcional Unicorn/pyelftools para el oracle, no para el
lector. SHA exacto fijado en el script. Ejecuta parser/binding y comparador
originales: 87 casos, sin JNI/Android/RSA. JADX terminó con 27 errores generales;
las rutas indicadas se revisaron con DEX y desensamblado nativo, sin afirmar
descompilación completa. El directorio Java contiene material sintético.

`flexnet_b46_capture.js` se carga por el REPL de Frida en el proceso oficial;
`flexnet_collect_grant.py` verifica GCM/XML antes de crear una captura local 0600.
El runtime Android de ese observador sigue pendiente: las cinco pruebas Node
usan mocks. No guardar logs/concesiones reales en Git. El APK/SO y las tres
muestras se vuelven a aportar localmente con los hashes documentados.

La tercera muestra es v6 offline: ver
[FLEXNET_V2_4_V6_SAMPLE.md](../../docs/FLEXNET_V2_4_V6_SAMPLE.md).
El observador también captura el retorno v5 de `d.w` y el colector admite
`--offline-inner`. Se contrastó su descriptor real en DEX (50 instrucciones).
Los mismos comandos de pruebas cubren ahora 32 casos Python y cinco Node.
La clave de época no se exporta. El host verifica las capas internas v5;
la autenticación del exterior v6 depende de la llamada original en Android.
