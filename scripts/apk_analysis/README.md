# Herramientas de análisis APK

FlexNet B46: `flexnet_b46_grant_oracle.py` contrasta 87 casos del binding de
concesión con el bloque ARM64 original y un vector JDK. El observador
`flexnet_b46_capture.js` y colector `flexnet_collect_grant.py` preparan la
recuperación local durante una importación oficial: requieren Android
instrumentable y **no se han validado en teléfono**. Las tres muestras reales
siguen sin abrirse. Los mocks del observador no sustituyen esa comprobación.
Layout, límites y pasos en `docs/FLEXNET_V2_4_AUTHORIZED_IMPORT.md` y RESTORE.
Para la nueva muestra v6 offline se observa `d.w` y se guarda su v5 interior
con `--offline-inner`, sin extraer la clave hardware. El host autentica el v5;
el tag v6 lo verifica la llamada original observada. Ver el documento V6_SAMPLE.

Tx Tunnel build 70: `tx_tunnel_verify.py` reutiliza el comparador de documentos
completos y la referencia libsodium/JDK, sin copiar el motor histórico. Catálogos
reales 23/66 y 27/643, 4888 campos; cuatro documentos sintéticos adicionales.
El origen GET usa appcode 27.0 calculado del tamaño real del APK, no una cuenta.
`dex_method.py` requiere descriptor original **Lrk1;**, no el `defpackage` de
JADX, para `g(Context)D` (32 instrucciones). Exportador `NetworkAdapter.u`,
149 instrucciones. Sin contraseña de usuario; `.tx` real pendiente. Ver RESTORE.

MM Tunnel build 45: `mm_tunnel_verify.py` contrasta JSON completo con libsodium
Argon2id y JDK AES-GCM independientes, CLI y worker. Seis documentos sintéticos
y el catálogo real 34/555, incluidos 3335 campos. No imprime valores privados.
`go_inspect.py` admite pclntab f1 fusionada en `.data.rel.ro`, mantiene textStart
relocalizado y rechaza tablas ambiguas. Exportación `.mmt` sin contraseña de
usuario; pendiente muestra real y POST remoto aceptado (HTTP 403). Ver RESTORE.

Hex Custom 10.6.1: `hex_custom_recover.py` es una herramienta de análisis,
**no un decodificador de archivos**. Separa KVS1 con límites comprobados y
recupera la tabla JNI de CustomServerShare desde su pool XOR; `--verify-xor`
compara 546488 bytes con el bucle ARM64 original aislado. Salidas privadas,
hashes fijados, sin ejecutar JNI/VM. Cuerpos virtualizados y formato pendientes.
`elf_inspect.py` resuelve PLT mediante GOT, incluyendo entradas de 24 bytes;
regresión de cuatro wrappers AboWaged comprobada. Ver RESTORE y app/ANALYSIS.

CREEB VPN 50.0: `creeb_vpn_verify.py` compara documentos completos con JDK,
CLI y worker (cinco sintéticos y asset real 1/1). Dos claves y selección
contextual pInfo, sin password externo; pendiente `.crev` real y descarga
remota. `creeb_vpn_remote_probe.py` consulta solo el actualizador fijo, sin
atestación inventada, sin imprimir cuerpos. `vector_icon.py` conserva las
formas/colores de VectorDrawable plano y genera PNG a tamaño original;
rechaza construcciones no admitidas. Conservar siempre el AXML original,
registrar hashes y no afirmar identidad de antialiasing con Android.
Comandos en RESTORE.md; no confundir con CREEB INJECTOR ni su asset `.creeb`.

CREEB INJECTOR 38.0: `dex_method.py` conserva métodos Dalvik exactos en JSON
privado cuando JADX no produce la clase anónima; no ejecuta código. Confirmó
64 instrucciones de `ConfigParser$1.toString`, clave fija DES. `creeb_verify.py`
contrasta archivos completos con DES/Properties JDK y worker, y comprueba los
bundles JSON con varios perfiles. Cinco documentos sintéticos, pendiente
`.creeb` real. No confundir su actualizador APK con un catálogo de servidores.
Hashes, receta, bloqueos de contraseña/HWID y comandos en la carpeta de la app
y RESTORE.md. El cifrado no es el antiguo XXTEA de `.crev`.

AboWaged VPN 1.0: `inspect_apk.py --resource res/raw/noobdev.js` recupera el
catálogo raw exacto, además de `--native libwg-pro.so`. Para el wrapper
LSParanoid entre DEX, `paranoid_strings.py --call-class
Deobfuscator.AboWagedVPN10.app` conserva la clase de chunks original y usa la
notación de llamadas realmente emitida por JADX. **2432 / 100 / 2860** cadenas,
archivos e inventario. `abowaged_verify.py` compara documentos completos con
JDK y worker; `abowaged_native_oracle.py` ejecuta solo los cuatro wrappers
JNI con cadenas/call Java modelados, sin Android/red. Confirma sus constantes;
el AES del APK es Java y se contrasta por separado en JDK. Comandos y hashes
en RESTORE.md y `apps/AboWaged_VPN/ANALYSIS.md`. Sin muestra `.awg` real aún.

NPV Tunnel: `go_inspect.py` recupera nombres Go y resuelve `textStart` desde
moduledata relocado, evitando el desfase de 0x50 de la investigación original.
`npvs_verify.py` compara JSON íntegro, incluidas capas `npvs1:`, con framing y
primitivas JDK independientes; credenciales solo por stdin. Reutiliza las tablas
white-box verificadas para app-key. No descifra recipient con una public key.
Ver RESTORE.md y `docs/NPVS_PROTECTED_FILES.md` para el estado y las limitaciones.

Fuentes reutilizables para preparar próximas integraciones. No forman parte del
servidor ni se importan desde los decodificadores. No necesitan un APK en runtime.
Se mantienen aquí los scripts y versiones; los binarios se reconstruyen.

Continuación AM-63: `am_liapp_metadata.py` abre estáticamente los **213 bytes**
de metadatos LIAPP del APK con hash exacto. `am_liapp_native_probe.py` verifica
su igualdad con el flujo ARM64 acotado; requiere core/base/split originales y
modela archivos y contexto. `--buffers` conserva opcionalmente un checkpoint
posterior. Ninguno reconstruye todavía el DEX ni abre `pdrv2.json`; no habilitan
el proveedor. Comandos en [RESTORE.md](RESTORE.md), detalles en el ANALYSIS de AM.

Requisitos: Python 3.10+, JDK 17+ y `pip install -r requirements.txt` dentro de un
entorno virtual. JADX **1.5.6** se descarga de su publicación oficial solo con
`--install`; `decompile.py` verifica SHA-256 del ZIP y JAR antes de usarlo.
También acepta un JAR existente con `--jar`, verificando el mismo checksum.

1FTunnel 0.6.99: `oneftunnel_verify.py` compara el JSON completo con JDK y,
opcionalmente, archivo privado/worker. `oneftunnel_native_oracle.py` ejecuta la
KDF ARM64 del SO con hash fijado; modela HMAC y memoria, sin JNI/Android/red.
**16 documentos iguales y 32 KDF iguales** contando 15 vectores sintéticos y
la muestra real. Pasos reproducibles en [RESTORE.md](RESTORE.md) y formato en
`decoders/Python/apps/OneFTunnel/ANALYSIS.md`. No se identificó catálogo.

```bash
python scripts/apk_analysis/inspect_apk.py aplicacion.apks scripts/apk_analysis/work/app \
  --asset gremlin.json --native libputils.so
python scripts/apk_analysis/decompile.py --install
python scripts/apk_analysis/decompile.py scripts/apk_analysis/work/app/dex/classes2.dex \
  scripts/apk_analysis/work/jadx2
python scripts/apk_analysis/paranoid_strings.py scripts/apk_analysis/work/jadx2/sources \
  'scripts/apk_analysis/work/jadx2/sources/org/lsposed/lsparanoid/Deobfuscator$MHRTUNNELVPN$app.java' \
  scripts/apk_analysis/work/clear --inventory
python scripts/apk_analysis/random_strings.py fuentes-jadx C1682lA salida-privada
python scripts/apk_analysis/elf_inspect.py biblioteca.so
python scripts/apk_analysis/elf_inspect.py biblioteca.so --disassemble 0x79ec --size 664
python scripts/apk_analysis/elf_inspect.py biblioteca.so --jni-table 0x26358 --count 17
```

- `inspect_apk.py`: metadatos, hashes, DEX raíz, PNG original si existe como PNG,
  assets explícitos y bibliotecas de una ABI. No reconstruye iconos adaptativos.
  Lee ZIP sin `extractall` y rechaza entradas ausentes, duplicadas o excesivas.
- `decompile.py`: llama a JADX con argumentos separados; conserva su código de
  salida y log. Errores de descompilación requieren inspección, no se ignoran.
- `paranoid_strings.py`: reproduce el algoritmo LSParanoid de `RandomHelper` y
  `DeobfuscatorHelper`; admite llamadas con IDs literales. `--inventory` requiere
  un seed compartido. Solo serializa datos UTF-16 a un programa Java conocido:
  no compila clases ni expresiones arbitrarias extraídas del APK.
- `random_strings.py`: patrón de constructor con `long[]` y `java.util.Random`,
  como el confirmado en MegaTunnel. El nombre de clase es obligatorio; no
  presupone que cualquier constructor tenga este algoritmo.
- `elf_inspect.py`: lectura AArch64 de segmentos, símbolos, PLT, relocaciones,
  desensamblado y tablas JNI dinámicas con direcciones conocidas. No ejecuta SO.
- `arm64_function.py`: clase `Arm64Function` para emular funciones aisladas con
  Unicorn, límite de instrucciones/memoria y relocaciones relativas. Solo modela
  memcpy/memset; rechaza cualquier otra importación. No carga JNI, Android ni
  ofrece red o llamadas al sistema. Las direcciones y argumentos deben obtenerse
  antes por inspección. Comprobada con las funciones KDF/AAD originales de
  SuperFlash 184.0.1; no pretende arrancar una biblioteca completa.

Referencia reproducible de SuperFlash: `tests/golden/superflash_vpn_native_oracle.py`
usa estas herramientas con el SO original aportado localmente, libsodium del
sistema y JDK. `superflash_vpn_generate.py` crea únicamente vectores sintéticos
firmados con una clave pública de pruebas, que el lector de producción rechaza.

Los patrones son específicos de familias confirmadas; no son un desempaquetador
universal de LIAPP ni garantizan recuperar todo el código protegido. Verificar
la receta y comparar documentos completos con un oracle independiente antes de
registrar un proveedor. Oracles sintéticos reproducibles: `tests/golden/`.

`cache/` y `work/` están ignorados. Mantener APK/APKS, SO/JAR, capturas, inventarios
de cadenas y resultados descifrados fuera de Git. Las salidas pueden contener
claves de formato o datos de usuarios; las herramientas imprimen solo recuentos
y metadatos. La descarga de catálogos se realiza por el lector de cada aplicación,
no por estas herramientas.

TurboMX 143.1.26 reutiliza las herramientas ELF/JNI/ARM64 anteriores. La referencia
`tests/golden/superflash_vpn_native_oracle.py` ahora selecciona únicamente los
layouts conocidos de SuperFlash/TurboMX por SHA-256 exacto del SO. Sus offsets,
revisión y clave pública se verificaron por separado; no se deducen del nombre
ni de la diferencia de tamaños. El generador compartido escribe vectores
sintéticos independientes según el layout y conserva los de SuperFlash.

`stringfog_strings.py` resuelve llamadas literales Base64/XOR de un wrapper
StringFog **confirmado** y una clave explícita, sin ejecutar código del APK.
Ejemplo comprobado con UT Loop 22.10.26:

```bash
python scripts/apk_analysis/stringfog_strings.py fuentes-jadx L5.b.a salida-privada \
  --key-hex 737472696e67666f67
```

Procesa únicamente el método exacto indicado; las llamadas mediante alias o
argumentos variables requieren inspección aparte. No compila expresiones del
APK ni imprime cadenas recuperadas. La clave se obtuvo de `L5.b` y el algoritmo
de `StringFogImpl`; las salidas privadas permanecen fuera de Git. El análisis
real resolvió 2438 llamadas en 71 archivos; no se afirma resolver toda la app.


Para wrappers LSParanoid renombrados, `paranoid_strings.py` admite identificadores
explícitos sin cambiar los defaults `chunks` / `getString`. Primero confirmar
las constantes y el generador de estado; no basta el nombre de clase.

```bash
python scripts/apk_analysis/paranoid_strings.py fuentes-jadx fuentes-jadx/defpackage/on.java   salida-privada --chunk-field a --method a --inventory
```

Caso real Xhypher 43: 1987 literales en 81 archivos / 2252 cadenas de inventario.
El oracle `tests/golden/xhypher_native_oracle.py` reutiliza ELF/Unicorn con hash
exacto del SO para ejecutar decode_invisible, XXTEA y Threefish offline, usando
únicamente helpers de memoria/cadenas acotados. APK/SO, inventarios y documentos
reales no se guardan en Git. El tipo nativo 3 es un DEX de comprobación de APK,
no un formato de configuración ni un método de catálogo.


## Recuperación y validación 7NET

[RESTORE.md](RESTORE.md) contiene el arranque desde un checkout nuevo del PR #96,
versiones y comandos para recuperar las herramientas después de perder el entorno.
Los binarios se reconstruyen con checksums; las fuentes quedan en Git.

`sevennet_verify.py` compara el documento completo con JDK y, con `--runtime`,
comprueba stdin y worker aislado. `--native` verifica además primitivas ARM64
originales del SO de 7NET 5.6, con hash exacto y sin JNI/red. Referencias y
generador sintético: `tests/golden/sevennet*`. En las muestras reales coincidieron
92/634 registros iniciales y 76/619 remotos; 9 casos ARM64 por fuente. El wrapper
LSParanoid confirmado es `pp.a(long)`, campo `a`, generador `px0.G` (DEX 2/3):
2089 literales en 72 archivos y 2280 cadenas de inventario. Los resultados
reales y los inventarios privados no se publican en el repositorio.

## Primera capa nativa de LIAPP en AM build 63

`liapp_wrapper.py` reproduce la extracción estática observada en el constructor
ARM64 del wrapper de AM: marcador de ocho bytes y restauración del magic ELF.
Comprueba hashes exactos de entrada y salida, límites y ausencia de sobrescritura;
no ejecuta código. **No es un desempaquetador DEX completo ni un lector del
catálogo.** Los siguientes pasos y sus límites quedan en `ANALYSIS.md` de AM.

`tests/golden/am_tunnel_lite_native_oracle.py` ejecuta solo la primitiva PUtils
XOR con copia C++ modelada y memoria/instrucciones limitadas. Ocho vectores
sintéticos coinciden con JDK, incluidos UTF-8 modificado y emoji. No se llama
JNI, controles de firma ni el inicio de la app. `RESTORE.md` deja los comandos
para reconstruir este avance; no habilitar el proveedor hasta abrir el catálogo.
