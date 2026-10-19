# C8 — Catálogo de VPN, iconos originales y caché

- Base: `feat/cloud-c8-vps-installer-updater`, origen de motores: PR #95.
- Inventario C0 de 240 rutas: congelado. Extensiones extra: .rt, .gol,
  .ua, .nvpnc, .green, .mtp, y .hxt con lector HX independiente.
- Cada aplicación tiene su módulo Python en `decoders/Python/apps`;
  los siete módulos históricos de la raíz son entradas de compatibilidad.
- Catálogo público de presentación: `POST /api/v1/server-vpn/catalog`
  con `knownVersion`. Responde `unchanged=true` cuando coincide.
- Iconos: `POST /api/v1/server-vpn/icon` con ID del registro. PNG original
  y hash SHA-256; no se exponen URLs de proveedores.
- Versionado: subir `CATALOG_VERSION` al modificar nombres, proveedores,
  iconos u opciones. El cliente consulta como máximo cada 24 horas y
  solo obtiene las imágenes cuyos hashes hayan cambiado.
- Android: `noBackupFilesDir/server_vpn_cache/v1` cifrado con clave AES-256
  generada en Android Keystore, GCM aleatorio por registro, AAD ligada a nombre
  e integridad SHA-256 de iconos. No puede proteger datos una vez descifrados
  dentro de un dispositivo con root, malware o instrumentación Frida.
- Consentimiento: registro cifrado de la versión legal aceptada antes de la
  primera consulta Cloud, con enlaces públicos a términos y privacidad.
- Los seis iconos disponibles y originales son NUR, 24clan, HX, MKK, My Tunnel Proxy y Robust Tunnel.
  El resto de proveedores NO debe mostrarse con iconos inventados: hay que
  extraerlos de sus APK de origen y revisar derechos de marca antes de Play Store.
- NUR mantiene su broker probado. 24clan, HX, MKK, My Tunnel Proxy y Robust Tunnel disponen de su propio
  broker con HTTPS fijo, DNS anclado, reintentos limitados por IP y worker
  aislado. Están DESACTIVADOS por defecto mediante
  `CLOUD_SERVER_VPN_ENABLED=false` hasta validar contra sus proveedores reales.
- KSH, DTunnel Mod y Neutro requieren sus iconos originales verificados,
  autorización de proveedor y/o parámetros de actualización antes de mostrar
  un botón operativo. No debe simularse un descifrado correcto.
- Reintentos de proveedores: reutilizar la estrategia existente C3.5/NUR,
  limitada a transitorios de conexión/DNS, con IP pública fijada a TLS,
  mismos hosts aprobados, presupuesto total y sin repetir ante error
  criptográfico, autenticación o respuesta HTTP definitiva.
- Términos/política existentes siguen siendo BORRADORES. Falta verificación
  legal en México, responsable de tratamiento, plazos, derechos y marcas.

## Validación antes de producción

Ejecutar `cd cloud/web && npm test && npm run build`, pruebas unitarias
Python C8, `./gradlew :app:assembleDebug`, auditoría C5 y GitHub Actions.
Las pruebas de firmas, compatibilidad real con exportadores y VPS
deben realizarse antes de habilitar estos métodos en Play Store.

## Política de publicación de nuevas versiones (Fase VI)

`CATALOG_VERSION` es la versión mínima del código. Al publicar una lista,
icono o cambio en la disponibilidad de un proveedor, aumentar
`CLOUD_SERVER_VPN_CATALOG_VERSION` a un entero **mayor que el anterior**.
Nunca disminuirlo en un rollback del backend: las instalaciones Android
rechazan catálogos con versiones inferiores. Los indicadores de habilitación
de proveedores son parte de la metadata, por lo que también requieren
incrementar la versión. El cliente comprueba como máximo una vez cada
24 horas, transmite solo `knownVersion`, conserva la caché cuando
`unchanged=true` y descarga únicamente iconos cuyo SHA-256 sea nuevo.

La cadencia de 24 horas es una comprobación de versión, no la descarga
diaria del catálogo completo. El botón de reintento permite resolver una
primera instalación sin datos, sin abrir conexiones a proveedores externos.
No usar cron en Android para forzar conexiones mientras la app esté cerrada.

## Consentimiento

El cliente bloquea **todas** las operaciones Cloud, incluidas las consultas
de catálogo y de iconos, si no hay registro cifrado de aceptación vigente.
En cada cambio sustancial de los términos o política de privacidad, crear una
nueva revisión y elevar `CloudLegalConsent.VERSION` en una actualización
Android. El registro anterior no habilita la nueva versión. La página legal
sigue siendo un borrador que requiere revisión profesional y datos del
responsable antes de publicarse en Google Play.

## Phase VII — verificación temporal de catálogos remotos

Durante `sudo spdecode qa start` o `sudo spdecode qa services`, los cinco proveedores fijos (24clan Green, HX Tunnel, MKK Hyper, My Tunnel Proxy y Robust Tunnel) se habilitan temporalmente junto a NUR para pruebas privadas autorizadas. Al ejecutar `sudo spdecode qa stop`, se restauran los interruptores anteriores y se revoca el acceso QA. No implica autorización de terceros para distribuir su contenido ni certificación de compatibilidad.

El catálogo Android se cifra y consulta como máximo cada 24 horas, pero el botón existente de **Actualizar** ejecuta una consulta completa (`knownVersion=0`) incluso con la misma versión para reflejar cambios de habilitación. Las actualizaciones automáticas normales siguen necesitando incrementar monotónicamente `CLOUD_SERVER_VPN_CATALOG_VERSION`. La disponibilidad de un botón no garantiza que el servidor remoto esté operativo o que la respuesta pueda descifrarse.

La APK QA mostrará códigos de error sanitizados por extensión (sin nombres de archivo ni credenciales) para distinguir fallos de transporte, configuración, sesión y descifrado. Los resultados reales de NUR se diagnostican con `sudo spdecode qa probe-nur` durante una sesión activa.

## My Tunnel Proxy 2.3 — catálogo versión 3

ID fijo `my-tunnel-proxy`, módulo
`decoders/Python/apps/My_Tunnel_Proxy/server_catalog_decoder.py`. Descarga real
validada el 2026-10-19: 44 servidores y 601 redes, con comparación del JSON
completo usando las primitivas ARM64 originales. El broker conserva únicamente
el query estático de la URL original; rechaza cualquier modificación de ese
query en redirecciones. El cliente no selecciona URL, query, host ni módulo.

El lector `.mtp` y el texto `mytunnelproxy://` usan `file_decoder.py`. Las
copias de catálogo `.js`/`.rj` se leen explícitamente con el lector de catálogo,
sin registrar esas extensiones genéricas en el router global. `mytunnel://`
solo revela una referencia Cloud offline; no se descarga su destino autenticado.
La compatibilidad `.mtp` se verificó con vectores nativos sintéticos: falta
una exportación real. Ver README, TESTING y manifest de la carpeta.

La incorporación de My Tunnel Proxy elevó la versión mínima del catálogo a 3.
La versión mínima vigente se indica en la última incorporación de este documento.
Si la instalación ya fija `CLOUD_SERVER_VPN_CATALOG_VERSION`, actualizarlo a
un entero mayor que el anterior y nunca inferior a esa versión mínima.
El CLI QA avanza monotónicamente desde la versión mínima actual. El proveedor
continúa bajo el interruptor existente, desactivado por defecto; esta entrega
no despliega ni altera Android, la web administrativa o los proveedores previos.

## Robust Tunnel VPN isvsoft 16.4.7 — catálogo versión 4

ID fijo `robust-tunnel`; lector autónomo de biblioteca estándar
`decoders/Python/apps/Robust_Tunnel_VPN/server_catalog_decoder.py`. La misma
entrada procesa la descarga remota y las copias locales importadas por la app,
sin necesitar APK ni parámetros de cuenta/dispositivo. No se identificó una
exportación independiente de perfiles; no se crean extensiones/rutas de archivo.

El catálogo original incluido contiene 74 servidores, 434 ajustes y un
certificado; la descarga real validada el 2026-10-19 contiene 151 servidores,
1187 ajustes y 6 certificados. La paridad del JSON completo, sobre y campos
anidados, se comprobó ejecutando el algoritmo Java original. Las muestras reales
no se publican. Los tests y fixtures usan exclusivamente datos ficticios.

Se añade el icono PNG original y se conserva la política HTTPS del broker:
host/consulta fijos, IP pública validada, TLS y redirecciones acotadas sin cambiar
el query. La metadata cliente no incluye endpoints o claves. Los proveedores
anteriores y las 240 rutas C0 / 246 rutas efectivas C8 permanecen disponibles.

La versión mínima actual y el valor por defecto Compose son **4**. En una
instalación con `CLOUD_SERVER_VPN_CATALOG_VERSION` explícita, usar un entero
mayor que el anterior y al menos 4 al actualizar. El CLI QA eleva versiones
antiguas sin rebajar las superiores. La incorporación sigue desactivada por
defecto bajo `CLOUD_SERVER_VPN_ENABLED`; no modifica Android ni la interfaz
administrativa y no realiza despliegue.

## Royal Tunnel VPN 7.0 — lectores privados; proveedor público pendiente

Implementación nueva desde el APK `kd.app.royaltunnelplus` versionCode 7,
independiente del motor histórico Royal/XTProy. Carpeta única
`decoders/Python/apps/Royal_Tunnel_VPN/`, con `file_decoder.py`,
`server_catalog_decoder.py`, `codec.py`, icono original, manifest y documentación.

La ruta C8 `.roy` usa ahora el esquema exportado por Royal 7.0: Base64,
IV + AES-256-CBC/PKCS#7, marca Royal, JSON y campos AES-256-GCM; servidor
opcional como cadena JSON con campos AES-CFB. `.xtp` y el mapa congelado C0
no cambian. El router efectivo continúa con 246 extensiones. Para preservar
la compatibilidad C2, el router reconoce el `.roy` histórico por su alfabeto
Unicode distinto y selecciona su ruta original antes de ejecutar el proceso;
no hay fallback después de errores en el lector moderno.

El bridge privado offline admite `royal-tunnel`. El catálogo combina
XXTEA con delta propio, metadatos/servidores AES-CFB128 y tweaks AES-CBC con
clave distinta. El JSON completo del recurso del APK (27 servidores,
100 tweaks, 1485 campos no vacíos) coincide con el Java original/JCE.
Las pruebas de `.roy` usan perfiles sintéticos y el empaquetado nativo original
contrastado con JCE; no se recibió una exportación real independiente.

**No se incorpora Royal al broker ni al catálogo público en esta revisión.**
El endpoint fijo del APK devolvió HTTP 200 con HTML «Site Unavailable» el
2026-10-19, impidiendo validar el catálogo real remoto. El icono original de
415664 bytes también supera el límite existente de 256 KiB. Se conserva en la
carpeta de la aplicación sin sustituirlo por otro logo ni alterar el cliente.
La versión pública sigue en **4**: no cambia la lista visible. El CLI permite
reintentar la descarga fija y explica la respuesta HTML sin simular éxito ni
usar el recurso local automáticamente. Pendientes y hashes completos en
`Royal_Tunnel_VPN/TESTING.md`; sin despliegue, fusión ni cambios Android/web.

## TRV TUNNEL 2.4 — archivos .hxt y catálogo remoto verificado, versión 5

Paquete `com.trv.tunnel`, versionCode 15. Carpeta única
`decoders/Python/apps/TRV_TUNNEL/`, con `file_decoder.py`,
`server_catalog_decoder.py`, PNG original, manifest, README y TESTING.

El APK exporta/importa tweaks `.hxt`: JSON en UTF-8 modificado JNI, XOR nativo y
hexadecimal. El catálogo usa el XXTEA propio de `AbstractC0282Km` con delta
`-1638454863`. El análisis independiente del Java y del XOR ARM64 de **TRV**
confirmó que coincide con los motores HX existentes; se reutilizan sin cambiar
sus fuentes ni duplicar algoritmos. La ruta C8 `.hxt` ya acepta esos bytes,
por lo que C0 conserva 240 rutas y C8 mantiene 246 extensiones efectivas.
No se inventa una extensión `.trv` ni un lector de enlaces `hxt://`.

Se verificó el JSON completo frente al Java original del APK: catálogo inicial
**27 servidores / 630 payloads**; descarga real **32 servidores / 671 payloads**.
Los grupos Premium/Vip/Private estaban vacíos y también se preservan. Ambos
catálogos atravesaron el subproceso Cloud sin recortes. Los perfiles `.hxt`
usan fixtures sintéticos generados con XOR ARM64 y texto JNI contrastado en
Java; no se recibió una exportación real y `exporterCertified` sigue en false.

ID fijo `trv-tunnel` en bridge privado, broker HTTPS, contrato OpenAPI y metadatos
públicos. URL fija del APK, TLS, DNS/IP pública anclada y redirecciones acotadas;
la respuesta pública solo contiene presentación y checksum, sin endpoint o
credenciales. PNG original de 76923 bytes, idéntico en la carpeta y el backend.

**Versión pública mínima: 5.** Una instalación con override debe incrementarlo
a un entero mayor que el anterior y al menos 5. QA conserva el incremento
monotónico y el interruptor `CLOUD_SERVER_VPN_ENABLED` permanece desactivado
por defecto. Royal continúa pendiente de registro público por sus dos límites
ya documentados; la incorporación de TRV no los modifica.

Los adaptadores funcionan con biblioteca estándar, sin APK, pip ni Java. El ZIP
descargable incluye las dos fuentes compartidas como dependencias locales,
verificadas por checksum, para ejecutar fuera del repositorio. Las pruebas no
llaman a proveedores en CI ni publican datos reales. Sin cambios Android/panel,
fusión, despliegue VPS ni publicación APK.

## 4U TUNNEL LITE 2.2 e iconos obligatorios — versión pública 6

Paquete `com.forutunnel.lite`, versionCode 13. Carpeta
`decoders/Python/apps/4U_TUNNEL_LITE/` con dos lectores, icono PNG original,
manifest, README y TESTING. El análisis independiente del Java y XOR ARM64
confirma las primitivas compartidas HX; esas fuentes no se modifican ni duplican.

El archivo real de exportación es `.4ulite`: JSON en UTF-8 modificado JNI, XOR
y hexadecimal. Se preservan sus campos completos, PIN/HWID/caducidad, tipos y
valores que parecen hexadecimales sin descifrado heurístico. C8 sustituye la ruta
genérica de `.4ulite`; el lector de archivos admite además `4ulite://` como
prefijo de compatibilidad offline. El dispatcher global de textos conserva su
motor histórico y no se registra un handler nuevo. No se afirma que el APK tenga un handler para ese esquema. C0 permanece
en 240 rutas y C8 en 246 extensiones efectivas: `.4ulite` ya estaba registrada.

Catálogo XXTEA verificado contra el Java original: local **25 servidores /
635 payloads**; remoto real **33 servidores / 707 payloads**. Ambos JSON completos
atraviesan el subproceso Cloud sin recortes; los tres grupos Premium/Vip/Private
vacíos se conservan. Los perfiles se contrastan con el XOR nativo y texto JNI
Java usando fixtures sintéticos; no se recibió una exportación real independiente.

ID fijo `4u-tunnel-lite` en bridge, broker HTTPS, OpenAPI y metadatos públicos,
con URL fija e IP pública anclada. Icono original de 20114 bytes, idéntico en la
carpeta y el backend. El CLI y el paquete descargable funcionan con biblioteca
estándar, sin APK, Java ni pip; el ZIP incluye sus dos dependencias compartidas.

**Política del usuario aplicable a todas las apps:** no excluir iconos por superar
el antiguo límite. Backend y cliente retiran los umbrales específicos de
256 KiB / 350000 caracteres. Android conserva y verifica el original, amplía su
caché al presupuesto general de transporte existente y muestrea solo el bitmap
de pantalla. No cambia diseño, credenciales ni motores de descifrado en Android.

Royal aparece con su PNG original de 415664 bytes y descifrado desactivado. Esto
sustituye el pendiente de imagen descrito en la sección histórica de Royal;
el pendiente de catálogo remoto permanece. No se añade Royal al broker ni al
contrato público de descifrado mientras no se valide su respuesta remota.

**Versión mínima 6.** Los overrides deben incrementarse por encima de la versión
anterior y al menos a 6. QA conserva el incremento monotónico; el interruptor
global sigue desactivado por defecto. Instalar el cliente con la nueva política
antes de activar el catálogo con imágenes grandes: el cliente anterior conserva
su límite y no se corrige al actualizar solo el servidor. No se ha desplegado,
fusionado ni publicado una nueva APK en este trabajo.

## AC TUNNEL VPN 1.4 — versión pública 7

Paquete `com.boss.actunnelvpn`, versionCode 14. Se añade
`decoders/Python/apps/AC_TUNNEL_VPN/` con `file_decoder.py`,
`server_catalog_decoder.py`, `codec.py`, dependencias, README, TESTING, manifest
/PNG original. El análisis nuevo del Java y `libovpn3.so` verifica la semilla,
sal, IV, suma/resta 2 del tipo 0, XXTEA personalizado y Threefish con tweak
`[índice,0]`. Usuario/contraseña usan Base64 normal + XXTEA + AES-256-CBC con
IV incluido, PBKDF2-SHA256/100000. Se reutilizan las primitivas RENZ intactas.

El perfil real `.actun` lleva `actunnelvpn://`. El lector actualizado usa campos
/ubicaciones demostrados por los consumidores Java y conserva JSON completo,
Unicode, tipos, PIN/caducidad/bloqueos y cadenas desconocidas. Evita recortar
ceros legítimos del criptograma AES en el relleno de Threefish. La ruta C8 se
selecciona por el prefijo original antes del descifrado. `.actun` histórico sin
prefijo conserva el motor C0; `.actunnelvpn` y el alias `actunnel://` permanecen
intactos. Para texto `actunnelvpn://`, un sobre con `Name` selecciona el formato
real; documentos genéricos sin ese campo mantienen el resultado RENZ. Un fallo
de un perfil moderno no provoca reintento con otro algoritmo.

El catálogo remoto se valida completo: **24 servidores / 1248 redes**, frente a
**1 / 1** del recurso local. El oráculo ARM64 contrasta todos los 6319 campos
cifrados no vacíos, las listas completas y metadatos; también se verifican los
12 campos locales. Ambos cruzan el subproceso Cloud con JSON completo idéntico,
`isPartial=false`. Derivación y 12 vectores adicionales contrastados con OpenSSL.
El CLI sin argumentos descarga la URL fija e imprime todos los datos, sin APK.
Las actualizaciones `.js`/`.rj` se leen offline con el mismo lector del catálogo.

Las referencias `acvpn://` se decodifican únicamente a identificador offline,
con `profileDownloaded=false`. No se incorporan ni usan credenciales GitHub
incluidas en el APK para resolver perfiles de cuenta. No se recibió un export
`.actun` independiente; pruebas del formato con datos sintéticos y primitivas
nativas originales, `exporterCertified=false`.

Proveedor fijo `ac-tunnel-vpn` en bridge privado, broker HTTPS, OpenAPI y ficha
pública. PNG original idéntico de 188312 bytes. **Versión mínima 7**, monotónica;
QA incrementa sobre el máximo entre esa versión y el override previo. Siguen
240 rutas C0 y 246 efectivas C8 porque `.actun` ya existía. Los interruptores
siguen desactivados por defecto; ningún cambio Android, diseño web, despliegue,
fusión o publicación APK en esta incorporación.

Verificación local de esta incorporación: **633 pruebas Python, 9 omisiones
existentes**; worker **11**, VPS/QA **39**, gates Cloud **4**, Node **64** y build
Next.js correctos. El bundle incluye `renz.py` exacto y se prueba fuera del
repositorio sin `PYTHONPATH` heredado. No se publican APK, bibliotecas nativas,
catálogos reales ni credenciales de cuenta.

## AustroPlus VPN 13.0.1 — rama nueva desde main, catálogo público 8

Rama `feat/austroplus-vpn-13-0-1-decoders` creada desde `main`
`e6cbb5926372aa6b7d36105802bf366a2138c98e`, que ya incluye el PR #94. No se
continúa en la rama C8 anterior. App `xyz.tekidoer.austroplus.vpn`, versionCode
13, carpeta `decoders/Python/apps/AustroPlus_VPN/` con dos lectores, codec,
dependencias, manifest, README/TESTING e icono original.

Los `.aro` actuales son Base64 de nonce12 + AES-256-GCM + etiqueta16. `CONFIG`
contiene campos con doble Base64 Android; `Server` es una cadena JSON con
campos Base64/XOR. Se verificaron el cifrador/descifrador Java originales y
perfiles sintéticos, incluyendo Unicode, vacíos y restricciones. La etiqueta
siempre se verifica. No hay muestra independiente de exportación real:
`exporterCertified=false`. No se registra un protocolo de texto inventado.

El catálogo usa **XXTEA estándar** de `m83.i/j`, no la variante de `ys.i`.
La primitiva compatible de `decoders/Python/ec.py` se reutiliza intacta con la
clave verificada del APK. `ys.h` decodifica campos específicos con Base64/XOR.
Paridad Java real de ambos JSON completos: inicial **1 servidor / 1 tweak**,
remoto **6 servidores / 198 tweaks**, 6 / 503 campos comprobados incluidos
vacíos. Ambos cruzan el subproceso Cloud con igualdad íntegra e `isPartial=false`.
El CLI del catálogo usa biblioteca estándar y descarga la URL fija original
sin APK; el lector de archivos requiere PyCryptodome. El ZIP incluye `ec.py`
exacto y se prueba fuera del repositorio.

La ruta C8 `.aro` selecciona el motor actual; el JSON `CONFIG` completo del
formato histórico byte+18 se reconoce antes de elegir la ruta y conserva su
motor/snapshot original. Un fallo GCM moderno no provoca fallback. `aro.py`
y `ec.py` permanecen sin cambios. C0 conserva 240 rutas y C8 246 extensiones.

Proveedor fijo `austroplus-vpn` en bridge, broker HTTPS y OpenAPI; ficha pública
con PNG original idéntico de 192×192 / 16607 bytes. Se extrae el PNG completo
de mayor densidad, no el XML adaptativo como si fuera imagen. Sin límite
específico que excluya iconos por peso. **Versión mínima 8** y versión QA
monotónica; interruptores desactivados por defecto. No se aceptan URLs del
cliente ni se siguen URLs incluidas en el JSON. Sin cambios de diseño web ni
Android, fusión, despliegue o publicación APK.

Verificación local: **650 pruebas Python / 9 omisiones existentes**, worker
**11**, VPS/QA **39**, gates Cloud **4**, Node **70** y build Next.js correctos.
Los 14 controles nuevos incluyen el Java original; el bundle aislado conserva
JSON completo y el catálogo funciona con `python -S`. Sin APK, bibliotecas,
catálogos reales o credenciales de cuenta en Git/CI/ZIP.


## HTTP FenixVPN 19.4 — PR #96, misma rama

Incorporada en `feat/austroplus-vpn-13-0-1-decoders`, después de AustroPlus,
sin crear otra rama ni otro PR. Carpeta `decoders/Python/apps/HTTP_FenixVPN/`:
lector `.sks`, lector de catálogos, codec, claves de campos, PNG original,
README, TESTING, manifest y dependencias. Paquete `com.fenix.vpn`, código 181.

El GET fijo de servidores recuperado del APK devolvió HTTP 200, 386584 bytes y
**300 servidores**; el catálogo local trae uno. La descarga separada de usuarios
contiene un perfil, accesible mediante `server_catalog_decoder.py --users`.
El broker Cloud `http-fenixvpn` usa exclusivamente el catálogo de servidores.
Sobre `WakkoDev`, MD5 encadenado y AES-256-CBC; 27 campos de servidor y 6 de
usuario usan Base64 URL-safe, IV prefijado, AES-CBC y ROT21 de Java. Se comparó
el JSON completo local/remoto, incluidos 2127 campos reales no vacíos de los
servidores. Se conservan claves opacas, nombres de usuario planos, opciones
BHTTP, tipos, desconocidos y campos vacíos.

Importación `.sks`: PBKDF2-HMAC-SHA256/1000, AES-128-GCM con sal32/nonce12/tag16,
o DES binario antiguo. Salida íntegra Java Properties: entradas ordenadas,
duplicados y XML original. Archivos probados con vectores sintéticos basados
en el APK, sin muestras reales independientes ni certificación del exportador.
La actividad de exportación existe, pero el onClick observado no invoca la
rutina exportadora. No se atribuye un esquema de enlaces propio a esta versión.

La colisión `.sks` conserva el motor C0 SocksIP para sobres JSON `d/v`; GCM/DES
usan el nuevo lector. La selección ocurre antes de descifrar, sin reintentos tras
un fallo de autenticación. `sks.js`, motores compartidos y snapshots se conservan
sin cambios. C0 permanece en 240 rutas y C8 en 246 extensiones efectivas.

Bridge, broker, OpenAPI y ficha/icono públicos incorporan `http-fenixvpn`.
Catálogo mínimo **9**, Compose 9 y QA `max(previous,9)+1`, sin rebajar overrides
superiores. Icono original 431×426 de 89926 bytes, obtenido del split xhdpi;
checksum idéntico entre carpeta de app y web. No se cambian el diseño Android,
los valores predeterminados de activación ni se despliega/publica una APK.


Verificación del lote: Python 664 pruebas / 9 omisiones existentes; worker 11;
VPS/QA 39; gates 4; Node 71; build web satisfactorio. CLI descargando ambos
catálogos reales y worker aislado con igualdad JSON completa frente a Java.
Muestras `.sks` sintéticas; exportación real independiente todavía no acreditada.

## HTTP Jireh 2.0 — PR #96

Se añade `http-jireh`, paquete `com.jirehvpn`, a la rama
`feat/austroplus-vpn-13-0-1-decoders`. Rutas `HTTP_Jireh/file_decoder.py` y
`HTTP_Jireh/server_catalog_decoder.py`, icono original de 141600 bytes y
documentación en esa carpeta de `decoders/Python/apps/`. El importador `.sks`
GCM/DES coincide exactamente con HTTP FenixVPN: conserva la ruta actual y la
detección histórica SocksIP JSON `d`/`v`; no se duplica un motor.

Catálogo derivado directamente del APK: alfabeto de nibbles, Base64,
SHA256(hex mayúsculo de contraseña)/AES-256-CBC/IV cero y campos
AES-128-CBC/IV cero/ROT22. El GET autorizado de servidores devolvió 109 perfiles
frente a uno incluido; el catálogo de usuarios separado devolvió uno. Los
documentos completos coinciden con un oráculo Java normalizado; no se guardan
en Git datos reales. Archivos verificados con vectores Java sintéticos, sin
exportación real independiente ni certificación de exportador operativo.

Se registran bridge/allowlist Python, broker fijo HTTPS, contrato OpenAPI,
ficha/icono y regresiones; catálogo público mínimo 10, QA aumenta desde ese
mínimo conservando versiones superiores. `CLOUD_SERVER_VPN_ENABLED` conserva
su estado por defecto. No cambia el diseño Android ni se fusiona/despliega.

Verificación HTTP Jireh: suite principal 677 (9 omisiones existentes), worker
11, VPS/QA 39, gates 4, Node 72 y build web correctos. CLI de descarga real y
worker coinciden en el JSON completo; ZIP probado fuera del repositorio.
