# C8 — Catálogo de VPN, iconos originales y caché

## Actualización TunnelDOOM 4.3.0 (430) — 2026-10-26

Se descargaron 4.2.7 (427) y 4.3.0 (430) de APKPure, paquete y versiones
confirmados en sus APK, certificado SHA256 igual a la 4.2.4 aportada.
La 430 reemplaza el origen antiguo por **GET público fijo**
`https://panel.tunneldoom.space/config.json`. HTTP200 real: **Version473,
387 servidores / 5031 campos cifrados**, documento entero igual a JCA,
CLI de descarga y worker aislado. El contador470 indicado por el usuario
ya está superado; no se descargó una instantánea470.

Broker DNS/TLS fijo, sin redirecciones, control individual persistente,
ficha e icono original (idéntico en430), gateway valida identidad y JSON
completo. Catálogo mínimo **56 /49 fichas**, C0 **240 / C8 254** intactos.
32 Python /348 Node y build web correctos. Node nativo no consigue egress
validado aquí; descarga real comprobada por Python, transporte Node y
sesión/gateway con mocks. VPS y Android/Termux físicos pendientes.

427 usa otra API con cabeceras nativas, no integrada; la430 pública no las
requiere. El endpoint HTTP7676/GCM del script del usuario sigue sin respuesta
real, no se confunde con esta receta. Sigue pendiente export SKS real/ruta UI;
no hay texto propietario/Cloud por ID nuevo. Herramientas y evidencia en
`apps/TunnelDOOM_VPN/`, sin binarios/datos reales en Git ni APK/novedad/VPS
publicados automáticamente. **Este estado sustituye el remoto pendiente de
TunnelDOOM descrito en los registros históricos siguientes.**

## TunnelDOOM VPN 4.2.4 (424) — 2026-10-26

PR **#102**, rama `feat/ha-tunnel-plus-1-7-1-decoders`, base `d7d2f696`.
`apps/TunnelDOOM_VPN/`: catálogo activo `res/raw/noobdev.txt` Version3,
**1 servidor / 13 campos cifrados**. XOR SHA256/test_key en el exterior,
NoobPass/NoobCrypt AES256-CBC/IV0 en campos; documento entero igual a JCA,
CLI y worker. Metadatos/flags/desconocidos conservados, sin copiar cuentas
codificadas del APK. `.sks` reutiliza Fenix GCM/DES; contrato del parser
confirmado pero sin export real ni ruta UI activa comprobada de build424.
No se identifica texto propietario ni importación Cloud individual por ID.

Actualizador GET fijo identificado, **inaccesible desde este entorno**:
HTTP503 del proxy/envoy por fallo de conexión upstream. No se afirma que el
origen esté caído. CLI fijo con mocks; sin paridad remota ni broker público.
Ficha con PNG launcher original16328 bytes, `remote:null`, aun con global on.
Mínimo **55 / 49 fichas**; C0 **240**, C8 **254**, sin extensión nueva.
Ver README/ANALYSIS/TESTING/manifest, `tunneldoom_verify.py` y oracle JDK.
No fusionar, desplegar, publicar APK ni novedades automáticamente.

Estado más reciente PR #99 (2026-10-24): **MNR TUNNEL PLUS 3.1 (31)**, fuente
real GitHub plusfast 14.4 / 14 servidores / 119 redes frente al asset 1.0 /
9 / 112. Ambos completos iguales a JDK y worker, 1149 campos internos. Nuevo
`.stp`, clipboard y referencia online `mnrtunneludp://` con Firebase fijo;
online validado con mocks, referencia real/export/Android/Termux pendientes.
PNG original y switch individual preservando los anteriores. Mínimo **46 /
46 fichas**, C0 **240**, C8 **254**, 26 overrides. **50 Python / 309 Node** y
build web correctos. Ver MNR_TUNNEL_PLUS; no confundir plusfastapp con catálogo.
Sin fusión, despliegue, APK o C11. Los estados siguientes son históricos.

Estado más reciente del PR #99 (2026-10-24): HTTP Door 5.0 incorpora `.kyz`
al inventario de archivos, DES/XML sin contraseña de usuario. **No se identificó
catálogo de servidores**, por lo que no se añade proveedor/ficha. C0 **240**,
C8 **253**, 25 overrides; se mantienen **45 fichas** y se eleva el mínimo a
**45** para refrescar metadatos 44. Parser Java compartido de CREEB, script
Termux reproducible. Tres documentos sintéticos completos iguales a JDK y
worker; falta `.kyz` real y Android/Termux. 43 Python / 296 Node aprobadas.
Sin consultar localhost, desplegar, fusionar, APK o C11. Los estados siguientes
son históricos.

Estado más reciente del PR #99 (2026-10-24): BD NET VPN build 111 añadido
después de Aura, mínimo **44 / 45 fichas**, C0 **240 / C8 252**, 24 overrides.
`.bdnet` y `bdnet://` actualizados, campos internos y recuperación binaria
completos, PNG e interruptor persistente. Remoto real 56 / 19 / 255 frente
al incluido 57 / 20 / 257; no mezclar versiones. Ver BD_NET_VPN y la guía
de continuación. Los conteos de las fases siguientes son históricos.

Estado más reciente del PR #99 (2026-10-24): Aura Net build 19 añadido después
de APNA, catálogo mínimo **43 / 44 fichas**, C0 **240 / C8 252**. `.aura` ya
existía y conserva su ruta histórica; nuevas claves confirmadas, catálogo
real completo, PNG original e interruptor individual. Sin nuevo lector
offline Android. Ver Aura_Net_VPN y SERVER_VPN_NEXT_CHAT_GUIDE. Las fases
históricas de abajo conservan sus conteos.

Estado actual del PR #99 (2026-10-24): APNA añadido después de ANY/Speicers,
catálogo mínimo 42 / 43 fichas, C0 240 / C8 252. APNA tiene fuente remota
fija validada, PNG original y control individual; `.apnavpn`/`apnavpn://`
usan el lector derivado de DEX/SO (exportación real pendiente). Ver
`decoders/Python/apps/APNA_VPN/` y SERVER_VPN_NEXT_CHAT_GUIDE para la
evidencia actual; las fases históricas de abajo conservan sus propios conteos.

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

## Tunneltweak 6.2.1 — PR #96

En la misma rama `feat/austroplus-vpn-13-0-1-decoders` se incorpora la carpeta
`decoders/Python/apps/Tunneltweak/`: lectores separados, codec, red fija, bridge
de worker, icono exacto, manifest y documentación. `.tut` admite CBC, TTPBE1
GCM con contraseña aportada y XOR heredado del APK. El dispatcher aislado
conserva la salida de los motores genéricos DES/GCM anteriores; un TTPBE1
fallido no llega a esos motores. Credenciales de `.tut`: solo password por
stdin, usando los códigos PASSWORD_REQUIRED/AUTH_FAILED existentes; HC intacto.

Proveedor `tunneltweak`: GET HTTPS fijo con cabeceras originales 6.2.1/51.
Catálogo GCM/PBKDF2SHA256/10000 independiente del PBE de archivo /120000.
Descarga pública verificada: 1 servidor y 53 configuraciones, sobre y anuncio
conservados; paridad completa con métodos Java del APK. No existe en el APK
el fallback `data_encoded.txt`. Clave de suscripción opcional solo en CLI y
UUID Cloud con respuesta simulada: no se proporcionaron credenciales ni UUID
reales. No se presenta el catálogo público como todos los planes de la app.

Se amplían broker fijo con cabeceras estáticas, bridge/allowlist Python,
contrato, metadatos/icono y pruebas de credenciales. Versión mínima pública
11; QA incrementa desde ese mínimo, conservando overrides superiores. C0
continúa en 240, C8 en 246. Icono original 192×192, 31632 bytes. Android,
motores históricos y valores por defecto de habilitación no se modifican.

Verificación Tunneltweak: suite principal 694 (9 omisiones existentes), worker
11, VPS/QA 39, gates 4, Node 74 y build web correctos. CLI real y worker
coinciden con el documento Java completo; ZIP autónomo probado. El intento
de broker directo en este entorno falló por DNS EAI_AGAIN (también GitHub),
sin relajar la política; transporte probado con DNS controlado, pendiente
una prueba directa en VPS. No se despliega ni fusiona el PR.


## SuperFlash VPN 184.0.1 — catálogo versión 29

Proveedor `superflash-vpn`, paquete `speicers.diablo.vpn`, build 184. Dos fuentes
HTTPS fijas, descarga pareada íntegra, worker Python aislado, control administrativo
y PNG original 192×192. Catálogo público mínimo **29**, **31 fichas**.

SV5C v2/release 157: firma Ed25519 sobre hash de dominio, metadatos y todos los
registros; cada registro se abre con XChaCha20-Poly1305 y KDF HMAC-SHA256/AAD
ligados a propósito, índice, tamaño y hash de metadatos. Campos AES-256-CBC con
IV incluido y rotación Java inversa de ROT5. Conserva nombres opacos, campos
vacíos, tipos, listas, opciones xhttp en claro y propiedades desconocidas.
No devuelve éxito con solo los metadatos visibles ni omite registros fallidos.

HTTP 200 autorizado del 2026-10-22: **268 servidores / una entrada de usuarios**,
versiones **27 / 5**, ambos JSON completos iguales a la referencia independiente
nativa/libsodium/JDK. Assets: **234 / 1**, versiones **2 / 4**. CLI `--all` HTTPS,
stdin fuera del repo y worker aislado coinciden con el par completo.
**3 pruebas Python y 30 web aprobadas**, sin suites completas; transporte Node
controlado, HTTPS Python real. Herramientas ELF/JNI y ARM64 guardadas en
`scripts/apk_analysis/`. Disponible en código, pendiente de actualizar la VPS.
Ver README/TESTING/manifest de la aplicación; no se añade una ruta de archivos,
se fusiona el PR, despliega el servidor ni publica un APK o novedades.


## TurboMX VPN 143.1.26 — catálogo versión 30

Proveedor `turbomx-vpn`, paquete `turbo.mx.anuncios`, build 168. Dos fuentes
HTTPS fijas, descarga pareada, control administrativo, worker aislado e icono
PNG original 192×192. Catálogo público mínimo **30**, **32 fichas**.

SV5C v2/release 143, Ed25519, HMAC-SHA256, XChaCha20-Poly1305 y campos AES-CBC/
ROT5. Reutiliza la primitiva de SuperFlash con firma, clave y contexto TurboMX
confirmados por separado; conserva todos los campos y autentica cada registro.
SuperFlash mantiene sus valores/release 157 y ambos lectores rechazan el otro.

HTTP 200 autorizado del 2026-10-22: **268 servidores / una entrada de usuarios**,
versiones **18 / 3**, 2900 campos procesados / 2189 no vacíos. Ambos documentos
completos y assets (240 / 1, versiones 3 / 3) coinciden con la referencia nativa
original/libsodium/JDK, CLI y worker. **3 pruebas nuevas, 3 regresiones SuperFlash
y 31 web aprobadas**, sin suites completas. El CLI HTTPS `--all` y los procesos
son reales; transporte Node controlado. Herramientas y layouts por SHA-256
conservados. Disponible en código, pendiente de actualizar VPS; sin merge,
publicación APK, novedades automáticas ni ruta de perfiles exportados nueva.


## UT Loop Pro VPN 22.10.26 (65): lector offline y acceso remoto pendiente

PR #96 registra `ut-loop-pro-vpn` en el bridge y allowlist del worker aislado,
con lector propio en `decoders/Python/apps/UT_Loop_Pro_VPN/`. Abre el JSON completo
de copias GCM y verifica RSA PKCS#1 v1.5/SHA-256 más GCM en respuestas firmadas.
El catálogo inicial real (1 servidor / 1 tweak, Version 1.0) coincide íntegro con
JDK independiente, CLI y worker. Los métodos de solicitud OTA/premium requieren
credenciales oficiales suministradas por el operador y se prueban con transporte
controlado. No hay un formato de perfil exportado acreditado en este build.

El endpoint oficial devuelve desde este entorno HTTP 200/text/html (195 bytes,
Site Unavailable), no un catálogo firmado. El APK tiene acceso OTA con Play
Integrity y entitlement premium separado; ninguno se fabrica. La ficha conserva
el PNG original 601×601, SHA-256
`8f01bceeb6a4f352e0b5b17ffe43df37ff4c5c78aaaf250696e540ae3f779b17`, con
`remote:null`, sin registro de descarga pública o control administrativo remoto.
Mínimo de catálogo **31**, **33 fichas**, respetando la versión persistente
monotónica. No habilitarlo hasta validar la respuesta oficial y el canal de acceso.

Un auxiliar offline reproduce los banners SSH GCM/XXTEA, comprobado con JDK
sintético; no se convierte en extensión de archivo ni proveedor adicional.
`TESTING.md` y el registro de integraciones distinguen lo comprobado y pendiente.
No hay despliegue, publicación Android ni actualización automática de C11.


## Xhypher Tunnel Pro 43: catálogo completo y compatibilidad RENZ

PR #96 incorpora `xhypher-tunnel-pro` al worker privado, broker HTTPS fijo,
controles de proveedor y contrato de salida completa (Servers + Networks,
proveedor/kind coincidentes, rawText y structuredJson iguales). Fuente única:
`https://raw.githubusercontent.com/XyrussProject/infinite88/refs/heads/main/xhyphertunnelpro888.hs`.
Consulta autorizada del 2026-10-22: HTTP 200, **57 servidores / 1161 redes**,
Version **2.665**. Todo el JSON y 7363 campos no vacíos coinciden con JDK,
CLI HTTPS/stdin y worker aislado reales. El recurso inicial también coincide.

Los tipos 0/1/2 cubren AES-CBC/XXTEA, HKDF/Threefish y PBKDF2 con credenciales
invisibles. Se preservan ceros legítimos hasta el límite de bloque CBC.
Las primitivas se confirmaron en el SO actual y diez casos ARM64 se ejecutaron
sin JNI/red; no se confunde este formato sin autenticación criptográfica con
un sobre autenticado. README/TESTING/manifest documentan pruebas y límites.

Se mantiene la ruta RENZ `.xhypher` con ajustes limitados a este proveedor;
no hay extensión nueva, consulta de enlaces cortos ni uso de credenciales de
servicios incrustadas. El icono original exacto 512×512, 102502 bytes, tiene SHA-256
`f32f6d6c2044ee507741b4b389f53b9fc03922800deaac66cda1dd094ece9e72`.
Catálogo mínimo **32**, **34 fichas**; la versión efectiva sigue siendo monotónica.
La disponibilidad pública requiere actualizar la VPS. Esta entrega no publica
APK, novedades C11, merge ni despliegue.


## 7NET VPN 5.6: catálogo completo y herramientas recuperables

PR #96 añade el proveedor fijo `7net-vpn`, worker privado, contrato de documento
completo, fuente HTTPS exacta sin redirecciones, control administrativo e icono
PNG original de 190×190 / 13258 bytes. Catálogo mínimo **33**, **35 fichas**,
conservando switches y sincronización monotónica de la versión persistente.

La lectura oficial del 2026-10-22 dio HTTP 200, Version **40.19**, **76 servidores
/ 619 redes**. El JSON completo, 6025 campos conocidos / 4750 no vacíos, coincide
con JDK independiente, CLI HTTPS/stdin y worker aislado (`isPartial:false`,
502968 bytes). El catálogo inicial también coincide completo: Version 1.0,
92 / 634. Tres métodos confirmados: AES/XXTEA con desplazamiento de bytes,
Threefish/HKDF con tweak `(índice,0)`, y credenciales PBKDF2/XXTEA/AES-256-CBC.
Conservar el bloque CBC recupera seis campos por muestra que el recorte nativo
truncaría; sus flujos originales se compararon con ARM64 offline. No hay
presunción de autenticidad criptográfica de estos formatos.

Se conserva la ruta RENZ `.7net` y sus aliases, con una corrección puntual
para este perfil; no se cambia el inventario C0. **12 Python / 54 web aprobadas**,
sin suites completas. No se aportó una exportación real independiente. Lectores,
manifest y pruebas: `decoders/Python/apps/SevenNET_VPN/`. Herramientas persistidas:
`scripts/apk_analysis/`, verificador `sevennet_verify.py`, guía `RESTORE.md` y
referencias `tests/golden/sevennet*`. No se suben APK/SO, catálogos reales ni datos
descifrados. La integración queda en código del PR, pendiente de despliegue VPS.


## AM TUNNEL LITE VPN build 63: ficha pendiente, proveedor desactivado

> Actualización 2026-11-22: el lector se recuperó y el proveedor nuevo
> `am-tunnel-lite` se integró en la nube (versión pública 96); ver la
> sección `## AM Tunnel Lite AM (63)` al final de este documento. La
> ficha antigua (`am-tunnel-lite-vpn`, `remote:null`) se RETIRÓ el
> 2026-11-22 por decisión de Pedro (versión pública 97); su PNG era
> byte-idéntico al del proveedor nuevo, así que no se perdió nada.
>
> La sección histórica de abajo se conserva como registro de la
> investigación; la tarjeta ya no existe en el catálogo.

El PNG original de 479×440 / 30105 bytes sigue en el proveedor nuevo `am-tunnel-lite` (mismos bytes); el archivo `am-tunnel-lite-vpn.png` se eliminó junto con la tarjeta.
Catálogo mínimo **34 / 36 fichas**, respetando los switches y la versión
persistente. `remote:null` impide habilitarla mediante una disponibilidad
inyectada; el ID no está registrado en el broker ni el worker.

El núcleo Java protegido con LIAPP no permitió recuperar aún el lector de
`pdrv2.json`; **no hay un resultado completo ni cantidades verificadas de
servidores/redes**. La consulta al enlace extraído produjo timeout, sin status
HTTP verificado. No presentar esta incorporación como catálogo operativo.

El auxiliar de campos PUtils sí reproduce hexadecimal/XOR y UTF-8 modificado,
con 8 vectores JDK y casos de XOR ARM64 originales iguales. **4 tests Python y
43 web aprobados**, limitados al auxiliar y a la ficha desactivada. Herramientas
persistidas en `scripts/apk_analysis/` y `tests/golden/am_tunnel_lite*`;
`liapp_wrapper.py` recupera solo la primera capa nativa, no el DEX. Las notas
para continuar están en `decoders/Python/apps/AM_TUNNEL_LITE_VPN/ANALYSIS.md`.
No se añaden formatos/exportadores sin confirmar, ni se publican datos reales.


## CREEB VPN 50.0 (50), 2026-10-23

Proveedor offline `creeb-vpn`, carpeta `apps/CREEB_VPN/`. `.crev` y catálogo
usan XXTEA modificado compartido con el motor histórico, con dos claves fijas
y selección por contexto/pInfo, sin adivinación de claves. El nuevo override
C8/bot abre Servers además de Tweaks; C0 240 / C8 250 sin cambiar cer/cerv.
Security.Password y DeviceID son controles de importación posteriores.

Catálogo incluido real 1.0.0, 1 servidor / 1 ajuste, todo el JSON idéntico a
JDK/CLI/worker. Descarga remota **pendiente**: flujo Play Integrity en la app,
GET HTML «Site Unavailable», POST sin token HTTP 405 HTML. No se interpreta
como prueba de que el proveedor rechazó una atestación. No entra en allowlist
remota ni controles operativos. Tarjeta `remote:null` incluso si disponibilidad
es true; mínimo **36 / 38 fichas**, versión persistente monotónica conservada.

Launcher VectorDrawable original conservado, PNG renderizado 512×512 de 29433
bytes, SHA-256 `2ae4ed0b2b96fdf3dfbd0cc96ae0bd69ec0e0d983fd35bf5fd37d08b63217bf3`.
No se sustituye por iconos genéricos del APK. Ver receta, evidencias, pruebas,
limitaciones y comandos en README/ANALYSIS/TESTING de la app. 19 Python y 50
Node; `.crev` real pendiente, sin despliegue/Android/C11.

## GCP VPN 1.1 (11) — catálogo en la nube, versión pública 92

Proveedor fijo `gcp-vpn`, paquete `com.gcpvpn.net`, versionCode 11.
Carpeta `decoders/Python/apps/GCP_VPN/` con `server_catalog_decoder.py`,
`codec.py`, `file_decoder.py`, PNG original, manifest, README y TESTING.
Sigue el patrón 7NET (broker HTTPS fijo, worker aislado, contrato de
documento completo, control administrativo individual, gateway
enriquecido), pero **sin codec propio por campo**: no hay evidencia del
APK para una tabla de modos propia, y la ruta RENZ genérica de
`decoders/Python/renz.py` (perfil `gcpvpn`) ya descifra el catálogo en
vivo. El sobre exterior es Base64 → AES-128-CBC → XXTEA propio →
restar 2 por byte; los campos anidados usan el pase recursivo genérico
(hosts Threefish/HKDF, credenciales PBKDF2-XXTEA-AES, resto modo
principal). La ruta `.gcpvpn` / `gcpvpn://` es la canónica RENZ y no
cambia.

Lectura pública autorizada del 2026-11-19: HTTP 200,
**505176 bytes, SHA-256
`fff27a6d2a7bdb23275fdcd3bd947baaddc70dda73e89921e1421c156fb8044e`,
Version 3304, 90 servidores / 334 redes**, 2736 campos descifrados por
el pase recursivo; 81/90 servidores traen credenciales que abren con
el modo sensible. Los 51 campos cortos de presentación
(`Servers[].Name`/`Subname`, `Networks[].Info`) se sirven como están.
`SlowDNS.PubKey` (10) abre con el modo principal a una clave hex de
64 caracteres — el mismo despacho que el codec 7NET documenta para
ese campo — y **no** con speciale (que devuelve basura no imprimible);
el diff de fallback propuesto en el dossier se evaluó con el catálogo
en vivo y se **revirtió** por diagnóstico incorrecto (ver
`INTEGRATION_CLOUD.md`). Sin rotación de claves. HMAC de autenticación
de conexión: `NOT_OBSERVED`.

PNG original exacto del icono launcher `res/i/ca.png`: 240×240,
2863 bytes, SHA-256
`d65fec4b2cf0bf4325235b7a676c913b587e5f438a8313342fbbd1560a040a3a`.
Catálogo mínimo **92**; conserva switches y versión persistente.
**4 tests Python y 6 web nuevos aprobados**; regresión RENZ completa
sin cambios salvo 1 fallo preexistente (`wyrvpn://`, verificado en
HEAD limpio) y suite Node completa con solo fallos preexistentes /
uno flaky (DTunnel, pasa aislado). No se aportó una exportación real
independiente (`.gcpvpn` real o `gcpvpn://` real pendientes); estado
`VERIFIED_SYNTHETIC`. Sin despliegue, fusión ni cambios Android.

## NetFlux VPN 1.1 (11) — catálogo en la nube, versión pública 94

Proveedor fijo `netflux-vpn`, paquete `app.netfluxvpn.net`, versionCode 11.
App SEPARADA de GCP VPN (`com.gcpvpn.net`): proveedor propio, sin fusión
ni cambios en la entrada `gcp-vpn`, la tarjeta GCP ni el módulo
`GCP_VPN`. Carpeta `decoders/Python/apps/NETFLUX_VPN/` con
`server_catalog_decoder.py`, `codec.py`, `file_decoder.py`, PNG original,
manifest, README y TESTING. Sigue el patrón 7NET/GCP (broker HTTPS fijo,
worker aislado, contrato de documento completo, control administrativo
individual, gateway enriquecido), pero **sin codec propio por campo**: no
hay evidencia del APK para una tabla de modos propia, y la ruta RENZ
genérica ya descifra el catálogo en vivo. El sobre exterior es Base64 →
AES-128-CBC → XXTEA propio → restar 2 por byte; los campos anidados usan
el pase recursivo genérico (hosts Threefish/HKDF, credenciales
PBKDF2-XXTEA-AES, resto modo principal). La ruta `.netflux` /
`netfluxvpn://` despacha EXPLÍCITAMENTE al perfil existente `gcpvpn`
de `decoders/Python/renz.py` — sin perfil nuevo, por regla de
arquitectura (una actualización de catálogo, archivos o textos en el
servidor no toca la APK) — con el MISMO material de claves que `gcpvpn`
y URL propia
`https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/netflux`.

Lectura pública autorizada del 2026-11-20: HTTP 200,
**505176 bytes, SHA-256
`fff27a6d2a7bdb23275fdcd3bd947baaddc70dda73e89921e1421c156fb8044e`,
Version 3304, 90 servidores / 334 redes** — blob byte a byte IDÉNTICO
al de `gcpvpn2026`, por lo que el pase recursivo descifra los mismos
2736 campos y sirve como están los mismos 51 campos cortos de
presentación (`Servers[].Name`/`Subname`, `Networks[].Info`).
`SlowDNS.PubKey` (10) abre con el modo principal a una clave hex de
64 caracteres. Sin rotación de claves. HMAC de autenticación de
conexión: `NOT_OBSERVED`.

PNG original exacto del icono launcher `res/h/cd.png`: 240×240,
51006 bytes, SHA-256
`0fd1bf191d2d162c458ed032c53e96da55e5d13d94931f26eab0d9a20610898a`.
Catálogo mínimo **94**; conserva switches y versión persistente.
**5 tests Python y 6 web nuevos aprobados** (el Python añade el
round-trip de enlace `netfluxvpn://` al patrón de 4 de GCP).
Sin despliegue, fusión ni cambios Android.

Pendiente fuera de esta entrega: fila `.netflux` en
`docs/cloud/C0_FORMAT_MATRIX.csv` como documentación (el conteo ya
cuadra en 277 porque el test `file-formats.test.mjs` deriva los
conocidos de `_C8_FILE_ENGINES` en `engine.py`, que incluye `netflux`).
Los contadores de inventario RENZ se mantienen en 16 sufijos /
23 protocolos / 14 perfiles por decisión de arquitectura (las
actualizaciones de catálogo, archivos y textos en el servidor no tocan
la APK); no hay que actualizarlos. No se aportó una
exportación real independiente (`.netflux` real o `netfluxvpn://`
real pendientes); estado `VERIFIED_SYNTHETIC`.

## PM Tunnel Lite 1.0 (10) — catálogo en la nube, versión pública 95

Proveedor fijo `pm-tunnel-lite`, paquete `com.pmtunnel.app`,
versionCode 10. Carpeta `decoders/Python/apps/PM_Tunnel_Lite/` con
`server_catalog_decoder.py`, `codec.py`, `file_decoder.py`, PNG
original, manifest, README y TESTING. Sigue el patrón 7NET/GCP/NetFlux
(broker HTTPS fijo, worker aislado, contrato de documento completo,
control administrativo individual, gateway enriquecido), pero con
**codec propio standalone**: la estructura y el delta XXTEA
(`0x7a56d3e1`) coinciden con la ruta RENZ, pero el material de claves
(`PASSWORD`, `FIXED_SALT`, `IV`) es distinto de todas las entradas de
`RENZ_KEYS` (p. ej. `gcpvpn`), así que el perfil compartido no abre
este catálogo; y no se registra ningún perfil nuevo en
`decoders/Python/renz.py` por regla de arquitectura (una actualización
de catálogo, archivos o textos en el servidor no toca la APK). El
sobre exterior es Base64 → AES-128-CBC → XXTEA propio → restar 2 por
byte; los campos anidados usan la tabla explícita de modos 0/1/2
(hosts Threefish/HKDF, credenciales PBKDF2-XXTEA-AES, resto modo
principal, incluidas las secciones anidadas `SlowDNS`/`V2Ray`/
`UDPOptions`, verificadas modo a modo contra el catálogo en vivo).
La ruta `.js` NO se registra como formato de archivo (sufijo
genérico; el despacho es solo por sufijo, sin detección por
contenido) y `pmtunnellite://` despacha por bloque explícito en
`text_bridge.py`, como `netfluxvpn://`.

Lectura pública autorizada del 2026-11-22: HTTP 200,
**140224 bytes, SHA-256
`d09b5d7304ec70561a6871cd0ee6ca08f3a5ad6a713b77977c7c840e2698a82d`,
Version 159, 10 servidores / 151 redes** — re-fetch ~16:10 Tijuana
con bytes idénticos a la descarga de las 04:10. 915/915 campos no
vacíos descifran (modo 0: 694, modo 1: 155, modo 2: 14; anidados: 52);
0 sin descifrar. 6/10 servidores traen credenciales que abren con el
modo sensible. No existe flag libre/premium en el catálogo. Sin
rotación de claves. HMAC de autenticación de conexión:
`NOT_OBSERVED`.

PNG original exacto del icono launcher del XAPK: 512×512,
295765 bytes, SHA-256
`cd38af8be4d17162c0481008f7a7882b287d7dc5731d3fee3b794b315f43218d`.
Catálogo mínimo **95**; conserva switches y versión persistente.
**8 tests Python y 5 web nuevos** (el Python añade known-answers del
catálogo empaquetado `e.js`, redacción de credenciales y round-trip
`pmtunnellite://`). Sin despliegue, fusión ni cambios Android.

## MAYA TUN PRO 43.0 (43) — catálogo en la nube, versión pública 95

Proveedor fijo `maya-tun-pro`, paquete `maya.tun.udp`, versionCode 43.
Carpeta `decoders/Python/apps/Maya_Tun_Pro/` con
`server_catalog_decoder.py`, `codec.py`, PNG, manifest, README y
TESTING — **sin `file_decoder.py` a propósito**: los archivos `.maya`
siguen su ruta C0 congelada (`C0_FORMAT_MATRIX.csv` fila 80 →
`decoders/Python/maya.py` → `_noobcrypt.decrypt_profile`); un wrapper
sería código muerto y el precedente `RMP_TUNNEL_PRO` envía módulos
solo-catálogo igual. Sigue el patrón GCP/NetFlux (broker HTTPS fijo,
worker aislado, contrato de documento completo, control administrativo
individual, gateway con rama propia Servers+Tweaks — la rama RENZ de
`c3-gateway.mjs` exige `Networks` y NO aplica a Maya). El sobre
exterior es Base64 → AES-256-XTS modo 5 (tweak = primeros 16 B, clave
de 64 B derivada del `.rodata` de `libovpn3.so`); los campos internos
usan la clave `maya` existente de `_noobcrypt.py` (GCM modo 0, CBC
modos 1/4). La ruta `maya://` despacha EXPLÍCITAMENTE a
`codec.decode_text` (ChaCha20-Poly1305 modo 3 sobre los bytes `.maya`,
misma clave; los bytes descifrados abren por la ruta de archivo
existente). Sin perfil nuevo en `renz.py` y sin cambios en `android/`.

Lectura pública autorizada del 2026-11-22: HTTP 200,
**454,716 bytes, SHA-256
`131869d6027906f3cfcadfbc96bf81db9479435ad54a6b069ef80f84668b4806`,
Version 1.3.41, 27 servidores / 376 tweaks** — 2,449 campos Base64
internos, 0 sin descifrar (el recuento de NOTES.md decía 2,402 por
una regla de conteo distinta; el blob es byte-idéntico). Sin marca
libre/premium en el catálogo (`NoobLevel` no separa libre/premium).
Sin rotación de claves. HMAC de autenticación de conexión:
`NOT_OBSERVED`.

PNG del icono launcher del XAPK 43.0, remuestreado Lanczos 300×300 →
512×512, 216,321 bytes, SHA-256
`7749e091a93dba4bb5f64372c8b4d795aabf621e2af8ea2112aca412eeaa2e00`
— NO son los bytes exactos del APK (original 300×300, 47,275 bytes,
SHA-256 `57f6a6f79829f4eb8336fb7d127a1043d11efe921c1f3f5093b06e9532b488a6`);
pendiente de confirmación del owner. Catálogo mínimo **95**; conserva
switches y versión persistente. Tests Python y web nuevos aprobados
(ver TESTING.md). Sin despliegue, fusión ni cambios Android.

Pendiente fuera de esta entrega: una exportación `.maya` real o un
enlace `maya://` real del teléfono de Pedro (archivos
`VERIFIED_STATIC`, texto `VERIFIED_SYNTHETIC`).

## RMP Tunnel Lite RMP-4 — catálogo en la nube, versión pública 95

Proveedor fijo `rmp-tunnel-lite`, paquete `com.rmptunnel.lite`, versionCode 4.
App SEPARADA de RMP TUNNEL PRO (`com.rmptunnel.pro`): proveedor propio, sin
fusión ni cambios en la entrada `rmp-tunnel-pro`, la tarjeta PRO ni el módulo
`RMP_TUNNEL_PRO`. Carpeta `decoders/Python/apps/RMP_Tunnel_Lite/` con
`server_catalog_decoder.py`, `codec.py`, `file_decoder.py`, PNG original,
manifest, README y TESTING. Sigue el patrón 7NET/GCP/NetFlux (broker HTTPS
fijo, worker aislado, contrato de documento completo, control administrativo
individual, gateway enriquecido), pero **sin codec propio de catálogo**: el
catálogo reutiliza el motor `python-shared-mx-xxtea` ya integrado para PRO
(`codec.py` delega en `../RMP_TUNNEL_PRO/codec.py`, que delega en
`../Mx_Tunnel_PRO/codec.py` y las primitivas `../HX_Tunnel_VPN/`). La Lite
comparte ese motor con PRO — verificado desde su propio APK, no asumido: su
asset `gremlin.json` es byte-idéntico al de PRO (versión 3.8, 40 servidores,
1211 payloads) y sus bytes en vivo son idénticos a los de RMPPRO en vivo.
La única divergencia es la URL propia
`https://raw.githubusercontent.com/pipoyrichards/RMPSYSTEM/refs/heads/main/RMPLITE`,
con agent propio `RMP TUNNEL LITE/RMP-4` (el de la app, verificado en vivo).

Lectura pública autorizada del 2026-11-22: HTTP 200, **723808 bytes, SHA-256
`a977755b358fa69010dc3cc54005c60150fa33ca8577dcb5d2ba233fb81b99b0`,
Version 10.3, 40 servidores libres / 1255 payloads** — blob byte a byte
IDÉNTICO al de `RMPPRO` en vivo. Re-verificación en vivo el mismo día:
**723984 bytes, SHA-256
`8f61ee74773551c9fd596b557b1726e0539205e1d0b9e3c24655f1decbbeb55d`,
Version 10.4, mismos conteos** (40 libres, 0/0/0 premium/vip/private,
1255 payloads); los bytes siguen siendo idénticos a los de RMPPRO en vivo.
Sin rotación de claves. HMAC de autenticación de conexión: `NOT_OBSERVED`.

La ruta `.rmplite` / `rmplite://` es NUEVA para Lite (PRO no tiene ruta de
archivos): una línea hex → XOR con la clave de formato de 12 bytes
`4%PdXch>fkP]` → texto JNI modified UTF-8 → JSON de tweak. Verificada con
oráculo nativo Unicorn en ambas direcciones; sin muestra real, estado
`VERIFIED_SYNTHETIC`. `.ovpn`/`.conf` son passthrough (core OpenVPN, sin
cifrado RMP). `server.psi` es PARTIAL y no tiene decoder. El sufijo
`rmplite` se registra en `_C8_FILE_ENGINES` (`engine.py`) y el esquema
`rmplite://` despacha explícitamente en `text_bridge.py`; nada se registra
en `renz.py` ni en `android/`.

PNG original exacto del icono launcher `res/drawable/ic_app_icon.png`:
512×512, 67222 bytes, SHA-256
`157565e9f1d1aafdb1b4cb90da76f9e844088137d30e4a285b73d38a1932f0b1`.
Difiere del icono de PRO. Catálogo mínimo **95**; conserva switches y
versión persistente. **Tests Python y web nuevos aprobados** (ver
`decoders/Python/apps/RMP_Tunnel_Lite/TESTING.md`). Sin despliegue,
fusión ni cambios Android.

Pendiente fuera de esta entrega: una exportación `.rmplite` real o un
enlace `rmplite://` real del teléfono de Pedro (estado actual:
`VERIFIED_SYNTHETIC`); `server.psi` sin resolver; fila `.rmplite` en
`docs/cloud/C0_FORMAT_MATRIX.csv` como documentación (el conteo ya
cuadra en 278 porque el test `file-formats.test.mjs` deriva los
conocidos de `_C8_FILE_ENGINES` en `engine.py`, que incluye `rmplite`).

## AM Tunnel Lite AM (63) — catálogo en la nube, versión pública 96

Proveedor fijo `am-tunnel-lite`, paquete `app.vpn.amtunnellite`, versionCode 63.
App distinta de la ficha antigua `am-tunnel-lite-vpn` (`remote:null`, retirada 2026-11-22 por decisión de Pedro): proveedor
propio, sin fusión ni cambios en esa tarjeta. Carpeta
`decoders/Python/apps/AM_Tunnel_Lite/` con `codec.py`, `file_decoder.py`,
`server_catalog_decoder.py`, PNG original, manifest, README y TESTING. Sigue el
patrón 7NET/GCP/NetFlux (broker HTTPS fijo, worker aislado, contrato de documento
completo, control administrativo individual, gateway enriquecido), con codec
propio standalone (stdlib, sin `renz.py`): Base64 → XXTEA con la clave estática
`'...|...'` y el delta NO estándar `0x9E5729B1` (con el delta estándar `0x9E3779B9`
el catálogo no abre).

Lectura pública autorizada del 2026-11-22: HTTP 200, **163960 bytes Base64,
SHA-256 `38cca53786aa61f5842202b649b8e8a3bdff7aa6fa03ce9a34d387f2b31d49da`,
Version 4.6, 172 servidores libres (3.341 endpoints) / 137 payloads, 0/0/0
premium/vip/private** — bytes idénticos en dos descargas independientes el mismo
día. Catálogo embebido `assets/pdrv2.json`: Version 1.5, 165 servidores,
128 payloads, abre con el mismo esquema y clave. HMAC de autenticación de
conexión: `NOT_OBSERVED`.

El servidor corta cada respuesta a múltiplos de 16 KiB y cierra la conexión, así
que la descarga es por rangos de 16 KiB con reanudación y reintentos, con la UA
Android exacta del script (sin ella, 403): en el broker
(`server-vpn-provider.mjs`, `downloadAmTunnelLite`, 206 + `Content-Range`) y en
el CLI/worker (`codec.fetch_catalog`). Un GET plano verificado en vivo se corta
a 98.304–114.688 bytes y se aborta; el broker nunca entrega un catálogo
truncado (el worker rechaza el XXTEA incompleto). **Reserva de tiempo:**
observado 11–18 s vía proxy de la VM, cerca del tope de 20 s del worker de
archivos — pero el catálogo usa el worker de catálogos (límite 120 s) y el
broker tiene su propio plazo de 30 s. **No se sube ningún tope.**

La ruta `.pdtv2` es NUEVA: `pdrv2.json` es la copia local del catálogo (mismo
formato exterior que el remoto); se registra en `_C8_FILE_ENGINES`
(`engine.py`) y en `file-formats.json`. Los 1.000 assets `wg/am*.conf`
embebidos parsean (`Endpoint`/`Hash1`/`Hash2`) con `file_decoder.py --wg`
(uso directo/CLI, sin sufijo registrado: son assets internos del APK, no un
formato de importación). **Sin importación por el usuario y sin esquema de
texto:** nada se registra en `text-formats.json` ni en `text_bridge.py`;
`udp://*` son opciones de DNS, no enlaces de importación. Nada se registra en
`renz.py` ni en `android/`.

PNG original exacto del icono `res/drawable/ic_app_icon.png`: 479×440,
30105 bytes, SHA-256 `ad8aab869a41fd23aa1bff5c976c589ae73738192a8d475c3fcc36edd1da2d7a`.
No existe un icono 512×512 en el APK; no se redibujó ni reescaló. Catálogo
mínimo **96**; conserva switches y versión persistente. **Tests Python y web
nuevos aprobados** (ver `decoders/Python/apps/AM_Tunnel_Lite/TESTING.md`). Sin
despliegue, fusión ni cambios Android.

Pendiente fuera de esta entrega: una exportación `pdrv2.json` real del teléfono
de Pedro (la ruta es `VERIFIED_REAL` por el catálogo remoto + embebido, no por
exportación de usuario — la app no tiene importación por el usuario);
confirmación extremo a extremo en un dispositivo; codificación de campo del
token de cuenta superior (`Username` == `Password`, 16 B) sin recuperar.
La ficha antigua `am-tunnel-lite-vpn` se retiró 2026-11-22 por decisión de Pedro.

## HTTP WinzapVPN 1.1.61 (76) — catálogo en la nube, versión pública 98

Proveedor fijo `winzap-vpn`, paquete `com.winzap.winzap_vpn`, versionCode 76.
Carpeta `decoders/Python/apps/WinzapVPN/` con `server_catalog_decoder.py`,
`codec.py`, PNG, manifest, README y TESTING — **sin `file_decoder.py` a
propósito**: la app no registra sufijo de archivo ni importa
configuraciones por archivo; tampoco hay esquema de texto (`winzap://` no
existe), así que nada se registra en `file-formats.json`,
`text-formats.json`, `text_bridge.py` ni `_C8_FILE_ENGINES`; el precedente
`RMP_TUNNEL_PRO`/`Maya_Tun_Pro` envía módulos solo-catálogo igual. Sigue el
patrón GCP/NetFlux/Maya (broker HTTPS fijo, worker aislado, contrato de
documento completo, control administrativo individual, gateway con rama
propia `countries`+`servers` — la rama RENZ de `c3-gateway.mjs` exige
`Servers`/`Networks` y NO aplica a Winzap). El bootstrap es JSON en claro
por HTTPS, sin firma ni autenticación; el codec valida la estructura y
redacta todo lo que no es catálogo (sesión por dispositivo, controles de
anuncios, notificaciones, URLs de assets, tokens por servidor como
`change_token`). El blob `Winzap01` (`encrypted_mobile_config` del perfil)
es Base64 → `Winzap01` + salt(8) + AES-256-CBC con clave/IV
EVP_BytesToKey-MD5 sobre la clave maestra de la app, con campos de capa 3
AES-256-CBC + ROT13 y claves cortas renombradas a largas. Sin perfil nuevo
en `renz.py` y sin cambios en `android/`.

Lectura pública autorizada del 2026-11-23: HTTP 200, **249,350 bytes,
SHA-256 `85272d084d9cb89a8bf25659c5e2a0a484e593ce8aca40ecc50e1cef2cfd0b49`,
`config_version` 1, 19 países, 177 servidores, 0 VIP** — dos descargas
seguidas byte-idénticas (solo los contadores volátiles `online_users`
cambian entre ventanas). El catálogo creció desde la ventana del
2026-11-22 (174 servidores): 3 altas, 0 bajas. El servidor anuncia
`latest_version` **1.1.62** — un build más nuevo que el 1.1.61 analizado;
no se afirma compatibilidad con él. El bootstrap sin `device_id` responde
422 (`Field required`); el perfil por servidor exige la firma HMAC-SHA256
de la app (no reproducida ni falsificada) y responde 401 sin ella, así que
el catálogo completo de configuraciones queda PENDING. HMAC de
autenticación de conexión: `NOT_OBSERVED`.

El puerto no estándar (2083) y el `device_id` obligatorio obligan a un
descargador dedicado en el broker (`server-vpn-provider.mjs`,
`downloadWinzapVpn`, `pinnedRequest` directo): la ruta genérica rechaza
cualquier puerto distinto de 443 y `downloadSupplied` también rechaza
`url.port`; mismo patrón que AM Tunnel Lite / OpenTunnel / Tunneltweak.
La rama de despacho va antes de la comprobación genérica de puerto y el
id está en la lista de rechazo de redirecciones. El `device_id` es el id
de prueba sintético verificado `WINZAP-TEST0001`; si el owner emite un id
dedicado de SP-DECODE, se cambia en 4 lugares de producción (`codec.py`
`CATALOG_URL` y `DEVICE_ID`, `manifest.json` `catalog.source`, y la URL
de `PROVIDERS` en `server-vpn-provider.mjs`) más los fixtures de pruebas.

PNG del icono launcher del .apks 1.1.61, **bytes exactos del APK**
(`res/mipmap-xxxhdpi-v4/ic_launcher.png`, 192×192, **21,447 bytes**;
SHA-256 `319b2dbfdf696276d87c6135c104113e750b4dbb663f96b1e9fc6573d4d538ea`),
no remuestreado a 512×512. Catálogo mínimo **98**; conserva switches y
versión persistente. **Tests Python y web nuevos aprobados** (ver
`decoders/Python/apps/WinzapVPN/TESTING.md`). Sin despliegue, fusión ni
cambios Android.

Pendiente fuera de esta entrega: un blob `Winzap01` real
(`encrypted_mobile_config` de un perfil) para cerrar el blob como
`VERIFIED_REAL` (hoy `VERIFIED_SYNTHETIC`); cabeceras firmadas válidas de
una sesión real de la app para descargar perfiles por servidor; build
1.1.62 anunciado por el servidor, sin analizar; prueba en VPS tras el
despliegue autorizado (`update all`).

## B SHIELD NET 2.9 (29) — catálogo en la nube, versión pública 99

Proveedor fijo `bshield-net`, paquete `xyz.bshieldnet.org`,
versionCode 29. App de la familia RENZ (base v2rayNG + RENZ).
Carpeta `decoders/Python/apps/BShieldNet/` con
`server_catalog_decoder.py`, `codec.py`, `file_decoder.py`,
`bshieldnet.py` (script entregable original), PNG, manifest,
README y TESTING. Sigue el patrón GCP/NetFlux (broker HTTPS fijo,
worker aislado, contrato de documento completo, control
administrativo individual, gateway enriquecido), pero **sin perfil
nuevo en `renz.py`**: el perfil `bshield` (semilla, IV, sal, URL
del catálogo, sufijo `.bshield`, esquemas `bshieldnet://` /
`bshield://`) YA estaba registrado (integración RENZ/7NET, oct
2026), `.bshield` YA estaba en `file-formats.json` y en la matriz
C0, y el perfil YA estaba en la tabla Android. Esta entrega solo
añade el **catálogo vivo como proveedor** y las dos entradas de
texto en `text-formats.json` (que faltaban); nada bajo
`android/` cambia. El sobre exterior es Base64 → AES-128-CBC →
XXTEA custom (delta 0x7A56D3E1) → restar 2 por byte → JSON; los
campos anidados usan el pase recursivo genérico (modos 0/1/2/3).
El generador inverso está verificado: re-cifrar el plaintext vivo
reproduce el blob original byte a byte. Matiz del motor RENZ
compartido: el pase recursivo NO es idempotente (re-cifrar un
catálogo YA descifrado cambia 156 hojas); no afecta al uso real.

Lectura pública autorizada del 2026-11-24: HTTP 200,
**911,897 bytes, SHA-256
`17975a398ea527e2768cc3aa8662e091a66c9072ad464d3d4048d85cbc127b9b`,
Version 7.34, 90 servidores / 792 networks** — dos descargas
seguidas con el mismo blob y el mismo descifrado. URL fija
`https://raw.githubusercontent.com/snapb/B-SHIELD-NET-2026/refs/heads/main/b_shield_net_2026`
(GET plano, sin auth, sin firma; UA "B SHIELD NET", resultado
independiente del UA verificado). El catálogo completo lleva
credenciales de servidor: **NO va a Git, ni al ZIP, ni a Drive**,
solo como adjunto del chat (precedente Ways Tunnel). HMAC de
autenticación de conexión: `NOT_OBSERVED`.

PNG del icono launcher del XAPK 2.9, redimensionado Lanczos
240×240 → 192×192, **44,744 bytes**, SHA-256
`d5c5889522c25eca76109e033e555bc0f0767af0b4c3fd605497dc7e11e9bbea`.
Catálogo mínimo **99** (lo fija el coordinador al fusionar,
98 → 99; este staging NO sube `CATALOG_VERSION`). **Tests Python
y web nuevos aprobados** (ver
`decoders/Python/apps/BShieldNet/TESTING.md`). Sin despliegue,
fusión ni cambios Android.

Pendiente fuera de esta entrega: un `.bshield` real exportado por
la app y un enlace `bshieldnet://` (o `bshield://`) real para
cerrar archivos y textos como `VERIFIED_REAL` (hoy
`VERIFIED_SYNTHETIC`); prueba en VPS tras el despliegue
autorizado (`update all`).

## Ways Tunnel 18.1 (18) — catálogo en la nube, versión pública 99

Proveedor fijo `ways-tunnel`, paquete `com.ways.tunnel`, versionCode 18
(Pausa Studio). Carpeta `decoders/Python/apps/Ways_Tunnel/` con
`waystunnel.py` (codec original, verbatim), `server_catalog_decoder.py`,
`text_decoder.py`, PNG, manifest, README y TESTING — **sin
`file_decoder.py` a propósito**: la app no registra sufijo de archivo
ni importa configuraciones por archivo; tampoco hay entrada en
`file-formats.json` ni en `_C8_FILE_ENGINES`. Sigue el patrón
WinzapVPN/GCP/NetFlux/Maya (broker HTTPS fijo, worker aislado,
contrato de documento completo, control administrativo individual,
gateway en la rama RENZ `Servers`/`Networks` de `c3-gateway.mjs`).
El catálogo vivo es texto de glifos por HTTPS público
(glifos → Base64 → AES-256-CBC, clave SHA-256 del hex en mayúsculas
de `dam0n`, IV cero, PKCS7); el codec valida la estructura y redacta
todo lo que no es catálogo (credenciales de servidor `ServerIP` /
`ServerUser` / `ServerPass`, `ProxyIP`, `SlowChave`, `TokenAuth`,
`NameServer`, `udpserver` / `udpobfs` / `udpauth`, `OpenVPNConfig`,
`v2rayJson`, `SlowDns` de networks y el enlace de invitación
`WhatsApp`). El resultado JSON no lleva la API de descarga. Sin
perfil nuevo en `renz.py` y sin cambios en `android/`. Sin entrada en
`supplied-integrations.json`: como WinzapVPN/Maya/AM/PM/RMP/GCP/
NetFlux, los proveedores solo-catálogo no viven en supplied (supplied
exige un `fileModule`); la ruta de texto `wyst://` va por despacho
explícito en `text_bridge.py`, como `maya://` / `pmtunnellite://` /
`rmplite://`.

Lectura pública autorizada del 2026-11-24: HTTP 200, **276,225 bytes
UTF-8 (92,800 glifos) → 36,007 B JSON, SHA-256
`468725bbef20019fbd48d84b0029e5912ee30df8518b428413b5202305aa7b10`,
versión 1.0.49, 5 servidores, 78 networks** — dos descargas
reproducidas con bytes descifrados byte-idénticos. El endpoint fijo
es `raw.githubusercontent.com` (443, sin puerto no estándar), GET
plano sin cabeceras ni auth, exactamente como la app; el `?t=<millis>`
es solo anti-caché de la app y el broker no lo necesita, así que la
ruta genérica del broker basta (sin descargador dedicado) y el id va
en la lista de rechazo de redirecciones. HMAC de autenticación de
conexión: `NOT_OBSERVED`. Sin catálogo premium separado verificable:
v1.0.49 no tiene ningún campo VIP/premium y la app descarga este
único `config.json`.

Textos `wyst://` (tweaks): mismo AES/CBC con IV cero, clave de
`tweakdam0n`, parseo como JSONObject; estado **VERIFIED_SYNTHETIC**
(round-trip sintético; falta una muestra real `wyst://` para
VERIFIED_REAL). Entrada en `text-formats.json` (sufijo `wyst`, sin
formato de archivo asociado) + despacho en `text_bridge.py` +
`text_decoder.py:decode_text`.

PNG del icono launcher del .apks 18.1, **bytes exactos del APK**
(`res/drawable/icon.webp`, que son bytes PNG, 1280×1279,
**718,879 bytes**; SHA-256
`4394211fa756d4d31752aee9deeee10b284b881f29e0a012a925720a2e0af00e`),
no remuestreado a 512×512 (bajo el límite de 2 MiB). Catálogo mínimo
**99** (lo sube el coordinador, una sola vez 98 → 99); conserva
switches y versión persistente. **Tests Python y web nuevos
aprobados** (ver `decoders/Python/apps/Ways_Tunnel/TESTING.md`). Sin
despliegue, fusión ni cambios Android.

Pendiente fuera de esta entrega: un tweak `wyst://` real para cerrar
el tweak como `VERIFIED_REAL` (hoy `VERIFIED_SYNTHETIC`); muestras
`vmess://` / `vless://` en claro (hoy solo inferidas); prueba en VPS
tras el despliegue autorizado (`update all`).
