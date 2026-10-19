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
