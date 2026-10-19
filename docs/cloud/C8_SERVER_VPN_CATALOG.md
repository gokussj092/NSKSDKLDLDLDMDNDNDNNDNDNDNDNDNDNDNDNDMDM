# C8 — Catálogo de VPN, iconos originales y caché

- Base: `feat/cloud-c8-vps-installer-updater`, origen de motores: PR #95.
- Inventario C0 de 240 rutas: congelado. Extensiones extra: .rt, .gol,
  .ua, .nvpnc, .green, y .hxt con lector HX independiente.
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
- Los cuatro iconos disponibles y originales son NUR, 24clan, HX y MKK.
  El resto de proveedores NO debe mostrarse con iconos inventados: hay que
  extraerlos de sus APK de origen y revisar derechos de marca antes de Play Store.
- NUR mantiene su broker probado. 24clan, HX y MKK disponen ahora de su propio
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

Durante `sudo spdecode qa start` o `sudo spdecode qa services`, los tres proveedores fijos (24clan Green, HX Tunnel y MKK Hyper) se habilitan temporalmente junto a NUR para pruebas privadas autorizadas. Al ejecutar `sudo spdecode qa stop`, se restauran los interruptores anteriores y se revoca el acceso QA. No implica autorización de terceros para distribuir su contenido ni certificación de compatibilidad.

El catálogo Android se cifra y consulta como máximo cada 24 horas, pero el botón existente de **Actualizar** ejecuta una consulta completa (`knownVersion=0`) incluso con la misma versión para reflejar cambios de habilitación. Las actualizaciones automáticas normales siguen necesitando incrementar monotónicamente `CLOUD_SERVER_VPN_CATALOG_VERSION`. La disponibilidad de un botón no garantiza que el servidor remoto esté operativo o que la respuesta pueda descifrarse.

La APK QA mostrará códigos de error sanitizados por extensión (sin nombres de archivo ni credenciales) para distinguir fallos de transporte, configuración, sesión y descifrado. Los resultados reales de NUR se diagnostican con `sudo spdecode qa probe-nur` durante una sesión activa.
