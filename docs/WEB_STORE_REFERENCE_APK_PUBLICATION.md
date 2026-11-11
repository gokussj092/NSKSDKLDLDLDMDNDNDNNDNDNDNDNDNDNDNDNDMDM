# SP-DECODE — tienda con referencia HTML y APK públicos verificados

Referencia aprobada: archivo del usuario **Vista previa SP-DECODE (1).html**, 2026-11-10.
Rama: `feat/nuevas-integraciones`.

## Diseño adaptado

La tienda web real utiliza el tema AMOLED de la referencia: fondo #050706, paneles
#0d100e, bordes verde oscuro, acento #2fe07c, pestañas de productos, precio,
ahorro, características, limitaciones y resumen fijo de compra en escritorio.
Se conservan las cuatro familias: **Online**, **Offline**, **API** y **créditos**.
El carrusel por producto sigue siendo infinito y ocupa el ancho completo: las
flechas están **solo en escritorio, en los laterales**, y en móvil se puede deslizar.

No se copian literalmente las afirmaciones del prototipo sobre 239 formatos,
1.000 usuarios, actualizaciones, caducidad de créditos, favoritos o compatibilidad
universal que no estén verificadas. La edición Online utiliza el servidor y la
edición Offline solo soporta los formatos realmente integrados en su APK.
No se incorpora inicio de sesión por correo o contraseña: actualmente se utiliza
únicamente Google Auth, sin modificar sus credenciales ni el rol de PostgreSQL.

El HTML de referencia contiene un formulario de tarjeta y generación de licencia
simulados. **No se trasladan a producción**. El checkout se conecta a
`/api/store/quote` y `/api/store/checkout`, con impuestos, términos, sesiones,
validaciones y confirmación de pago por webhook. Nunca se genera una licencia por
pulsar un botón ni se aceptan números de tarjeta en el servidor de SP-DECODE.

## URLs y disponibilidad

- Tienda: `https://spdecode.xyz/store`
- Página principal: `https://spdecode.xyz/`, sección de descargas de ambas APK
- Descarga directa Online: `https://spdecode.xyz/api/downloads/online`
- Descarga directa Offline: `https://spdecode.xyz/api/downloads/offline`
- Información de la versión: añadir `?metadata` a cada URL de descarga.
- Antes de una publicación firmada se recibe HTTP 404, nunca una APK de pruebas.
- AAB de Google Play y actualizaciones internas son **independientes** del
  APK externo; el proceso público genera **solo APK**, sin Play updater.

La web monta el directorio host
`${SPDECODE_PUBLIC_APK_DIR:-/opt/spdecode/public-apks}` como
`/app/public-apks:ro`. El contenedor web no puede crear, modificar ni firmar
APKs. Las descargas aceptan exclusivamente las rutas online/offline y validan
el manifiesto de la publicación. Los hashes SHA-256 y el número de versión se
muestran antes de descargar.

## Política de compilación y respaldo

El servicio `spdecode android public-build` compila **una sola edición** usando
el SDK y Gradle del VPS. Antes de construir, comprueba:

1. Que `spdecode update all feat/nuevas-integraciones` haya instalado la fuente,
   la rama esté limpia y se use el **commit exacto** que pasó CI.
2. Que GitHub Actions informó `success` para ese commit y para el workflow
   firmado correspondiente. La información se obtiene con `gh api` usando
   autorización de lectura; las credenciales nunca se incrustan en la APK.
3. Que la firma PKCS12 persistente del VPS está configurada en
   `/etc/spdecode/signing.env`, sin generar otra clave.
4. Que el APK sea release firmado V2/V3, correctamente alineado, con paquete,
   número de versión y certificado esperados. Online además ejecuta las auditorías
   Cloud-only, secretos y provisioning; Offline no puede pedir INTERNET.
5. Que el `versionCode` sea **superior** al APK público anterior del mismo paquete
   y que el certificado firmado sea idéntico al anterior.

Solo entonces se prepara un slot alternativo, se verifica el SHA-256 y se
cambia el puntero `current` mediante sustitución atómica. Hay **dos slots
físicos por edición:** uno es el público vigente y el otro la **única copia
anterior**. La compilación fallida no toca el publicado. El rollback selecciona
el slot anterior sin reconstruir ni borrar nada más. Los APK no se guardan dentro
de la imagen web, en PostgreSQL ni en un volumen secreto.

### Prerrequisitos VPS

- Linux `x86_64`; SDK/NDK y Gradle mediante `spdecode android setup`.
- Más de 10 GiB libres para compilaciones; mayor memoria/swap recomendados.
- `gh` instalado y autenticado para lectura del repositorio privado y Actions.
- Firma persistente ya importada mediante
  `spdecode android signing configure /ruta/clave.p12 ALIAS`. Verificar que su
  huella corresponda a la app existente; **no generar una firma nueva**.
- En Online, dominio API y pins públicos HPKE válidos.
- `spdecode update web feat/nuevas-integraciones` y `spdecode status` antes
  de publicar para que la web reconozca el directorio de APK. Ninguna compra se
  habilita automáticamente.

### Secuencia para cada versión (después de CI verde)

```bash
spdecode backup
spdecode update all feat/nuevas-integraciones
spdecode status
spdecode android setup

# Desde GitHub Actions, obtener el ID de un run con success para el HEAD actual.
# Online: "SP-DECODE Branch Release APK Signed"
# Offline: "SP-DECODE Offline Native APK (unified branch, persistent signer)"
spdecode android public-build online --ci-run ID_ONLINE_EXITOSO
spdecode android public-status online
spdecode android public-build offline --ci-run ID_OFFLINE_EXITOSO
spdecode android public-status offline
```

Si hay una incidencia en una edición:

```bash
spdecode android public-rollback online
# o:
spdecode android public-rollback offline
```

El rollback cambia el puntero únicamente si existe una copia anterior con
manifiesto e integridad verificados. Nunca ejecuta Docker prune, toca los
contenedores de descifrado, reescribe el volumen PostgreSQL ni renueva credenciales.

## Pasarelas y Android

La interfaz conserva las marcas reales de Stripe, PayPal y Mercado Pago.
Solo se ofrecen para pago si su configuración, país y moneda están habilitados
en backend. Impuestos y total siempre se calculan de nuevo en el servidor.
La integración de compras dentro de Android requiere una fase posterior con
sesiones, derechos de usuario, entrega y tratamiento del método de compra
específico del canal de distribución. No copiar tarjetas del HTML ni exponer
tokens secretos en las APK.

## QA mínimo

- CI comercial: `npm test`, migraciones PostgreSQL y `npm run build`.
- CI publicación: pruebas del slot doble, rollback, fallo sin afectación, script
  shell, manifest, endpoint con rutas restringidas.
- CI release Android Online/Offline: compilación release y verificación real de
  firmas, paquete, permisos y auditorías.
- Verificación manual en Chrome Android y escritorio: desplazamiento del
  carrusel, cambio de producto y moneda, indicadores, inclusiones y exclusiones,
  resumen, impuestos y descarga con contenido `application/vnd.android.package-archive`.
- No anunciar descargas como disponibles mientras no se publique un APK firmado
  y verificado, ni simular compras exitosas.

**Estado de implementación:** código listo en la rama; NO es una publicación
efectuada. La activación y pruebas en el VPS y CI del commit final son obligatorias.
