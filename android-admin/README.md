# SP-DECODE Admin — servidor real

Aplicación Android nativa independiente, paquete `com.ghostdeveloper.spdecode.admin`, versión 1.0.0 (3). Conserva los colores AMOLED, las tarjetas, la navegación por secciones y los tres temas. El artefacto distribuible es **release**, con R8 y firma permanente. La variante de desarrollo utiliza `.dev` y no se distribuye.

## Integración

- Origen fijo: `https://panel.spdecode.xyz`. Los dominios público/API bloquean deliberadamente `/api/admin`; no se deben utilizar para el panel.
- Las rutas, métodos, límites, codificación de consultas y ejecución HTTPS residen en `admin_routes.cpp` y `admin_transport.cpp`, con JNI. TLS y la verificación de host usan `HttpsURLConnection` de Android. No hay redirecciones ni URL introducida por el usuario.
- Acceso por usuario/contraseña con la API administrativa existente. El servidor verifica las cookies, revocación, permisos y cambio obligatorio de contraseña temporal.
- Solo se conserva la sesión con vencimiento, cifrada con AES-GCM y una clave no exportable de Android Keystore. Las contraseñas no se guardan. Al restaurar, se valida `/api/admin/access` antes de mostrar información.
- No hay `PreviewState`, identidades precargadas, claves DEMO, métricas inventadas ni botones que cambien datos comerciales en memoria.

## Secciones y autoridad

| Sección | Fuente/acciones |
|---|---|
| Resumen | Sesión administrativa, servicios y métricas reales |
| Usuarios | Directorio paginado y búsqueda remota; detalles de la cuenta, compras, identidades, licencias, soporte, sesiones y créditos |
| Personal y cargos | Crear/editar personal, nombre/usuario/cargo, habilitar/deshabilitar, restablecer contraseña y cargos personalizados; contraseña temporal visible una vez |
| Soporte | Conversaciones autorizadas, mensajes del servidor, responder, cerrar/reabrir y asignar; actualización mientras la pantalla está activa |
| Finanzas/transacciones | Pedidos persistidos, totales completos de pedidos pagados por moneda; paginación y separación de entornos de pagos |
| Productos | Precios base, plazos y paquetes; escritura con revisión de versión para evitar sobrescribir cambios concurrentes |
| Licencias/API | Derechos existentes; revocar/restaurar y cambiar la IP pública del acceso API; restaurar exige pedido pagado y acceso vigente |
| Gift codes | Emisión real, historial/canjes y desactivación; código completo disponible una vez |
| Créditos | Movimientos reales del ledger; no se inventan abonos ni se cambian saldos locales |
| Catálogo | Disponibilidad real de proveedores y publicación del aviso de la versión actual mediante el flujo existente |
| Avisos | Feed real y publicación persistida; se informa si el servidor no pudo entregar push |
| Servidor | Reporte real de observabilidad; el alcance del contenedor web se distingue del VPS completo |
| Auditoría | Eventos reales permitidos al cargo |
| Seguridad/sesión | Identidad y cargo autenticados, cambio de contraseña del personal y cierre remoto de la sesión actual |
| Mantenimiento | Mantenimiento global y solicitud de limpieza mediante los endpoints existentes |

La emisión de licencias o claves comerciales no se simula: se muestran los derechos emitidos por los flujos del servidor. Los pagos y reembolsos siguen dependiendo de los proveedores y webhooks verificados. Las funciones de la maqueta sin contrato real (pagar manualmente, falsificar sesiones, generar licencias locales, ajustar créditos sin ledger) se eliminaron. La contraseña del propietario continúa administrándose en el VPS.

Los avisos de catálogo usan el flujo servidor/cliente existente, con sus traducciones. La publicación manual de avisos utiliza los campos y límites admitidos por el feed actual; no inventa traducciones ni capacidades de recepción push de esta APK administrativa.

## Backend requerido

Esta rama añade `/api/admin/mobile`, exclusivo para sesiones administrativas. GET permite órdenes, derechos y créditos a `billing.read`; POST de derechos/IP exige propietario y CSRF. Las consultas son parametrizadas, paginadas y limitadas al entorno configurado. Nunca devuelve digests ni claves completas. No añade tablas ni exige una migración nueva; requiere las migraciones comerciales existentes, incluida `007_staff_permissions.sql`.

Para usar estas tres secciones hay que desplegar el backend de **esta misma rama** en el VPS. No basta con instalar la APK. Los endpoints existentes pueden utilizarse si el VPS ya tiene su versión correspondiente. Un 404 en el nuevo endpoint se muestra como necesidad de actualizar el servidor.

## Firma y compilación

Workflow: `.github/workflows/android-admin-release.yml`.

Reutiliza exclusivamente los secretos existentes:

- `SPDECODE_SIGNING_KEYSTORE_BASE64`
- `SPDECODE_SIGNING_STORE_PASSWORD`
- `SPDECODE_SIGNING_KEY_ALIAS`
- `SPDECODE_SIGNING_KEY_PASSWORD`

No crea una firma alternativa. El workflow verifica el certificado del APK contra el extraído de esa misma keystore, ejecuta R8 y comprueba mapping, permiso INTERNET, paquete, alineación/ELF de 16 KB, apertura del APK release en Android 15 y pruebas instrumentadas. La keystore temporal se elimina incluso si falla el trabajo.

## Pruebas

`sh android-admin/tests/run-native.sh` y `sh android-admin/tests/run-jni-host.sh`: planificación y transporte JNI con una conexión HTTPS de prueba en memoria, sin credenciales reales. Comprueban origen fijo, cuerpo/headers POST, rechazo de cookies inyectadas, ausencia de sesión, redirecciones, UTF-8, errores, límite de respuesta y cierre de conexiones.

Backend: desde `cloud/web`, `node --test tests/mobile-admin.test.mjs tests/staff-console.test.mjs tests/c6-admin.test.mjs`.

Las pruebas de backend usan PostgreSQL embebido y cuentas sintéticas. No equivalen a una sesión real en producción. La comprobación autenticada contra el VPS y hardware físico se debe registrar por separado.
