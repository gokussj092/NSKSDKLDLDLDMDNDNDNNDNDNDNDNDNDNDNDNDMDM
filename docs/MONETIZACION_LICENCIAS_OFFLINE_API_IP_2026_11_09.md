# SP-DECODE — Licencias Offline, emisión manual y futura API vinculada a IP

**Fecha:** 2026-11-09  
**Rama de destino:** `feat/nuevas-integraciones` (rama Online).  
**Rama de origen para migrar Offline:** `feat/version-offline-apk` (no modificar).  
**Estado:** especificación de implementación, **no implantada en el VPS**.  
**Responsable de aprobación de pruebas:** propietario de SP-DECODE.

## 1. Alcance y decisiones

Se producirán dos APK autónomas desde un mismo repositorio:

| Producto | Destino | Ejecución | Red | Anuncios |
|---|---|---|---|---|
| SP-DECODE Online | Usuarios gratuitos | Descifrado mediante servidor | Obligatoria | Futuramente, con aprobación de red |
| SP-DECODE Offline | Clientes con licencia | Descifrado en dispositivo | Solo activación/re-activación | Nunca |

- **No** fusionar dos modos en una sola aplicación. Los APK requieren `applicationId` distintos, identidad visual identificable, instalación simultánea y pipelines de firma independientes.
- La versión Offline debe solicitar licencia en su **primera apertura**. Una vez activada, debe abrir y descifrar sin contactar al VPS y sin límite temporal de funcionamiento.
- Licencia personal de pago único con **tres dispositivos activos** (tres activaciones simultáneas como máximo, no tres aperturas ni tres intentos). La transferencia/reinstalación requiere mecanismo de recuperación.
- Primeras ventas: **emisión manual** en el panel administrativo tras verificar el pago por un canal externo. No integrar todavía checkout ni pagos automáticos. Registros de cortesía y pruebas no cuentan como ingresos.
- Futura tienda común para **dos líneas comerciales**: licencia Android Offline y acceso API restringido a una IP pública. Sus secretos, permisos y tablas de autorización son independientes.
- La API por IP **no** forma parte de la primera fase; solo registrar el contrato y reservar la separación de productos.
- Los formatos existentes fueron probados con archivos reales por el propietario; no deducir incompatibilidad del hecho de que existan aplicaciones todavía no integradas.

**Documentación complementaria:** `docs/MONETIZACION_ANUNCIOS_SPDECODE_ONLINE_2026_11_09.md` define la monetización exclusivamente de Online.

## 2. Estrategia de ramas y construcción Android

1. Base de trabajo: `feat/nuevas-integraciones`. Mantener intactos `main` y `feat/version-offline-apk` durante la preparación.
2. Inventariar los cambios de `feat/version-offline-apk`, y **portar selectivamente** motores nativos, recursos, vistas, tests y variante `offlineNative`. Las ramas han divergido; **no aplicar merge completo y automático** sin resolver el impacto sobre Online.
3. Configurar dos variantes Android explícitas; utilizar el nombre real existente `offlineNative` si ya está integrado en Gradle y una variante separada para Online. Examinar `build.gradle.kts`, CMake, Manifest, JNI, ProGuard y fuentes antes de cambiar.
4. Dos `applicationId` diferentes, misma marca pero nombre identificable para la offline (p. ej. "SP-DECODE Offline"). Fijar paquetes y firmas estables; no renombrar `applicationId` de la Online existente accidentalmente.
5. Retirar del APK offline: SDK publicitario, catálogo remoto, API de descifrado cloud, analytics no imprescindibles, Play Updates y los secretos de la variante online. Mantener únicamente tráfico TLS al endpoint de activación inicial y, si el usuario lo solicita, al de recuperación de dispositivo.
6. Tras activar, confirmar que el descifrador no envía archivos, resultados, claves VPN, credenciales o telemetría al servidor. El permiso `INTERNET` puede mantenerse para la activación, pero no implica comunicaciones posteriores.
7. Construir y firmar **dos artefactos APK** que se instalen uno junto al otro. Validar Android 7–16 conforme a los targets realmente soportados.

## 3. Modelo persistente y separación de productos

Usar una **base de datos transaccional** (preferentemente PostgreSQL), no un JSON local ni un contador en memoria/Redis como fuente única de verdad. Redis puede servir para rate limits o caché.

### Entidades

```text
products(id, code, type, enabled, max_devices, policy_version)
  code: SPDECODE_OFFLINE | SPDECODE_API_IP
  type: offline_device | api_ip

licenses(id, product_id, key_verifier, status, created_at,
         issued_by, order_reference, customer_contact_encrypted,
         max_devices, policy_version)
license_devices(id, license_id, device_public_key_hash,
                device_public_key, activated_at, released_at, status)
activation_challenges(id, license_id, nonce_hash, expires_at, consumed_at)
issued_certificates(id, license_id, device_id, signing_key_id, issued_at)
manual_orders(id, reference, amount, currency, paid_at, verified_by, license_id)
admin_audit(id, admin_id, action, resource_id, status, occurred_at, metadata_redacted)

# Reservado para fase API-IP:
api_credentials(id, product_id, token_verifier, allowed_ip,
                scopes, quota, status, expires_at, revoked_at)
api_usage(id, credential_id, period, accepted, rejected, bytes)
```

- `licenses.key_verifier`: HMAC-SHA256 del código de licencia normalizado con secreto **solo de servidor**. Generar el código con un CSPRNG, idealmente 192–256 bits. No almacenarlo en texto claro ni registrarlo en logs.
- `license_devices`: índice único `(license_id, device_public_key_hash)` y máximo de tres `status=active`; la operación de activación debe utilizar transacción con bloqueo apropiado (p. ej. `SELECT ... FOR UPDATE`) y ser idempotente por clave pública.
- La cancelación/reembolso impide **activaciones posteriores**. Una APK offline permanente que ya se activó **no se puede revocar inmediatamente** mientras permanezca desconectada: no prometer lo contrario.
- No exponer nunca las claves privadas de firma, HMAC de verificación, tokens completos o datos de clientes en GitHub, APK, logs o el panel después de emitirlos.

## 4. Primera fase: emisión manual desde el panel

### Pantalla propuesta: `Panel > Licencias y API`

Secciones:

1. **Licencias Offline:** tabla de licencias, estado, dispositivo(s) ocupado(s), fecha de emisión, referencia de pago manual y acciones auditables.
2. **Crear licencia:** producto fijo `SP-DECODE Offline`, cupos fijos `3`, duración de acceso `permanente`, referencia de operación, contacto opcional, notas internas mínimas.
3. **Entrega:** generar un código con CSPRNG y mostrarlo **una sola vez**; botón «Copiar licencia». No permitir volver a consultar el código íntegro; la pérdida obliga a regenerar bajo control administrativo.
4. **Ver dispositivos:** mostrar identificadores reducidos (no identificadores hardware invasivos), fechas de activación y opción de liberar cupo para otra instalación.
5. **Suspender / revocar:** registrar motivo interno y exigir confirmación. La revocación no destruye el estado offline de una instalación ya activada.
6. **API por IP:** apartado visible como «Próximamente», **sin** emisión de tokens ni rutas públicas aún.

Los operadores autorizados pueden emitir después de verificar pagos manuales. No asumir que el precio exacto tiene que estar dentro del certificado de licencia: es un dato comercial del pedido, no un permiso técnico. Precio de lanzamiento acordado: US$4.99 por tres equipos, pago único. Un futuro ajuste para nuevos compradores a US$6.99 se decidirá después.

### Seguridad del panel

- Reutilizar la sesión administrativa existente, con autorización por rol, comprobación de Origin/CSRF y `Cache-Control: no-store`.
- Enviar credenciales **solo por cuerpo HTTPS**, jamás por URL; aplicar rate limits, `Idempotency-Key` e historial inmutable de operaciones.
- Error de persistencia, falta de secretos, sesión no válida o llave de firma no disponible ⇒ **fallar cerrado**, sin emitir claves aparentemente válidas.
- Mostrar y registrar IDs de licencia, no el código completo. Desactivar trazas que expongan información de pago.
- Para la primera fase, **no aceptar cambios de cuota, duración ni producto desde el cliente**. El servidor fija esos atributos.

### Contratos previstos (no implementados en este documento)

```http
GET    /api/admin/licenses
POST   /api/admin/licenses
GET    /api/admin/licenses/:id/devices
POST   /api/admin/licenses/:id/suspend
POST   /api/admin/licenses/:id/revoke
POST   /api/admin/licenses/:id/devices/:deviceId/release
```

El panel podrá conectarse a estas rutas una vez que pasen las pruebas de permisos, concurrencia y persistencia. No crear rutas administrativas sin middleware de autenticación verificado.

## 5. Segunda fase: activación inicial en Android

### Interfaz

Al abrir por primera vez SP-DECODE Offline se muestra **Activar licencia** antes del resto del contenido. Campo de clave, botón «Activar», estado de conexión, explicaciones para licencia inválida, cupos agotados, servidor no disponible y reintentos sin consumir cupo.

No utilizar un simple booleano `isLicensed` editable. Tampoco colocar una llave maestra en Kotlin, C++, recursos o assets. La protección de uso local ha de ser criptográfica y distribuida.

### Protocolo

1. Android crea un par de claves **no exportable** en Keystore, preferentemente respaldado por hardware cuando esté disponible. No requerir obligatoriamente hardware-backed en todos los Android 7–16; definir soporte y degradación controlada.
2. Solicita un desafío temporal al servidor por TLS. Firma con la clave privada local un mensaje canónico que vincule `nonce`, `product=SPDECODE_OFFLINE`, versión de protocolo, hash de clave pública e identificador de instalación.
3. Backend valida licencia, nonce no usado, firma, identidad de producto, versión compatible y cupos. Inserta/recupera la activación en **transacción atómica** y no consume una nueva plaza para el mismo dispositivo.
4. Backend firma un **certificado de autorización** con Ed25519 (o formato firmado estandarizado COSE/CBOR) que contiene `iss`, `aud`, `license_id`, `device_pubkey_hash`, `entitlement=local_decode`, `issued_at`, `policy_version`, `key_id`. Nunca incluye el código de licencia en claro.
5. APK almacena certificado en almacenamiento privado. En cada inicio, verifica firma con clave pública confiable empotrada, producto y vinculación con su clave Keystore, y demuestra posesión de esta clave localmente. Conectar el permiso al inicio del motor JNI/C++ y no a un único `if` superficial en UI.
6. **Después de activar, no hay solicitudes de licencia para descifrar.** El motor existente opera localmente. Resultado JSON completo, exportaciones y pruebas de formatos siguen funcionando sin Internet.

Rutas previstas:

```http
POST /api/offline/v1/activation/challenge
POST /api/offline/v1/activation/complete
```

**No enviar** archivos de configuración, contenido decodificado, contraseñas, claves privadas VPN o catálogos al sistema de licencias.

### Tres dispositivos: condiciones reales

- El límite es **tres dispositivos activados con licencia**. La cuarta activación se rechaza incluso cuando dos solicitudes llegan simultáneamente.
- Instalar la misma APK en otro móvil no concede acceso: requiere un certificado vinculado a su propia clave Keystore y un cupo disponible.
- Reinstalación/restablecimiento puede eliminar la clave Keystore; ofrecer liberación administrativa y futura recuperación autenticada.
- **La revocación offline no es instantánea.** Liberar un dispositivo en el servidor solo afecta nuevas activaciones; el equipo liberado, si conserva una autorización permanente y está desconectado, puede seguir funcionando. Para forzar revocación haría falta revalidación periódica, contradiciendo la exigencia de no depender de Internet. Indicar esta limitación explícitamente en términos de venta.
- Ningún mecanismo local garantiza resistencia total a APK mod; medidas de firma, R8, JNI, comprobaciones nativas y Keystore aumentan el coste de una modificación, pero no son invulnerables.

## 6. Futura tienda comercial, separada de la activación

Cuando se integre checkout (no ahora): guardar pedidos, identificar cada operación, verificar **webhooks firmados y confirmación server-to-server**, gestionar idempotencia, devoluciones, contracargos, contacto del comprador, comprobantes fiscales y emisión posterior de licencia.

No generar una licencia basándose únicamente en el retorno del navegador a la página de éxito. No registrar en el repositorio credenciales de proveedores de pago.

La tienda debe poder vender **productos diferentes**, no copiar el modelo de activaciones Android para la API.

## 7. Futura API comercial vinculada a UNA IP pública

### Reglas de autorización

- Cliente compra/solicita una credencial API y registra **una dirección IP pública específica** de salida de su servidor (IPv4 o IPv6). Validar y normalizar la dirección; rechazar hostnames, IP privadas/no enrutable, CIDR y listas de IP si el plan es estricto de una sola IP.
- Generar token aleatorio de alta entropía y mostrarlo una sola vez; persistir solo un verificador con secreto de servidor. La licencia Android **no** es un token API.
- Exigir TLS y cabecera `Authorization: Bearer <token>`. Cada solicitud requiere: `token válido && cuenta activa && IP origen exacta && scope permitido && cuota disponible && vigencia`.
- Obtener IP del **socket de origen** o de un proxy inverso *realmente confiable*. En Nginx, configurar `set_real_ip_from` para IP de proxy(s) propios y manejar adecuadamente `real_ip_header`/cabeceras limpiadas. **Nunca confiar en `X-Forwarded-For` inyectado por el usuario**.
- Token ausente/incorrecto ⇒ HTTP 401; token válido desde IP diferente ⇒ HTTP 403; cuota agotada ⇒ 429. Respuestas externas genéricas para no revelar existencia de recursos o tokens.
- IPs de NAT/CGNAT, IP dinámica, túneles, proxies corporativos y egress IPv6 pueden provocar falsos rechazos. El comprador debe saber qué IP pública usa realmente su servidor; proporcionar cambio de IP autenticado y auditado con límites.
- La limitación por IP **no identifica por sí sola a una máquina**. Clientes detrás del mismo NAT pueden compartir IP: usar clave, scopes, cuotas, rotación y, opcionalmente, mTLS si se necesita identificar un equipo con mayor confianza.
- Restricción de IP es condición de autorización, no sustituto de autenticación criptográfica.

### Rutas previstas, deshabilitadas hasta fase posterior

```http
POST /api/admin/api-licenses
GET  /api/admin/api-licenses
POST /api/admin/api-licenses/:id/revoke
POST /api/admin/api-licenses/:id/change-ip
POST /api/commercial/v1/decode  # nombre provisional
```

## 8. Matriz de aceptación y pruebas de seguridad

| Prueba | Resultado requerido |
|---|---|
| Generación manual sin sesión | 401, sin generación |
| Sesión no autorizada/CSRF incorrecto | 403, sin generación |
| Dos clics o reintento de emisión | Idempotencia sin duplicados |
| Reinicio del contenedor | Licencias y cupos persisten |
| Cuarta activación simultánea | Rechazada, contador <= 3 |
| Activación repetida en el mismo dispositivo | No consume otro cupo |
| Licencia inválida, nonce caducado o firma falsa | Rechazo sin acceso ni cambios persistentes |
| Copia del certificado a otro móvil | No funciona por vinculación Keystore |
| Activación correcta y modo avión | APK Offline inicia y descifra sin conexión |
| VPS caído después de activar | La APK Offline sigue operando |
| Error del servidor en primera activación | Mensaje claro, no consume cupo |
| Dos APK instaladas a la vez | Distintos `applicationId`; ambas independientes |
| Inspección de APK Offline | Sin SDK de anuncios, sin catálogo remoto, sin secretos backend |
| Token API desde IP distinta | 403, sin ejecutar trabajo |
| IP correcta con token falso | 401, sin ejecutar trabajo |
| `X-Forwarded-For` falsificado | No sortea el control de origen |
| Quota/scope inválido | 429/403 respectivamente |

Probar `SP-DECODE Online` y `SP-DECODE Offline` de forma independiente. **No** anunciar como implementada ninguna fase sin pruebas de código, CI, instalación real y firma. Si existe discrepancia entre este documento y el código desplegado, el código probado prevalece a efectos de estado.

## 9. Entregables y orden de ejecución

1. Documento de arquitectura (este archivo).
2. **L1** — backend persistente de emisión manual, autenticación y auditoría, más vista de panel.
3. **L2** — activación Android offline con certificado firmado y control de tres equipos.
4. **L3** — port selectivo del cliente offline a la rama online, dos APK firmadas, CI y prueba en dispositivo.
5. **L4** — tienda de licencias y cobros automáticos con impuestos.
6. **L5** — producto comercial API restringido a una IP (sin compartir claves Android).

**Estado al redactar:** documentación preparada; aún faltan implementación L1–L5, revisión de firmas y migración. **No ejecutar cambios de producción** ni habilitar la tienda hasta completar pruebas y aprobación.