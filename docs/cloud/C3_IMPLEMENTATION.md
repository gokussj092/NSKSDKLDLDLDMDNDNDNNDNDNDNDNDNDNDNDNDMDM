# C3 — API protegida, sesiones, límites y procesamiento seguro

**Alcance:** únicamente SP-DECODE Android Cloud; sin cambiar UI/UX, bot ni algoritmos. La comunicación C++ en `libspdecode.so` sigue siendo parte de C4 y **no contendrá ninguna credencial permanente**.

## C3.1: API de archivos, textos y catálogos

`POST /api/v1/decode/file`, `/decode/text` y `/decode/import/catalog` conectan Next.js con los respectivos motores privados de C2 **solo** tras validar una sesión temporal de aplicación. Los archivos entran como JSON Base64 con formato explícito; `.hc` admite `credentials.password` y/o `credentials.hwid` de manera transitoria (solo en RAM y entrada estándar del worker). No se guardan originales en la API web ni se registran cuerpos de solicitud o resultados. Las salidas conservan `rawText`, `structuredJson`, `isPartial`, warnings y metadatos, sin afirmar certificación de versiones de exportador.

C3 introduce como límite de subida pública **8 MiB**, textos **250.000 caracteres**, cuerpo JSON **11 MiB**, worker privado C2 **16 MiB** máximo y salida **4 MiB**. El cuerpo HTTP se consume con límites; no se leen cantidades ilimitadas. Todos los resultados usan `Cache-Control: no-store` y códigos de error explícitos. El borrado de temporales ocurre dentro del `TemporaryDirectory` de C2 después del proceso.

## C3.2: sesiones y Google Play Integrity

1. Android solicita `POST /api/v1/session/challenge`: recibe `challengeId` y `nonce` aleatorios, conservados **120 segundos** en Redis.
2. La futura biblioteca nativa `libspdecode.so` integra con Kotlin/Play Integrity el desafío. Solicita un **token de integridad clásico** con ese `nonce`; la API no confía en valores enviados por Android sobre versión, modelo, paquete ni resultado.
3. Android envía `POST /api/v1/session` con `challengeId` e `integrityToken`. El servidor consume el desafío atómicamente con Redis `GETDEL` (no permite reuso) y llama al servidor de **Google Play Integrity API** para descodificar el token utilizando una cuenta de servicio exclusivamente del servidor.
4. Se comprueba `requestPackageName`, `nonce`, `timestampMillis` reciente, `appIntegrity.appRecognitionVerdict=PLAY_RECOGNIZED`, `deviceIntegrity` con `MEETS_DEVICE_INTEGRITY` y `LICENSED` por defecto. El requisito Strong Integrity es configurable.
5. Tras validación se emite un bearer HMAC-SHA256 con `jti` aleatorio y alcance `decode`, **TTL 300 segundos**, asociado a presencia activa de `jti` en Redis. Cada petición comprueba firma en tiempo constante, expiración y existencia de sesión.

**Limitaciones:** la validación real solo puede verificarse con credenciales de Google y una versión reconocida por Play Console; las pruebas CI inyectan una respuesta de Google simulada, nunca acreditan verificación real con dispositivos. Play Integrity no sustituye la protección de datos personales, autorización por usuario ni defensas contra robo de tokens; la app debe usar HTTPS y nunca registrar bearer o credenciales. Si se necesita acceso por cuenta de usuario habrá que añadir autenticación de identidad adicional.

## C3.3: límites, concesiones y red

- Desafíos: máximo **15 por ventana de 15 minutos** por IP normalizada (solo cabecera `X-Real-IP` establecida por proxy confiable; el Nginx debe **sobrescribirla** y limpiar encabezados de cliente).
- Admisiones Play Integrity: máximo **20 por IP / 15 minutos**.
- Solicitudes de descifrado: máximo **10 por token / minuto** y **20 por IP / minuto**.
- Procesos simultáneos por token: **2**. Un semáforo Redis evita excederlos incluso con múltiples instancias.
- Redis se utiliza para desafío de un solo uso, sesión y control de concurrencia; las cargas descifradas **no se almacenan** en Redis.
- API → worker está restringida a `http://decoder-worker:8787` (red privada Docker). Worker exige `X-SP-Worker-Token` distinto del token de sesión.
- API pública deshabilitada a menos que `CLOUD_API_ENABLED=true`, existan credenciales de Google, claves aleatorias del backend, URL Redis y proxy confiable. Sin configuración las rutas siguen respondiendo `503 CLOUD_NOT_READY`.
- `/api/v1/ready` solo responde READY cuando se encuentra configurado el acceso, Redis responde y el worker privado está listo; `/health` es únicamente liveness.

## C3.4: errores y resultado

Las rutas no exponen stderr, excepciones, contraseñas, rutas de sistemas de archivos ni tokens. Errores frecuentes: `INVALID_REQUEST`, `UNAUTHORIZED`, `RATE_LIMITED`, `INVALID_BASE64`, `INPUT_TOO_LARGE`, `UNSUPPORTED_FORMAT`, `PASSWORD_REQUIRED`, `HWID_REQUIRED`, `HWID_PASSWORD_REQUIRED`, `AUTH_FAILED`, `ENGINE_TIMEOUT`, `DECODE_FAILED` y `SERVICE_UNAVAILABLE`.

## C3.5: integraciones externas pendientes de activar

**HTTP Injector Cloud / `POST /api/v1/decode/import/cloud` está implementado en C3.5 pero permanece deshabilitado por configuración, a falta de provisión de claves del servidor y pruebas reales.** Aceptar una URL arbitraria y hacer `fetch` desde el servidor generaría riesgo de SSRF, credenciales filtradas y accesos a la red interna. Antes de habilitarlo es obligatorio un broker de descarga con allowlist de hosts del proveedor real, resolución DNS vinculada a IP pública, denegación de IP privadas/reservadas, prohibición de redirecciones y limitaciones de contenido/tiempo.

Los catálogos NUR ya descargados se pueden procesar como bytes protegidos, pero el servidor aún no descarga sus enlaces. La subida de muestras reales, la certificación de todas las versiones Android y las pruebas con Play Console siguen pendientes. **C3 no modifica ni adelanta la publicación del APK**.

## C3.6: despliegue y validación

`cloud/compose.yaml` añade Redis en la red interna, sin puerto público, sin persistencia de desafíos; no se entregan valores de secretos en Git. La API se publica solo en **127.0.0.1:3000** para pruebas locales, nunca se abre sin HTTPS y proxy restrictivo. La instancia Redis no está protegida con ACL/password porque es solo el prototipo de red Docker privada; usar autenticación y segmentación adicional para producción y configurar copias/HA según la política de retención.

```bash
cd cloud/web && npm install --no-audit --no-fund && npm test && npm run build
cd ../..
docker compose -f cloud/compose.yaml config --quiet
```

Las pruebas de `.github/workflows/cloud-c3.yml` verifican configuración fail-closed, expiración/replay, firma HMAC, nonce y respuestas Play Integrity simuladas, Redis simulado, límites y gateway en memoria. **Estas pruebas no sustituyen pruebas en un VPS real con Redis, Google Play Integrity, reverse proxy y datos sintéticos por cada formato.**

### Condiciones pendientes antes de habilitar usuarios

- [ ] Provisión de Google Cloud API, cuenta de servicio y aplicación Play Console reconocida.
- [ ] Configuración de servidor HTTPS, proxy confiable, protecciones anti-abuso y Redis autenticado.
- [ ] Auditoría de ataques SSRF e importadores remotos HTTP Injector Cloud/NUR.
- [ ] Pruebas reales Android → Play Integrity → API → workers por variante y formato, manteniendo UI/UX.
- [ ] Política de privacidad que explique transferencia de archivos, almacenamiento transitorio y no-retención.
- [ ] Pruebas de carga, memoria, tareas canceladas y continuidad del servicio.
- [ ] Retirar motores/secreto del APK (C4/C5) **solo** después de paridad.

**Rama:** `feat/cloud-c3-api-security`, PR apilado sobre C2 → C1 → C0. **No fusionar con `main` ni activar producción antes de validar los requisitos pendientes.**

## C3.5 — Importaciones remotas seguras (añadido)

**Implementación:** `cloud/web/lib/c35-provider.mjs`, `c35-gateway.mjs` y rutas /api/v1/decode/import/cloud y /api/v1/decode/import/catalog/remote. **Los motores originales y la UI Android no se modificaron.**

### HTTP Injector Cloud

Se admite el formato histórico de la aplicación Android: clave alfanumérica, `https://ehi.link/CLAVE`, `ehi://ehi.link/CLAVE` o emoji codificado. El backend extrae **solo la clave**, nunca usa el enlace como destino HTTP. Construye exclusivamente un POST a `https://www.ehi.tools/httpinjector/import_config` reproduciendo el HMAC de protocolo y el flujo AES-CBC/HMAC-SHA256/zlib de Android, con el resultado EHI enviado al worker `/internal/v1/decode/file` con formato `ehi`. No existen bypass de cifrado, modificaciones a motores originales ni fallbacks cruzados.

El servidor necesita `CLOUD_EHI_IMPORT_ENABLED=true`, `CLOUD_EHI_SIGN_KEY` y `CLOUD_EHI_RESPONSE_KEY` **provisionadas fuera de Git/Android/C++**. La opción está desactivada por defecto. Las claves existentes embebidas en APK siguen siendo un riesgo **hasta la fase C5**; añadirlas al servidor no las retira automáticamente del cliente. Las claves y destinos se toman de configuración del servidor, nunca del usuario.

### NUR Tunnel — Server VPN

`POST /api/v1/decode/import/catalog/remote` acepta solamente `{"consent":true}`, lee del servidor `CLOUD_NUR_CATALOG_URL` y requiere `CLOUD_NUR_FETCH_ENABLED=true`. El hostname exacto permitido es `strongteam.co`, basado en el origen actual del proyecto; no se acepta `url` en el cuerpo HTTP. Una vez descargado el sobre cifrado, el contenido se entrega exclusivamente a `/internal/v1/decode/import/catalog`, que comprueba la autenticación y esquema NUR `Version/Servers/Networks`. La operación local de subir bytes cifrados continúa disponible y es independiente.

### Política común SSRF y fallos

- El cliente **nunca controla destinos**, puertos, credenciales de URL, cabeceras del proveedor, métodos remotos ni redirecciones.
- HTTPS estricto, nombre de servidor/certificado verificado por TLS y **IPv4 público comprobado y fijado en la conexión**. Respuesta DNS mixta con cualquier IPv4 privado o reservado: rechazo; solo IPv6: falla de forma cerrada. Esto impide cambios de resolución entre la comprobación y la conexión real (DNS rebinding).
- Se rechazan IPs de loopback, redes privadas, link-local, CGNAT, metadatos de nube, documentación, benchmark y multidifusión, además de puertos no 443.
- **Redirecciones 3xx prohibidas**, sin seguir `Location`. `Accept-Encoding: identity` y rechazo explícito de cuerpos comprimidos para evitar descompresión implícita no acotada. Límite **8 MiB** en HTTP remoto, incluso si el proveedor omite o falsea `Content-Length`; timeout global 15 segundos (más 10 segundos por socket).
- En HTTP Injector, la respuesta se verifica por HMAC en tiempo constante **antes** de descifrar o inflar; la salida zlib está acotada a 8 MiB, y los datos se autentican antes de alimentar el worker EHI.
- **Play Integrity + bearer temporal + autorización + cuota y semáforo Redis + `consent=true`** preceden a toda llamada de red externa. Las respuestas no incluyen tokens del proveedor, URLs privadas, encabezados de autenticación ni el sobre cifrado bruto.
- La API devuelve errores seguros `INVALID_REFERENCE`, `USER_CONSENT_REQUIRED`, `REMOTE_NOT_CONFIGURED`, `REMOTE_NETWORK_DENIED`, `REMOTE_PROVIDER_UNAVAILABLE`, `REMOTE_RESPONSE_INVALID`, `REMOTE_INTEGRITY_FAILED`, `REMOTE_TOO_LARGE` y `REMOTE_DECODER_FAILED`.

**Pruebas:** `cloud/web/tests/c35-import-security.test.mjs` incluye URL/emoji, firma idéntica al vector sintético Android, DNS/SSRF, solicitud HTTPS con IP fijada, denegación 3xx, límites, HMAC/tampering, consentimiento/sesión, contrato y despacho privado. Las pruebas simulan proveedores; **no** constituyen confirmación de disponibilidad real, aprobación contractual del servicio externo ni paridad de un archivo cloud real. Requiere pruebas manuales con cuenta/servidor legítimos y permiso del proveedor antes de activar producción.

**Operación:** habilitar únicamente tras provisionar secretos reales, completar C4/C5/C7 y configurar HTTPS/Play Integrity/privacidad. `CLOUD_API_ENABLED=false` y los dos flags externos en `false` por defecto. No publicar el endpoint remoto antes de certificar con el proveedor.
