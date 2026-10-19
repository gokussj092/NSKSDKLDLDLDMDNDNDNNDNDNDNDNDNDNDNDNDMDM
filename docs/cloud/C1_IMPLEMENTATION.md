# Fase C1 — Infraestructura SP-DECODE Cloud

**Alcance:** exclusivamente la futura versión online de Android. No modificar el bot ni el diseño, elementos visuales o flujos de UI existentes. Esta fase se apoya en C0 (`feat/cloud-c0-audit-baseline`), que permanece sin fusionar con `main` a fecha del comienzo de C1.

## C1.1 — Proyecto web / API

Se creó `cloud/web/` como aplicación Next.js 16 (App Router, Node.js 22) separada de los sistemas actuales del repositorio. El index actual es informativo y temporal; **el sitio oficial se construirá en C6**. No se modifica la aplicación Kotlin. La futura biblioteca de comunicaciones se llamará **`libspdecode.so`**, no se compila en esta fase.

## C1.2 — Contrato HTTP versionado

El contrato está en `cloud/contracts/v1/openapi.json` y cubre 11 rutas:

| Ruta | Método | Comportamiento exacto en C1 |
| --- | --- | --- |
| `/api/v1/health` | GET | 200: proceso API vivo, **no** implica procesamiento posible |
| `/api/v1/ready` | GET | 503: descifrado deshabilitado |
| `/api/v1/capabilities` | GET | 200: 239 formatos + 1 `.solid` inventariados, **0 habilitados** |
| `/api/v1/config` | GET | 200: configuración **pública** sin secretos, nombre `libspdecode.so` |
| `/api/v1/decode/file` | POST | 503 `CLOUD_NOT_READY` |
| `/api/v1/decode/text` | POST | 503 `CLOUD_NOT_READY` |
| `/api/v1/decode/import/cloud` | POST | 503 `CLOUD_NOT_READY` |
| `/api/v1/decode/import/catalog` | POST | 503 `CLOUD_NOT_READY` |
| `/api/v1/session` | POST | 503 `CLOUD_NOT_READY` |
| `/api/v1/jobs` | POST | 503 `CLOUD_NOT_READY` |
| `/api/v1/jobs/{id}` | GET / DELETE | 503 `CLOUD_NOT_READY` |

**Semántica:** `503` es intencional; no debe devolverse `200` con datos ficticios ni procesarse un archivo antes de autenticación, validación de entrada y workers certificados. El retorno aplica cabeceras `Cache-Control: no-store`, `nosniff`, política restrictiva de contenido y no configura CORS permisivo. `GET /capabilities` no confunde rutas experimentales con exportadores verificados.

El contrato de respuestas de descifrado completas (`rawText`, JSON, warnings, isPartial, decoderVersion, requestId) quedará implementado en C2/C3 junto con sus pruebas, sin ocultar campos ni truncar resultados.

## C1.3 — Worker independiente

`cloud/workers/python/server.py` implementa exclusivamente los endpoints internos `/health` (200) y `/ready` (503); todos los `POST` están deshabilitados y ningún decoder de `decoders/` se importa. El worker real, su pool Node/PHP y la ejecución autorizada de las 240 rutas se construirán durante C2.

Los workers reales deberán correr aislados, sin red por defecto; importadores externos requerirán un broker explícito con política anti-SSRF y destinos permitidos. No reutilizar sesiones de Telegram ni dar al worker un intérprete shell sin aislamiento.

## C1.4 — Contenedores y red privada

`cloud/compose.yaml` publica Next.js solo en `127.0.0.1:3000` y deja `decoder-worker` en una red interna sin `ports`. Los dos contenedores corren sin root, con filesystem read-only, `cap_drop: ALL`, `no-new-privileges` y comprobación HTTP de **liveness**, no de readiness. Se configurarán TLS, reverse proxy, límites de subida, integridad del cliente y sesiones al pasar a C3; **no desplegar a Internet en C1**.

## C1.5 — CI y pruebas

- `cloud/web/tests/contract.test.mjs`: status HTTP, `no-store`, contrato de capacidades, `libspdecode.so`, denegación de POST/jobs.
- `cloud/web/tests/openapi.test.mjs`: cobertura de cada endpoint en el esquema versionado.
- `cloud/workers/python/test_server.py`: salud, readiness y rechazo de cargas.
- `.github/workflows/cloud-c1.yml`: `node --test`, `next build`, `unittest`, validación de Docker Compose.
- Se mantienen sin editar todas las fuentes Android y de bot.

## Alcance de los trabajos restantes

| Fase | Trabajo pendiente obligatorio |
| --- | --- |
| C2 | Ejecutar **todos** los motores Android en workers confinados; fixtures sintéticos y paridad, incluidos textos, `.hc`/HWID, `.solid`, HTTP Injector Cloud y NUR |
| C3 | Autenticación, Play Integrity validado en servidor, protección anti-abuso, seguridad de cargas, gestión de sesiones, cuotas, resultados y borrado |
| C4 | Cliente C++ JNI `libspdecode.so`; reemplazo interno de llamadas Android sin rediseñar UI/UX |
| C5 | Retirar archivos, motores y tablas sensibles del APK/AAB y auditar el binario |
| C6 | Sitio oficial, páginas públicas y panel privado |
| C7–C8 | Pruebas de paridad, privacidad, preparación Google Play, despliegue y mantenimiento |

**Definición de finalización C1:** tests Node y Python exitosos, `next build` correcto, Docker Compose válido, HTTP fail-closed, PR revisado, sin código Android/bot modificado. Un PR exitoso **no equivale** a un descifrador Cloud funcional ni a un servicio de producción listo.
