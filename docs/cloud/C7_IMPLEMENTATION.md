# C7 — Integración, paridad y verificación preproducción

**Rama:** `feat/cloud-c7-integration-parity`, PR #93, basada en C6 (#92), seguido por C5 (#91), C4 (#90), C3/C3.5 (#89), C2 (#88), C1 (#87) y C0 (#86).

## Objetivo y alcance

Validar el recorrido que ejecuta SP-DECODE en modo Cloud, conservando la interfaz Android y sin introducir algoritmos locales nuevos. El servicio sigue **sin desplegar para usuarios**. Las pruebas de laboratorio no certifican funcionamiento de variantes reales de los proveedores ni la seguridad de una instalación VPS.

C7 no modifica los scripts canónicos ni el bot; las muestras son **sintéticas o generadas por los tests existentes**. No se solicitan archivos privados, perfiles de terceros ni credenciales reales.

## C7.1 — Integración de extremo a extremo ejecutable en CI

`cloud/tests/c7-e2e.test.mjs` arranca un **ThreadingHTTPServer C2 real en loopback**, con puerto efímero y token privado sintético. Invoca las funciones reales de la API Node.js C3. El transporte de prueba `fetchImpl` solo sustituye el nombre DNS privado de Docker por loopback; la API sigue exigiendo exactamente `http://decoder-worker:8787`, validación de sesión y token interno de worker.

La sesión se crea con nonce desde C3, verificación de nonce y paquete, y un *verificador Play Integrity simulado*. Redis utiliza un test double con contratos `GETDEL`, límites y semáforos; las pruebas no conectan Google Play ni Redis de un VPS. El texto de salida del worker real vuelve sin abreviación por Next.js y se compara por UTF-8 completo.

### Matriz C7 automatizada

| Caso | Fuente de prueba | Comprobación |
| --- | --- | --- |
| API/worker privado | Worker C2 HTTP loopback | 403 sin token privado; inventario de 240 rutas no certificado |
| Challenge/session | Redis y Play Integrity simulados | Nonce ligado al token sintético; bearer firmado; errores sin verificación |
| Archivos de 3 motores | Generadores A.2.3 y scripts originales | Igualdad de `rawText` por byte y SHA-256; `isPartial=false` |
| HTTP Custom HCCFG | Generador propio con contraseña sintética | 422 `PASSWORD_REQUIRED`, error con contraseña errónea y JSON completo autenticado |
| Textos | Vector de fase G, Falcon Tunnel | Igualdad de texto y JSON estructurado |
| Catálogo NUR | Catálogo cifrado sintético existente | JSON completo, distinto de `.solid`; alteración rechazada |
| Solicitudes no autenticadas | Referencias/tokens falsificados | No hay despacho al worker |
| Malformaciones y credenciales ajenas | Entradas sintéticas | 400 antes del worker, sin selección cruzada de claves |
| Cuota y concurrencia | Redis simulado | Diez solicitudes por minuto y máximo dos activas por sesión |
| Mantenimiento | Bandera C6 | Bloqueo de descifrado y readiness sin usar worker |
| Fallos de motor | Archivos inválidos | Código sanitizado, sin trazas ni token interno |

**Comparación de origen:** `cloud/tests/c7_vectors.py` genera entradas mediante los scripts sintéticos existentes, valida sus SHA-256 y ejecuta **separadamente el script canónico** para comparar resultados en el recorrido API. Las 60 muestras de A.2.3 siguen validándose por `tests/test_cloud_c2_golden.py`; no afirmamos que 60 rutas cubran las 240 variantes ni que las versiones reales estén certificadas. Las salidas históricas de A.2.3 no se reescriben silenciosamente.

Las pruebas de C3.5 existentes siguen verificando destino fijo HTTPS, fijación DNS, prohibición de redirects, límites, verificación HMAC y consentimiento con proveedores **simulados**. No se hacen descargas de URLs reales en CI.

## C7.2 — Android JNI/APK

El job `android-cloud` compila `:app:assembleDebug` con un origen HTTPS **de ejemplo y no desplegado**. Luego ejecuta `tests/cloud_c5_apk_audit.py` sobre el APK real: biblioteca nativa `libspdecode.so` y ausencia de motores antiguos, vault, assets de claves y claves originales. Se comprueba el candado de nueve pantallas de C0.

**Esto es una compilación y auditoría física, no una prueba de descifrado en un teléfono**. El flujo Android real (Google Play Integrity clásico → C++ JNI → TLS público → servidor) aún requiere un dispositivo, una compilación registrada en Play Console y una instalación de staging.

## C7.3 — Registro de evidencias y autorización

`docs/cloud/C7_EVIDENCE.json` detalla todas las evidencias. El script `scripts/cloud_c7_release_gate.py --stage` valida el formato y permite continuar la **fase de desarrollo**; `--production` debe responder bloqueado mientras falten requisitos de prueba reales y aprobación explícita C8. Un check SUCCESS de C7 no autoriza producción.

**Requisitos no resueltos antes de activar para usuarios:**

1. VPS con HTTPS real, TLS válido, proxy `X-Real-IP` confiable, Redis protegido, worker privado y métricas sin contenido sensible.
2. Cuenta de servicio y validaciones Google Play Integrity legítimas, dispositivo Android real, variantes de acceso y licencias según Play Console.
3. Pruebas del APK Cloud firmado en ARM64 y otros dispositivos objetivo, reconexión, cancelación, timeouts, lotes y archivo máximo de 8 MiB; inspección de resultados y exportación/historial sin cambio visual.
4. Paridad real por aplicaciones/formato y versiones de exportador, incluyendo `.ehi` completo, `.hc` contraseña/HWID/doble, NPVS, TLS, todos los textos y los catálogos NUR.
5. Ejemplos **autorizados** de importación externa HTTP Injector/NUR y revisión de condiciones del proveedor; ningún proxy de URL libre.
6. Carga/soak sobre infraestructura real, límites de CPU, RAM y concurrencia, tasa de errores, p50/p95/p99, recuperación y costo por solicitud. El p95 de loopback sintético solo es diagnóstico, nunca SLO contractual.
7. Auditoría de seguridad de componentes web/JNI, protección anti-SSRF, control de claves, credenciales, sesiones, retención y políticas de privacidad/legalidad.
8. Procedimientos C8 de despliegue, rollback, incidentes, verificación de integridad del APK y aprobación de publicación.

## Reproducción en un entorno autorizado

Desde la raíz del repositorio con Node.js 22, Python 3.12, PHP CLI y dependencias originales ya instaladas:

```sh
npm ci --omit=dev
python -m pip install -r requirements.txt
cd cloud/web && npm install --no-audit --no-fund && npm test
cd ../..
node --test cloud/tests/c7-e2e.test.mjs
python -m unittest cloud.tests.test_c7_release_gate -v
python scripts/cloud_c7_release_gate.py --stage
python scripts/cloud_c7_release_gate.py --production  # Debe fallar mientras no exista aprobación C8
```

Ver `.github/workflows/cloud-c7.yml` para los jobs de backend y APK por separado. **No fusionar con main, publicar un APK ni activar decodificación pública por el simple éxito de estos tests.**
