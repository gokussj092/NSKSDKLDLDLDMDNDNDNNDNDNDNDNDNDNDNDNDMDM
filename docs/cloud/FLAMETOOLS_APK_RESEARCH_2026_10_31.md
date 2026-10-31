# FlameTools.apk — investigación de ingeniería inversa (31-oct-2026)

**Estado: auditoría estática inicial; integración de descifrado NO habilitada.** Se revisó localmente el APK aportado por el propietario del proyecto. No se ejecutó, no se consultó su servidor y no se han subido archivos VPN a terceros. El VPS y `main` no se han modificado.

## Identidad y evidencia reproducible

- Paquete del manifiesto: `com.flame.decoder`; etiqueta `Flame Tools`; permiso `android.permission.INTERNET`.
- SHA-256 APK: `45db7398c5daa8445f353ce0933aa2d60f9bb93c80149e91e9e4599914c33bdb`.
- Componentes: `classes.dex` + `classes2.dex` + `classes3.dex` + `classes4.dex`, `Epic.vm`, `lib/arm64-v8a/libTinSeinReal.so`, `lib/arm64-v8a/libseinsein.so`.
- SHA-256 `libTinSeinReal.so`: `02f99974a18c61935409cfe457fe4430945e0810848636fc26cd0d0789f27cd7`.
- SHA-256 `libseinsein.so`: `86eec99396d6beb966b26df28f2665947df7459b0e13e6e6d1edc07da64bd483`.
- En el DEX propio figuran clases `MainActivity$activate`, `MainActivity$loadDecoders`, `MainActivity$runDecode`; `libTinSeinReal.so` contiene símbolos de `httpGet`, `postJson`, `BASE_URL`, `decoderNames`, `expiryText`, `getLastJson`, OkHttp y JSON.
- La biblioteca `libseinsein.so` tiene componentes de protección/virtualización de DEX y VM y detección de instrumentación. Esto no equivale a código criptográfico de formatos VPN.

## Interpretación y límites

Hay evidencia de un cliente Android que carga información de descifradores mediante HTTP y envía solicitudes JSON. **No se ha determinado si los algoritmos VPN se ejecutan íntegramente en el servidor o también en el cliente.** No se identificó ningún códec concreto para EHI, HTTP Custom, NPVS, Dark u otros formatos que pueda ejecutarse y validarse independientemente. No se recuperó catálogo remoto, esquema confiable de solicitudes/respuestas ni acceso autorizado a su backend. Cualquier integración de un módulo `FlameTools` hoy sería especulativa.

## Integración futura en SP-DECODE

El worker existente usa `cloud/workers/python/engine.py` (`decode_file` y `decode_provider_catalog`) con catálogo explícito, subprocesos aislados, contratos y límites; `cloud/workers/python/server.py` valida las solicitudes. No se registrará un nuevo códec sin:

1. Identificar un formato/versión que falte realmente en SP-DECODE.
2. Conseguir una muestra propia/sintética autorizada y salida esperada reproducible, sin publicar credenciales.
3. Derivar una implementación propia compatible que conserve todos los campos y compruebe autenticación y versiones.
4. Probar casos válidos, truncados, incorrectos y alterados, límites de tamaño/CPU/memoria y ausencia de red.
5. Registrar explícitamente el códec en el worker y probar el flujo Android, antes de evaluar un despliegue al VPS.

Una API de terceros solo se utilizaría con autorización oficial y consentimiento explícito sobre el envío de perfiles. No copiar código propietario, ocultar errores como éxito ni exponer claves/tokens.

**Resultado:** auditoría terminada; 0 algoritmos nuevos validados; 0 rutas de descifrado añadidas; no cambios en producción.
