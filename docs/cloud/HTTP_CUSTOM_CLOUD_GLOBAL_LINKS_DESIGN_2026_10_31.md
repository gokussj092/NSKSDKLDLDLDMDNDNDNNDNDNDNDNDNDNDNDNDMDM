# SP-DECODE — investigación: enlaces HTTP Custom Cloud globales y eprdv.link

**Fecha:** 2026-10-31. **Rama:** `fix/http-jireh-current-method`. **Estado:** propuesta técnica documentada; **NO implementado ni desplegado**, sin APK compilada ni cambios de catálogo.

## Solicitud y evidencia
El propietario solicita admitir enlaces del tipo `https://eprdv.link/<codigo>` en Nube global y otras páginas que compartan configuraciones HTTP Custom.

- La página oficial `https://eprdv.link/` indica: copiar enlace, abrir HTTP Custom, elegir **Open cloud**, pegar y enviar. Por tanto es un **enlace de referencia de configuración**, no una prueba de descarga directa de bytes `.hc`.
- La documentación oficial `https://eprdv.link/api/` indica que `https://api.eprodev.org/v1/configs/hc` **crea** archivos `.hc` con autenticación API key; **no** debe asumirse que este endpoint descarga enlaces `eprdv.link`, ni pedir/copiar la clave de otra persona.
- No fue posible obtener la respuesta HTTP ni el flujo de descarga del código concreto facilitado desde el navegador de investigación (cache miss). **No hay evidencia de que GET /<codigo> devuelva binario HC ni de un endpoint de descarga estable.** Evitar afirmar compatibilidad hasta reproducir con un enlace activo autorizado y comparar SHA-256 de los bytes con el archivo importado oficialmente.

## Código existente que puede reutilizarse
- `cloud/web/lib/c35-provider.mjs`: `parseHttpCustomReference`, `approvedUrl`, `downloadApproved`, `importHttpCustomReference`. Solo admite `cloudvpn.mrfrankofc.com` y `link.playsmarty.uk`; DNS IPv4 público fijado, límite 8 MiB, timeout, redirects limitados, respuesta HTML rechazada.
- `cloud/web/lib/c35-gateway.mjs`: endpoint autenticado para importación HTTP Custom; conserva los bytes cifrados y los devuelve en Base64, sin descifrar ni persistir el contenido del enlace.
- `android/.../cloud/HttpCustomCloudReference.kt`: detección de dos hosts **hardcodeada**. `CloudOnlineReference.kt` ofrece Nube global, pero las referencias `hc` no se obtienen dinámicamente de `onlineReferenceFormats`.
- `cloud/web/lib/text-format-catalog.mjs`: `publicOnlineReferenceFormats()` publica dos prefijos; la actualización de la lista no basta para habilitar hosts nuevos en las APK existentes.
- `HttpCustomOnlineFlow.kt`: descarga **una sola vez** y reutiliza bytes cifrados para contraseña/HWID, limpiando memoria al concluir.
- `docs/cloud/HTTP_CUSTOM_ONLINE.md`: contrato heredado y límites.

## Arquitectura recomendada: importador global con adaptadores auditados
1. Un único flujo Nube `Auto / HTTP Custom / HTTP Injector`. Los enlaces ePro Dev van al **importador HTTP Custom**, sin alterar ni confundir las firmas de HTTP Injector.
2. Un `ReferenceResolver` backend con registro de proveedores identificados y revisados, no un proxy abierto: `id`, patrones de referencia, hosts y rutas autorizados, estrategia de resolución, política de redirects, límites, versión del adaptador, estado.
3. Distinguir **estrategias reales**: (a) archivo `.hc` directo y validado; (b) share link que responde con redirección permitida o contenedor validado; (c) referencia de aplicación que requiere un endpoint/API oficial de lectura. Para `eprdv.link` el adaptador queda en estado *pendiente de caracterización*, NO asumir que basta GET al enlace ni reutilizar la API oficial de creación.
4. Encapsular las reglas de dominio/destino en el VPS; validar cada salto con HTTPS, DNS público fijado, sin IP privada ni puertos arbitrarios, sin userinfo, sin URL devuelta por HTML/JavaScript sin un contrato auditado. Mantener límite de bytes, contención de descompresión, timeout, consentimiento, rate limit y abort.
5. Para nuevos proveedores, publicar metadatos **de presentación** en un manifiesto versionado y autenticado del catálogo (`onlineReferenceFormats` o una versión 2 compatible). No permitir que un manifiesto descargado autorice destinos de red ni código; las allowlists y adaptadores deben permanecer en el backend. Android nuevo podría reconocer referencias `hc` de ese catálogo y enviar referencia al endpoint existente; **la APK actual no obtiene este soporte sin modificar su reconocimiento local**.
6. Preservar `POST /api/v1/decode/import/http-custom` y operación nativa V2, respuesta `encrypted_file` + `dataBase64`; V1/V2 comparten actualmente el catálogo lógico y ambos necesitarían una versión de cliente con esta función, salvo alias compatibles admitidos por clientes antiguos. El backend nunca debe persistir enlaces sensibles ni archivos/credenciales.
7. Evitar reintentos automáticos para enlaces de un solo uso; errores tipados: `REMOTE_CONFIG_UNAVAILABLE` para 404/410, `REMOTE_PROVIDER_UNAVAILABLE` para timeout/429/5xx, `REMOTE_RESPONSE_INVALID` para HTML y contenido no HC, `REMOTE_NETWORK_DENIED` para destinos no permitidos. **No eludir contraseñas, expiración, HWID ni controles de autorización de terceros.**

## Validación antes de anunciar soporte
- Obtener un enlace de prueba activo **generado con permiso** y su archivo `.hc` de referencia, sin subir a GitHub los valores reales ni credenciales.
- Inspeccionar de forma local y protegida el método de consulta de HTTP Custom Open cloud: request method, URL/ruta, status, redirecciones, headers genéricos, formato del body, límites/expiración; sin interceptar cuentas o tokens ajenos.
- Verificar, al menos, enlaces válidos, caducados, usados, 404, HTML 200, 30x externo, host falso, DNS privado, DNS rebinding, cuerpos grandes, límites TLS, cancelación y contraseña/HWID con **una sola descarga**.
- Pruebas Node de broker y tests de UI Android; smoke real en V1 y V2 con dispositivo físico, HPKE/session y Play Integrity, sin debilitar políticas.
- **Solo tras resultados positivos** activar adaptador, elevar versión efectiva de catálogo respetando `switches.json`, actualizar documentación y desplegar mediante `sudo spdecode update all <rama>`. No tocar `main` ni producción por esta investigación.

**Conclusión:** integración técnicamente factible como sistema de adaptadores por origen; no existe hoy evidencia suficiente para publicar soporte de descarga `eprdv.link` ni una descarga global arbitraria. El siguiente hito es caracterizar el protocolo real del enlace, no modificar el regex y suponer que devuelve `.hc`.
