# Resultados

**VERIFIED_REAL — servidores:** preflight original HTTP200/JSON con
`integrity_required:false`, seguido del catálogo3710bytes/6servidores. Segunda
descarga por el adaptador operativo repite el documento entero y SHA256
`c17f1ed60e5e43991b3ab40f185bb4cede355f5dc6eec5a3755b448b7c58ead2`.
Node JSON independiente, Python, CLI y worker aislado coinciden en todo el objeto,
incluidos defaults y objetos anidados; no se publican sus valores reales.
No hay versión remota de catálogo en la API, no se inventa una.

**NETWORK_UNAVAILABLE — payloads/xray_payloads:** ambas rutas originales devuelven
HTTP200/195bytes HTML Site Unavailable. No están habilitadas. El método nuevo
está limitado explícitamente al catálogo de servidores; no anuncia ni construye
un snapshot combinado de tres fuentes. No se aplica descifrado a JSON ya legible.

**VERIFIED_SYNTHETIC:** 27/27 Python (12 CATNET+15 regresión NAMO) y181/181 Node
en21 archivos. Fixture ficticio con Unicode, CRLF, null/bool/int/objetos, defaults,
claves futuras y texto de apariencia Base64 preservado. Negativos: HTML200,
JSON/truncado/UTF8/duplicados/NaN/esquema/tipos/límites, integridad requerida o
desconocida, mantenimiento, DNS privado revalidado, redirects, cabeceras originales,
URLs arbitrarias rechazadas, worker completo sin éxito parcial, switches y
versiones monotónicas. No se añaden paquetes ni formatos.

Primer Python11/12 por OSError del opener fuera del try; corregido12/12 y
regresión completa27/27. Source_evidence falló primero por capitalización del
getter en un assert; corregido al nombre observado. Revisión inicial de icono
Flutter conservada; se seleccionó después el launcher Android original PNG
192×192/52811bytes, SHA256
`f6d8e484d5ce00ce6c170bff16907ae3384909c147fc0d4f7ff4fdf20207d27d`, sin conversión.
JADX1.5.6: exit3/54errores; interceptor recuperado offline de DEX. Todo intento
significativo y scripts quedan en tools/history y ANALYSIS.

**SIMULATED_HTTP_REAL_BYTES:** replay Node con los dos cuerpos HTTP reales y
worker real pasa. **NETWORK_UNAVAILABLE:** Node HTTP real aquí sale3 con
REMOTE_NETWORK_DENIED. Prueba real en VPS, revisión humana y rollout pendientes.
La descarga Python es real y no lleva Play token/sesión fabricados. El backend
detiene futuras descargas si el proveedor cambia Integrity a true o deja el
campo desconocido. No se prueban conexiones VPN ni cuentas.

Solo Cloud: proveedor, cabeceras/preflight, parser offline, worker, contrato,
icono, controles y ficha. Piso72/66 fichas/256 formatos; versiones mayores
configuradas preservadas. Sin Android/build/merge/deploy. V2/V3 y fingerprint
inventariados, no equivalencia oficial Play. XjConfigCodec/GcpHostUpdateCodec
son observaciones estáticas, sin formato/archivo/texto/exportador habilitado.
Licencias transitivas/Fase7 y validador CI de evidencias siguen pendientes.

## Resultado de mantenimiento 2026-11-09

Estado actual NETWORK_UNAVAILABLE, descarga nueva no verificada. Misma APK build27; trazado estático confirmado con JADX1.5.6 completo sobre JDK21.0.13, Androguard4.1.3. Los sondeos anteriores recibieron503/91bytes antes de cabeceras; el lector con recuperación limitada agotó18s aproximadamente. No hay nuevo conteo real de servidores. generated/maintenance-20261109.json conserva hashes/trazado y el estado; los6 servidores citados arriba pertenecen a la observación histórica, no a una descarga actual.

15 tests Python (12 anteriores y3 de recuperación) y12 Node CATNET correctos. El conjunto de esta actualización pasa61 Python/77 Node. Se verifica recuperación simulada de503, persistencia de UUID, siguiente IP validada, límite de dos intentos y rechazo sin bypass de Integrity. Las simulaciones no acreditan disponibilidad remota. No se cambió el codec, ni se habilitaron rutas nuevas ni se modificaron iconos.

Auditoría actual: A0 sin bloqueos; P06 PASS_WITH_UNRESOLVED,7 métodos modificados,90 fuentes alcanzadas,14 expedientes y46 consumidores sin resolución estática. Ocho expedientes consumidores incorporan revisión documental. Las incertidumbres no se consideran aprobadas. Build web correcto; la ruta compilada respondió503 esperado con servicio desactivado, sin error de carga del módulo.
