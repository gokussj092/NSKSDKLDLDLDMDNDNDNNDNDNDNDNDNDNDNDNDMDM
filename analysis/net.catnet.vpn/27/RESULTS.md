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
