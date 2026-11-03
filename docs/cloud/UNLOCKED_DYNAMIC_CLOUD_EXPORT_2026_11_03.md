# SP-DECODE — exportación Unlocked universal por capacidades Cloud
Fecha: 2026-11-03 · Rama: `fix/http-jireh-current-method` · `main` sin cambios

## Objetivo
La función «Exportar Unlocked» no puede depender de tres o cinco nombres de aplicaciones compilados en Android. El servidor y su worker Python determinan qué formatos tienen **conversor de exportación real**. El catálogo cifrado de Cloud anuncia una lista dinámica; el archivo descargable requiere un resultado `compatibleExport.status == "ready"` que pase la verificación cliente.

## Contrato de compatibilidad
* APKs anteriores: encabezado `X-SPDecode-Compatible-Export: 1`, respuesta de catálogo `schemaVersion: 1` limitada a HC, Dark, EHI, NPVS y, cuando el cliente anuncia HA, HAT. No alterar sus respuestas ni habilitar formatos nuevos para un cliente antiguo.
* APK actual 1.1.26 b41: JNI anuncia `X-SPDecode-Compatible-Export: 2`. El servidor valida versión mínima; anuncia `compatibleExports.schemaVersion: 2` con todas las entradas del registro revisado. Un cambio de revisión en el registro incrementa la versión proyectada del catálogo para forzar su actualización.
* El registro `cloud/web/content/compatible-export-formats.json` es compartido con `cloud/workers/python/exports/job.py` en el contenedor worker. No se expone código privado de conversión, claves ni rutas ejecutables en Android.
* El importador `ServerVpnCatalogRepository` valida y conserva el catálogo en el almacén cifrado existente. La interfaz solicita el resultado de exportación **en el mismo descifrado** sin lista fija de sufijos.
* El servidor, no Android, controla la disponibilidad mediante la política global, la negociación del cliente y el exportador real; una configuración sin exportador devuelve `status: unavailable` y sigue mostrando el JSON descifrado sin archivo.
* El cliente solo ofrece exportar cuando recibió una carga autenticada `ready` con extensión, formato, aplicación destino, longitud y SHA-256 coherentes con el archivo de origen y el resultado descifrado. Rechaza referencias HTTP, identificadores inseguros, Base64 no canónico, tamaños extremos y cualquier protección que siga siendo necesaria.
* Los archivos exportados conservan nombre de origen y el sufijo « (Unlocked)», guardados por SAF a elección del usuario; jamás se reconstruyen copiando secretos de los textos del visor. El historial cifrado puede restaurar exportaciones ya obtenidas.
* Aplicación de soporte: el catálogo sirve para mostrar capacidades; no afirma que una variante protegida concreta pueda exportarse ni que el proveedor VPN remoto la aceptará. Esto se decide al procesar ese archivo y al verificar importación en la aplicación destino.

## Cómo integrar una nueva aplicación Unlocked sin cambiar Android
1. Implementar y probar un exportador auténtico y reversible bajo `cloud/workers/python/exports/`. Verificar el archivo por importación en la aplicación original; no limitarse al JSON descifrado ni alterar autorización remota del proveedor.
2. Añadir una rama explícita en `cloud/workers/python/exports/bridge.py`, con aislamiento y recursos limitados, que llame a dicho exportador.
3. Agregar al registro `cloud/web/content/compatible-export-formats.json` el sufijo público que **ya exista** en el catálogo de formatos, `targetAppId`, nombre legible y el tipo de banner. Subir su `revision` monotónicamente y probar que no haya duplicados. No activar una entrada que no tenga conversor verificado.
4. Ejecutar tests Node, Python, compilación Android, verificación de exportación/reencriptado/importación real y revisar permisos y política de publicación. Desplegar web y worker juntos. Mantener la opción general del panel de exportación habilitada (`CLOUD_COMPATIBLE_EXPORT_LOCKED` debe permitirlo).
5. La siguiente actualización autenticada del catálogo y el próximo descifrado habilitarán el botón en la APK 1.1.26+ sin otro cambio de UI. **No es necesario publicar una APK por cada nuevo exportador.**

## Límites y pendientes
* Integración de fuente en GitHub. No se ha publicado, desplegado en VPS ni fusionado con main.
* El registro declara los cinco exportadores existentes, no inventa soporte para Hex Tunnel u otras aplicaciones que aún no tengan convertidor compatible comprobado.
* Puede haber diferencias de importación dependiendo de la versión concreta del fabricante. Test por variante antes de declarar `ready`.
* Catálogo y archivo exportado se transportan mediante el canal actual autenticado HPKE y se guardan cifrados en historial; no se añaden endpoints públicos ni claves en Kotlin.
