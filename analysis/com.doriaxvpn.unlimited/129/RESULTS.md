> **Actualización 2026-11-04:** la consulta automática de URL/contraseña ya está implementada en CLI y broker. [Comportamiento vigente y pruebas](REFRESH_2026_11_04.md). El texto siguiente conserva la investigación inicial y sus limitaciones históricas.

# Resultados y límites

## Revisión de consumidor compartido, 2026-11-10

Se revisó el cambio del broker C3 para HTTP Custom revision 57. La excepción
exige `kind=file` y `format=hc`; no altera esta ruta de catálogo ni admite
resultados parciales de HTTP Conexión. Las pruebas de rotación autenticada y
rechazo de JSON parcial/no coincidente siguen pasando. Evidencia del cambio:
[HTTP Custom 564](../../xyz.easypro.httpcustom/564/RESULTS.md).

| Entrada | Estado | Versión /servidores | Campos GCM | Paridad |
| --- | --- | --- | --- | --- |
|Fuente /new elegida por Firebase|VERIFIED_REAL|107 /244|5325 /5299 únicos|JSON completo igual a JCA/CLI/worker|
|Segunda descarga por adaptador operativo|VERIFIED_REAL|107 /244|5325|Mismos bytes y comparación íntegra|
|Asset config.json|VERIFIED_REAL_INCLUDED|1 /7|84 /84 únicos|JSON completo igual a JCA/CLI/worker|
|Default /Update de APK|REAL_HTTP_OBSOLETE_SOURCE|57 /251|Censo separado|No se usa en producción como fuente actual|

Activo: HTTP200/application/octet-stream/4311432bytes, SHA256
`582549fb87e8303010dc332ef770002e2c0e2bd9cc52b0542ff89d4c96522323`.
Default:2699520bytes/SHA256de9ba992…4e85; no sustituye /new aunque tenga más filas.
Firebase FIS200/RemoteConfig200/template17 y eliminación de instalación200;
perfil analítico MX/es-MX/API34, no dispositivo físico ni atestación.

**VERIFIED_SYNTHETIC:**10 Python y147 Node aprobadas. Fixtures generados por JCA,
Base64 interno/externo con LF, ROT34 completo, Unicode, tipos/valores vacíos,
metadatos futuros, GCM inválido sin fallback, inner-Base64 inválido con tag válido,
CBC/clave incorrecta, glifos/truncado/HTML/duplicados/NaN/esquema/límites.
Node cubre fuente actual, timestamp y headers, TLS/DNS, redirects,404 sin
fallback viejo, icono original grande, switches y documento entero no parcial.

**Intentos conservados:** primer pase default real57 pero preferencia sin
confirmar; se investigó Firebase y corrigió a107. Censo Base64 estricto falló
por LF; JCAv1 también falló en Base64 interior después de verificar GCM.
Se guardan las revisiones usadas, la intermedia y el censo comparativo. No se
relajó autenticación GCM ni se inventó un JSON. JADX:3/0/3/3 con22/0/11/3 errores;
sc1.run se recuperó desde Dalvik, no se asumió éxito total de decompilación.

**SIMULATED_HTTP_REAL_BYTES:** replay Node procesa los4311432bytes reales y
el worker real, con HTTP/DNS simulados, y mantiene JSON completo107/244.
**PENDING:** transporte Node real/VPS (REMOTE_NETWORK_DENIED aquí), revisión del
PR y rollout. No se probaron cuentas/conexiones, Android, archivos/textos o
exportaciones. No se certifica integridad autenticada de toda la metadata CBC;
los5325 campos GCM sí validan sus tags.

Proveedor http-conexion, icono original618×613/449874bytes, piso67/63 fichas,
256 formatos. Constantes del formato inline; no nuevos secretos externos.
URL/password quedan fijados a la observación template17; cambios futuros o
condiciones Firebase distintas requieren revisión, no URLs arbitrarias.

No cambios/build Android, merge ni deploy. APK/SO, tokens Firebase, IDs,
decompilación y configuraciones VPN reales quedan fuera de Git. Se inventarían
certificados V2/V3, no firma Play/última versión oficial certificada. Licencias
transitivas/autoaprobación Fase7 pendientes; el validador CI de evidencia sigue
especificado y no implementado.
