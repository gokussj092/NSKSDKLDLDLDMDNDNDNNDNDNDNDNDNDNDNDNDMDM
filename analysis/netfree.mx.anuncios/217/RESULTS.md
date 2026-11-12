# Resultados

## Revisión de consumidor compartido, 2026-11-10

Se revisó el cambio del broker C3 para HTTP Custom revision 57. La excepción
solo permite `kind=file`/`format=hc` con el esquema exacto documentado; las
dos rutas de catálogo SpeiGo conservan sus validaciones y separación. La
prueba aislada de descargas y restricciones de destino pasó. Evidencia:
[HTTP Custom 564](../../xyz.easypro.httpcustom/564/RESULTS.md).

Catálogo: VERIFIED_REAL sobre APK217.4.4/build217; integración en código,
sin merge ni despliegue.

| Entrada | Servidores | Usuarios | Campos internos | Comparación completa |
| --- | --- | --- | --- | --- |
| Incluidos | 17 / 266 | 1 / 2 | 2649 + 12 | JCA = Python = CLI = worker |
| Remotos GET200 | 17 / 266 | 2 / 2 | 2649 + 12 | JCA = Python = CLI = worker |
| Descarga operativa repetida | 17 / 266 | 2 / 2 | 2649 + 12 | JCA = Python = CLI = worker |

10 Python / 154 Node aprobadas; reproducción posterior a limpieza incluida.
Fixtures ficticios cubren todos los campos, Unicode/metadatos, esquema, parejas
incompletas/intercambiadas, límites, HTML, padding/clave incorrectos, errores
sin devolver ciphertext como texto, JSON duplicado/NaN, CLI/stdin/worker,
destinos fijos, DNS privado, TLS/redirecciones, icono y switches persistentes.
La compatibilidad real proviene de los documentos reales completos, no solo
de los fixtures. CBC no proporciona autenticidad criptográfica.

Node directo real: NETWORK_UNAVAILABLE/REMOTE_NETWORK_DENIED. Replay de dos
fuentes reales y resultado real del worker: PASS, HTTP/DNS simulados. El VPS
real sigue pendiente. APK/perfiles/recipe/recursos sensibles quedan fuera de Git.

Herramientas/versiones efectivamente usadas: dependencies.lock.json y MANIFEST.
JADX3/0 con18/0 errores; métodos necesarios contrastados independientemente.
Sin Android/build, cuenta/VPN, archivos, texto o exportador certificado.
Licencias transitivas/aprobación automática fase7 y validador CI pendientes.
