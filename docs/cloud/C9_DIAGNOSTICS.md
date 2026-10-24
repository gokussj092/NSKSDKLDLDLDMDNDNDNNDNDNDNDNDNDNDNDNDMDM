# C9 — Diagnósticos y estadísticas de instalaciones

## Alcance
- API autenticada para reportes expresos desde Android, sin archivos adjuntos ni texto libre.
- Incidencias automáticas del worker en registros acotados, sin nombres de archivo, contenidos, claves, URL ni IP.
- Registro voluntario de una instalación aleatoria generada en Android; HMAC del lado del servidor y HyperLogLog diario, sin usuarios personales ni HWID.
- Dashboard administrativo con incidencias y contadores estimados. Retención: 8 días incidencias; hasta 32 días para cardinalidad.
- Participación desactivada por defecto, interruptor en Ajustes y eliminación local al retirar consentimiento.
- No modifica las funciones de descifrado ni incorpora redes publicitarias, pagos o sincronización de catálogos.

## Privacidad y obligaciones
La muestra de fallos es acotada; no admite subida de archivos. Las incidencias generadas por el servidor y los reportes voluntarios no tienen vínculo verificable con un archivo completo sin datos adicionales. El administrador ve el código, formato, servicio, UTC, tamaño aproximado (si disponible) y referencia. No se puede reconstruir el archivo. Los usuarios pueden detener la telemetría de actividad desde Ajustes; los agregados ya formados son irreversibles por individuo. Las cifras estiman instalaciones participantes, no personas reales.

El tratamiento y categorías declaradas en la ficha de Play Console deben revisarse antes de publicar esta versión. Los textos legales ES/EN del sitio están marcados como provisionales y requieren revisión jurídica.

## Pruebas de despliegue
1. Confirmar que la API rechaza reportes sin sesión C3, formatos desconocidos, tamaños de cuerpo excesivos y campos extra; comprobar el límite de reportes.
2. Verificar que archivos normales, importación HTTP Injector Cloud y Server VPN siguen funcionando y que los contadores automáticos se activan solo ante fallos relevantes.
3. Verificar que activar estadísticas genera una instalación aleatoria, envía una comprobación diaria y permite desactivar/limpiar la clave local.
4. Confirmar que el panel sigue privado, que no muestra archivos o IP y que el histórico no inventa datos anteriores al despliegue.
5. Comprobar idioma, traducción del botón Reportar error y ajustes de privacidad en Android físico; validar QA, producción y legal consent.
6. Confirmar Redis HyperLogLog en instalación real y monitorear el consumo bajo carga. Los registros y cardinalidades deben caducar automáticamente.

## Limitaciones intencionales
Las incidencias no adjuntan muestras de archivos. Los reportes manuales actuales no permiten texto libre o capturas. Se prevé ampliar únicamente tras definir una política de consentimiento explícito y cifrado de adjuntos.
