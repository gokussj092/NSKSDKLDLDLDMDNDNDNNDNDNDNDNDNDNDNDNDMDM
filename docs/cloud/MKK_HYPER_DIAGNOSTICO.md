# MKK Hyper — errores intermitentes de Server VPN (PR #96)

## Diagnóstico a partir del código

No hay evidencia suficiente para atribuir todas las incidencias reales a una única causa. Sin ejecutar solicitudes autenticadas desde la VPS ni disponer de los códigos de incidente del proveedor, no se puede confirmar si predominan fallos de sus endpoints, cambios de formato o límites de tamaño. No se ha tocado ningún endpoint, secreto ni regla TLS.

Sí se identificaron cuatro puntos reproducibles en el código:

1. **HTTP temporal (429/500/502/503/504 y sockets):** el descargador abortaba ante una respuesta temporal sin reintentar, incluso con una única IPv4 pública validada. Ahora hace un segundo intento acotado sobre el mismo destino verificado y bajo el plazo original de 30 s; con varias IPs públicas conserva la estrategia de alternativas. Los HTTP 401/403, los certificados incorrectos, los saltos a otro origen, la resolución privada y las respuestas corruptas siguen rechazándose.
2. **Agregado de cuatro fuentes mayor de 12 MiB:** antes devolvía `REMOTE_TOO_LARGE` aunque algunas respuestas cupieran por separado. Ahora conserva tantas fuentes completas como encajen en el límite del worker, por orden fijo, y marca explícitamente las excluidas como `REMOTE_TOO_LARGE`; nunca trunca campos silenciosamente.
3. **JSON demasiado extenso:** la agregación MKK usaba indentación de dos espacios, multiplicando el tamaño de salida. Ahora produce JSON compacto semánticamente equivalente; si aun así excede los 4 MiB admitidos, se emite el código `OUTPUT_TOO_LARGE` en lugar de un genérico `DECODE_FAILED`. No se ha incrementado el límite de salida porque el cliente Android podría no manejar un JSON tan grande.
4. **Contabilización incorrecta:** un fallo de las cuatro descargas salía de la función sin pasar por el registro habitual; ahora se contabiliza como fallo. Un resultado con solo parte de las fuentes se entrega como resultado parcial y se registra como advertencia `PARTIAL_SOURCE_FAILURE`, no como catálogo completo exitoso. El JSON contiene cada fuente y su estado sin exponer contenido privado en los logs de Redis.

## Interpretación de resultados

- `REMOTE_PROVIDER_UNAVAILABLE`: falló la descarga; revisar si el CDN/proveedor devuelve errores temporales o hay problemas de red en la VPS.
- `REMOTE_NETWORK_DENIED`: DNS/destino/redirección incumple reglas de seguridad; no relajar los controles sin inspección autorizada.
- `REMOTE_RESPONSE_INVALID`: respuesta remota vacía o codificación no admitida.
- `OUTPUT_TOO_LARGE`: el resultado JSON final excede 4 MiB incluso en formato compacto. No reducirlo silenciosamente.
- `DECODE_FAILED`: el motor no reconoce o no pudo descifrar las fuentes recuperadas; podría requerirse estudiar el formato con muestras autorizadas.
- `PARTIAL_SOURCE_FAILURE`: operación útil pero incompleta; consultar los estados sanitizados de las cuatro fuentes en la respuesta para determinar cuál falló.

## Validaciones

Las pruebas solo usan mocks HTTP y vectores sintéticos; no se descargan datos reales del proveedor. Cubren reintento 503, presupuesto de 12 MiB, estructura de resultados parciales, advertencias y error explícito cuando el JSON supera 4 MiB. El ajuste no añade proveedores ni altera Android, Play, catálogos de servidor o credenciales.

## Actualización conjunta del VPS (solo cuando las verificaciones estén en verde)

La instalación C8 usa una sola imagen Next.js para **API y panel** y otra imagen para el worker Python. Para aplicar ambas junto al decodificador MKK actualizado, ejecutar en la VPS:

```bash
sudo spdecode update all feat/austroplus-vpn-13-0-1-decoders
```

La CLI descarga el commit actual de esa rama, construye `decoder-worker` y `web` y los recrea conservando `/etc/spdecode/cloud.env`, cuentas del panel, certificados y controles de mantenimiento. Si el despliegue falla, intenta volver al commit previo. Después revisar `sudo spdecode logs all` y el estado del panel. **No hay despliegue automatizado por este cambio.**
