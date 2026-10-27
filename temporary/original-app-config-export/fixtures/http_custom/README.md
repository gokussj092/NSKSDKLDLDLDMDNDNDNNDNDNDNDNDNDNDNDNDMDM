# TEMPORARY PRIVATE TEST FIXTURES

Las dos muestras `.hc` binarias completas se guardan fuera del historial de
Git, dentro de `SP_DECODE_TEMPORARY_EXPORT_LAB_COMPLETE.zip` (adjunto privado
a la conversación), por contener potenciales credenciales.

`MANIFEST.json` registra los tamaños y hashes; el ZIP contiene
`fixtures/http_custom/source_original.hc` y
`fixtures/http_custom/export_rejected.hc`.
`source_decoded.json`: resultado legible del decoder.
`edited_preview.json`: vista modificada, no esquema completo de exportación.
`roundtrip_verification.json`: bitácora del experimento local anterior.

Restaurar con `unzip -p ZIP fixtures/http_custom/source_original.hc > /tmp/original.hc`.
No subir los binarios a Git ni compartirlos con herramientas de escaneo externas.
