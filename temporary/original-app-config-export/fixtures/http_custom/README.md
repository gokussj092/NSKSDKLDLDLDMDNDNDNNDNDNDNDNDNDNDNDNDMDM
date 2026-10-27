# TEMPORARY PRIVATE TEST FIXTURES

Estas muestras originales están guardadas como Base64 para garantizar
almacenamiento byte a byte en GitHub; **NO** están anonimizadas y pueden
contener credenciales. No copiar fuera de este repositorio privado.

`source_original.hc.b64`: HCX4 original aceptado por el importador.
`export_rejected.hc.b64`: HCX4 experimentado; autenticación local correcta,
el importador de HTTP Custom informó JSON inválido.
`source_decoded.json`: resultado legible del decoder.
`edited_preview.json`: vista modificada, no esquema completo de exportación.
`roundtrip_verification.json`: bitácora del experimento local anterior.

Restaurar con `base64 -d origen.hc.b64 > destino.hc`. Las claves privadas y
credenciales no deben enviarse a herramientas de escaneo externas.
