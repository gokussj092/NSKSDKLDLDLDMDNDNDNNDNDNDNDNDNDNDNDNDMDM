# Muestras privadas HTTP Custom

`MANIFEST.json` conserva nombres, tamaños y hashes de la fuente y el rechazado.
`roundtrip_verification.json` es el registro HISTÓRICO del rechazo, no el
resultado de la nueva matriz. La matriz actual está en `../../results/`.

Los binarios y JSON legibles están exclusivamente en el ZIP privado y fuera de
Git. Los anteriores `source_decoded.json` y `edited_preview.json` se retiraron
del árbol actual porque contenían datos de conexión. El historial anterior
sigue existiendo. El repositorio figura público, no debe tratarse como privado.

El script de matriz descifra la fuente y aplica los cambios autorizados sin
necesitar aquellos JSON. Para reproducir exactamente la nota histórica usar
`--edited` con la copia privada del ZIP. Para la nueva nota usar la matriz sin
`--edited`; su contenido coincide con el texto solicitado en esta investigación.

Staging verificable, exclusivo y sin sobrescritura:

```bash
bash temporary/original-app-config-export/scripts/stage_private_fixtures.sh \
  /ruta/privada/SP_DECODE_TEMPORARY_EXPORT_LAB_COMPLETE.zip \
  /ruta/privada/hc-fixtures-nuevos
```
