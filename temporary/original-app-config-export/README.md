# TEMPORARY — Original-App Config Export Lab

> **TEMPORAL / TEMPORARY. SOLO PRUEBAS. NO FUSIONAR A `main`, NO DESPLEGAR, NO PUBLICAR COMO EXPORTADOR FUNCIONAL.**
>
> Rama: `feat/temporary-original-app-config-export-lab`. Fecha: 2026-10-26. Alcance actual: **HTTP Custom** (HCX4 / HCCFG 10 / `n11`), no las demás aplicaciones.

## Objetivo

Guardar en una zona de diagnóstico temporal el script de reencriptación HCX4,
los archivos originales, la salida de prueba, los JSON de lectura y la evidencia
de validación. Permite reproducir el caso reportado por el propietario de
SP-DECODE antes de integrar un exportador a la API o Android.

**Reporte confirmado por el propietario**: HTTP Custom acepta/decripta
criptográficamente el archivo reconstruido, pero posteriormente informa un error
de **formato JSON inválido**. Por tanto, el archivo **NO está certificado como
importable**, incluso aunque el decodificador Python lo abra correctamente.

## Archivos

- `scripts/hc_hcx4_n11_experiment.py`: variante mantenible y aislada del
  experimento de reencriptación; reaprovecha `codec.py` y `_hc_hccfg.py` de
  `main`, sin alterar los motores productivos.
- `fixtures/http_custom/source_original.hc.b64`: fuente HCX4 íntegra,
  codificada en Base64 **solo para almacenarla como texto en GitHub**.
- `fixtures/http_custom/export_rejected.hc.b64`: salida de la prueba histórica,
  rechazada por el validador JSON de la aplicación original.
- `fixtures/http_custom/source_decoded.json`: JSON legible producido por el
  decodificador de SP-DECODE, no es un sobre HC completo.
- `fixtures/http_custom/edited_preview.json`: campos editados autorizados por
  el propietario; reproducción precisa del intento rechazado.
- `fixtures/http_custom/roundtrip_verification.json`: evidencia del experimento
  local anterior, **no** una certificación de importación Android.
- `docs/HTTP_CUSTOM_IMPORT_TRIAGE.md`: hipótesis, comprobaciones y matriz de
  pruebas controladas.

Las configuraciones son materiales aportados por el propietario y pueden
contener servidores, usuarios, contraseñas, notas y URLs privadas. **El repositorio
es privado al momento del alta**. No copiar, imprimir en logs, utilizar en CI
público ni trasladar a un repositorio público. Base64 no protege secretos.

## Reproducir sin tocar el producto

Desde la raíz del repositorio, en un entorno aislado, con
`python -m pip install -r requirements.txt`:

```bash
mkdir -p /tmp/spdecode-export-lab
base64 -d temporary/original-app-config-export/fixtures/http_custom/source_original.hc.b64 > /tmp/spdecode-export-lab/original.hc
base64 -d temporary/original-app-config-export/fixtures/http_custom/export_rejected.hc.b64 > /tmp/spdecode-export-lab/previous-rejected.hc

python temporary/original-app-config-export/scripts/hc_hcx4_n11_experiment.py \
  --source /tmp/spdecode-export-lab/original.hc \
  --edited temporary/original-app-config-export/fixtures/http_custom/edited_preview.json \
  --output /tmp/spdecode-export-lab/new-experiment.hc
```

La salida tiene nonces criptográficos aleatorios y normalmente otro SHA-256;
por tanto comparar **el JSON descifrado** y la estructura del sobre, no los
bytes exactos contra el intento histórico. No introducir credenciales en
argumentos de línea de comandos ni enviar el archivo de prueba a una API pública.

**Importante**: los nombres `source_decoded.json` y `edited_preview.json`
describen una **proyección de lectura** del formato, no un contenedor válido
para importación directa. El script recupera el contenedor original, reescribe
solo su sección cifrada `i` (JSON principal) y conserva `j` y los metadatos
del sobre original. Esa conservación ayuda a evitar perder líneas/secciones
por usar el JSON de presentación como fuente de exportación.

## Limpieza

Carpeta y rama **temporales**, no destinadas a `main`. Después de las pruebas,
eliminar esta rama y las copias temporales locales de las muestras. **Borrar una
carpeta en un nuevo commit no elimina secretos de la historia de Git**:
si se llegaran a fusionar los fixtures, sería necesario sanear la historia y
rotar las credenciales expuestas. Mantener `main` y los despliegues sin cambios.
