# TEMPORARY — Original-App Config Export Lab

Rama exclusiva: `feat/temporary-original-app-config-export-lab`.
Trabajo del 26 de octubre de 2026 (America/Tijuana). **No fusionar a main**.
Solo HTTP Custom 7.11.28 Patch 1, build 899, HCX4 / HCCFG10 / n11 sin
contraseña/HWID. No se implementa un exportador de producción.

## Estado actual tras prueba manual

El propietario confirmó importación correcta de la fuente y de **A, B y C**.
Fallaron el control rechazado y **D/E**, que cambiaban el acceso a `false`.
El rechazo queda aislado a `main.g.a = false`; la causa interna de tipo/coerción
no se distingue solo con esa prueba.

Se recuperó el enum real del APK mediante emulación ARM64 acotada: `none`,
`lock_all`, `lock_payload_unlock_server`, `unlock_user_pass`. El candidato
respaldado para la opción `NONE` es **`main.g.a = "none"`**.
Se generaron `D_access_none.hc` y `E_combined_none.hc`; ambos pasan AEAD local,
pero **su importación y editabilidad Android siguen pendientes**.

Ver [el seguimiento y los comandos](docs/HTTP_CUSTOM_ACCESS_FOLLOWUP.md).
Los datos manuales están en `results/manual_import_report_2026-10-26.json`;
la evidencia del enum, los nuevos hashes y auditorías, también en `results/`.

La matriz original A–E conserva el booleano como negativo reproducible.
Para los candidatos nuevos usar `scripts/create_hc_access_followup.py`.
La sonda `scripts/probe_hc_access_modes.py` es opcional, fijada a una biblioteca
por hash y solo de investigación; no ejecuta el importador ni necesita archivos
con conexiones.

## Correcciones

- Los comandos directos del README anterior fallaban con `ModuleNotFoundError:
  No module named 'decoders'`; los scripts ahora resuelven el repositorio.
- El baseline anterior volvía a serializar el JSON (426 → 419 bytes). Ahora
  conserva el plaintext completo, y el resto usa edición por tokens existentes.
  La diferencia de serialización **no está demostrada como causa del rechazo**.
- Comparaciones con tipos exactos evitan que Python acepte `False == 0`.
  No se permiten cambios fuera de `main.g.a`, `main.g.v` y `main.u`.
  Los strings de acceso se limitan a los cuatro valores recuperados del APK.
- Cambiar string a booleano se rechaza por defecto. D/E usan una excepción
  explícita de diagnóstico para reproducir `false`, sin aprobar ese esquema.
- Creación exclusiva de archivos 0600; matriz y staging exigen directorio
  nuevo. Hashes del ZIP se validan antes de escribir muestras.
- Se retiraron del árbol actual los dos JSON legibles con conexiones privadas.
  El repositorio figura **público** en GitHub. Esta retirada no borra la historia.

## Reproducir

Desde la raíz del repositorio, usar un entorno Python 3.12 con las dependencias
canónicas, sin modificar los decodificadores:

```bash
python -m venv /ruta/privada/hc-venv
/ruta/privada/hc-venv/bin/python -m pip install -r decoders/Python/apps/HTTP_Custom/requirements.txt

bash temporary/original-app-config-export/scripts/stage_private_fixtures.sh \
  /ruta/privada/SP_DECODE_TEMPORARY_EXPORT_LAB_COMPLETE.zip \
  /ruta/privada/hc-fixtures-nuevos

/ruta/privada/hc-venv/bin/python temporary/original-app-config-export/scripts/create_hc_import_matrix.py \
  --source /ruta/privada/hc-fixtures-nuevos/source_original.hc \
  --output-dir /ruta/privada/hc-matrix-nueva

/ruta/privada/hc-venv/bin/python temporary/original-app-config-export/scripts/audit_hc_matrix.py \
  --source /ruta/privada/hc-fixtures-nuevos/source_original.hc \
  --historical /ruta/privada/hc-fixtures-nuevos/export_rejected.hc \
  --matrix-dir /ruta/privada/hc-matrix-nueva \
  --output /ruta/privada/hc-audit-nuevo.json

/ruta/privada/hc-venv/bin/python temporary/original-app-config-export/scripts/test_hc_export_lab.py -v
/ruta/privada/hc-venv/bin/python -m unittest tests.test_http_custom_899 -v
```

La matriz no requiere JSON legibles versionados: obtiene `main` del original,
cambia la nota a los créditos solicitados y la URL a `https://spdecode.xyz`.
D/E prueban el booleano `false` del intento histórico. Otras opciones o notas
se pueden proporcionar mediante `--edited` con una proyección **privada**
completa. El script individual exige `--allow-access-type-change` para
reproducir expresamente el caso booleano.

No enviar las muestras a servicios externos. Nonces nuevos implican hashes y
tamaños de carrier UTF-8 diferentes en cada generación; no son una regresión.
Comparar contenido autenticado, campos y bytes conservados.

## Archivos públicos y privados

| Archivo | Uso |
| --- | --- |
| `scripts/hc_hcx4_n11_experiment.py` | Rewrap aislado, sin integración productiva |
| `scripts/lossless_json.py` | Edición de valores existentes conservando bytes ajenos |
| `scripts/create_hc_import_matrix.py` | A–E + manifiesto sin plaintext |
| `scripts/audit_hc_matrix.py` | Segundo backend AEAD puro Python, todos los tags |
| `scripts/test_hc_export_lab.py` | 13 regresiones sintéticas |
| `scripts/stage_private_fixtures.sh` | ZIP privado, hashes y protección contra sobrescritura |
| `results/` | Hashes, rutas de campos, indicadores, sin datos de conexión |
| `docs/HTTP_CUSTOM_IMPORT_TRIAGE.md` | Diagnóstico y prueba Android pendiente |
| ZIP privado nuevo de la conversación | Cinco variantes `.hc`, controles y guía de importación |

Los originales, el rechazado, las proyecciones completas y las variantes se
conservan fuera de Git. No se generó APK/AAB ni se modificó Android, API,
decodificadores productivos, otras aplicaciones o VPS.
