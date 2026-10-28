# TEMPORARY — Original-App Config Export Lab

Rama exclusiva: `feat/temporary-original-app-config-export-lab`.
Trabajo inicial del 26 de octubre de 2026 (America/Tijuana), continuación
Dark Tunnel del 27 de octubre (UTC). **No fusionar a main**.
HTTP Custom 7.11.28 Patch 1, build 899, HCX4 / HCCFG10 / n11 sin
contraseña/HWID, y laboratorio Dark Tunnel 1.0.26, build 32.
No se implementa un exportador de producción.

## Estado actual: HTTP Injector y decisión sobre banners

El propietario confirmó los banners de **HTTP Custom**. Para **Dark Tunnel**,
informó que añadir el banner bloquea la configuración: sus exportaciones
abiertas deben ir **sin banner**. El generador histórico exige ahora
`--reproduce-locking-banner` y está desactivado por defecto.
Ver `results/banner_owner_decision_2026-10-27.json`.

La siguiente fase usa el APK **HTTP Injector 6.5.0 / build 244** y la muestra
`.ehi` disponible, con `configVersionCode` 229. El rewrap A reproduce el archivo
original byte por byte. Se prepararon cinco casos A–E y dos diagnósticos,
preservando ambos JSON y las conexiones. Se corrigió la reconstrucción del
checksum **Adler-32** que el lector Python existente no verifica.

**Actualización del propietario:** solo A se importó. B–E fueron rechazados
con un mensaje de versión. Los dos controles auxiliares no tienen resultados
individuales confirmados. El paquete anterior es histórico y **no constituye
una exportación compatible**. Los números de versión no cambiaron. La
comparación posterior con `Open.ehi` y el importador recuperado confirmó un
**HMAC exterior desactualizado** en las seis variantes modificadas. Se
recuperó su derivación desde el APK y se verificaron ambos originales.
También se corrigieron la sal exterior ausente y el hash de bloqueo abierto.

El nuevo auditor detecta campos aún sin interpretar, un candidato TLS con
la sal predeterminada y pérdida de tipos al reconstruir JSON desde texto de
presentación. La nueva matriz con HMAC contiene A–E y tres controles del
abierto propio: ocho verificaciones completas locales. **El propietario
confirma importación de A y E_ACCESS_HTML_HMAC_CANDIDATE, y confirma que E
permite editar la configuración y muestra correctamente el banner. B/C/D
fueron rechazados como configuración inválida o archivo dañado, según una
descripción aproximada del mensaje.** Los tres controles `owned_open/` no
fueron nombrados individualmente. El flujo E queda validado manualmente para
esta muestra en importación, editor y HTML. Conexión, otros perfiles y causa
de los rechazos restantes siguen pendientes.
Ver `results/ehi_authenticated_manual_import_2026-10-27.json`.
Pasan **32 pruebas del laboratorio + 6 del lector existente**. Sin clave HMAC
verificada, el escritor sigue bloqueando modificaciones. No se cambia ningún
decodificador productivo, Android ni la API.
Ver [corrección autenticada y nueva tanda](docs/HTTP_INJECTOR_AUTHENTICATED_EXPORT.md).
Ver [investigación y pruebas HTTP Injector](docs/HTTP_INJECTOR_EXPORT_LAB.md).
Ver [diagnóstico del rechazo y de la salida descifrada](docs/HTTP_INJECTOR_REJECTION_AND_DECODE.md).

## Continuación: Dark Tunnel y repositorio migrado

Por instrucción del propietario, esta continuación utiliza exclusivamente la
cuenta GitHub **gokussj092** y el repositorio privado
`gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`, conservando esta rama.
Su punto de partida era el mismo commit `9cafafeb9e8cb8a1f31be285467004dec393bba5`.
El nombre de la aplicación y sus créditos se mantienen como SP-DECODE.

Se interpreta la referencia verbal a «Hot Tunnel» como **Dark Tunnel**, porque
los materiales disponibles son `DarkTunnel_1.0.26.apks` y una muestra `.dark`.
La muestra está **ya abierta**, con `darktunnel://` + Base64 + JSON VLESS.
No existe todavía una muestra bloqueada real de Dark Tunnel en los materiales
disponibles. No confundir los controles artificiales con una exportación del APK.

El lector experimental preserva JSON y MessagePack originales, bytes, claves
`Password`, secciones desconocidas y capas AES-CFB. El CLI exporta tanto `.dark`
como el token de texto. El desbloqueo experimental reconstruye SSH y VLESS
cuando todo el contenido coincide con los esquemas auditados. Las demás
variantes se rechazan expresamente.

**El propietario confirmó que las pruebas del paquete fueron correctas y que
ninguna falló sin banner. El ensayo posterior con banner bloqueó el editor y
el propietario descartó su uso en Dark Tunnel.** La aceptación de importación
de las variantes A–F se registra como reporte manual global del propietario,
sin medición independiente de hashes en el dispositivo ni resultados individuales
de los controles. Ver `results/dark_manual_import_report_2026-10-27.json`.

Las **25 pruebas nuevas + 38 regresiones HTTP Custom** ya habían pasado.
Seis serializadores Go originales fueron ejecutados con valores
sintéticos y el cifrado se contrastó con un segundo backend. No se ha cambiado
el lector productivo, el router de textos, Android ni la API.

El ensayo histórico del banner se conserva en
`scripts/create_dark_banner_matrix.py`, con opt-in obligatorio para reproducir
el bloqueo comunicado por el propietario. Ver
[archivos y prueba visual del banner](docs/DARK_TUNNEL_BANNER_TESTS.md).
Solo se sustituye `LockedAppConfig.Message` del control cifrado anterior;
conexiones y banderas se conservan, pero su presencia activa el comportamiento
de configuración bloqueada observado. **No usar banner para exportaciones
abiertas Dark Tunnel.**

Ver [diagnóstico, límites y reproducción](docs/DARK_TUNNEL_EXPORT_LAB.md),
`scripts/dark_tunnel_experiment.py`, `scripts/create_dark_export_matrix.py`
y los resultados `results/dark_*_2026-10-27.json`.

## Estado actual: estructura importada y nueva nota HTML

El propietario confirmó importación correcta de los tres archivos principales:
**A_owned_open_rewrap, D_open_layout y E_open_layout_combined**. La estructura
abierta ya superó esa prueba manual. El reporte y los hashes se conservan en
`results/open_layout_manual_acceptance_2026-10-26.json` y el manifiesto histórico.

La nueva nota AMOLED usa los créditos de SP-DECODE, Ghost Developer y
Ghost Nexora Studio, y enlaces oficiales del sitio, canal y comunidad.
**Siempre sustituye el contenido anterior o se inserta si no hay nota.**
El formato observado para HTML es `main.g.x = {v:1,s:"custom",h:HTML}`;
`main.g.v` se sustituye también por créditos legibles.

Ver [diseño, campos y comandos actuales](docs/HTTP_CUSTOM_HTML_NOTES.md).
Fragmentos y vistas previas en `notes/`; módulo `spdecode_note.py` y comando
`write_hc_html_note.py` en `scripts/`. El conversor abierto incorpora la nota
por defecto. El propietario confirmó los F/G con HTML mediante un reporte global;
no se midieron otra vez sus hashes en el dispositivo. Pasan 38 pruebas locales;
la selección del HTML también
se contrastó con la rama nativa usando datos sintéticos.

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
