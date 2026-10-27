# HTTP Custom — referencia propia sin bloqueos y migración de estructura

Fecha: 2026-10-26, America/Tijuana. Rama temporal existente; sin cambios productivos.

> Actualización: el propietario confirmó que A, D y E se importaron
> correctamente. La nota HTML nueva y su estado de prueba están en
> [HTTP_CUSTOM_HTML_NOTES.md](HTTP_CUSTOM_HTML_NOTES.md). Los estados pendientes
> de este registro describen el momento anterior a esa confirmación.

## Corrección del diagnóstico anterior

El propietario confirmó que **D_access_none.hc y E_combined_none.hc también
fallaron con los mismos errores**. Por tanto, recuperar el enum correcto no
resolvió el archivo. El intento anterior cambiaba el modo, pero dejaba intacta
la representación de perfil que acompañaba al modo bloqueado.

El nuevo archivo `Test Oppen.hc` fue creado y exportado por el propietario sin
activar bloqueos. Sus bytes autentican como HTTP Custom build 899, HCCFG10/n11,
sin contraseña ni HWID. SHA-256:
`0e7abec160052b9588a715ada05eddd1e5787bfe9dc5fa5551aa112f92422c2e`, 3181 bytes.
La muestra confirma directamente `main.g.a = "none"` en una exportación real.

## Diferencias comprobadas

| Propiedad | Original bloqueado | Candidato anterior `none` | Exportación propia abierta |
| --- | --- | --- | --- |
| `main.g.a` | `lock_all` | `none` | `none` |
| `envelope.f` / `main.c` | `ssh` | `ssh` | `ssh, profiles` |
| Plaintext autenticado de `j[0]` | `HPR1` | `HPR1` | `HPC1` |
| Capa interna adicional | XChaCha20-Poly1305 dentro de HPR1 | Se conservaba | No existe |
| Sidecar `j[0].d` | Presente; contiene custom payload | Se conservaba | Ausente |
| Campo auxiliar HPC1 | Conservado | Conservado | Presente, con otro contenido de conexión |
| Tags AEAD por archivo | 5 | 5 | 3 |
| Otros campos presentes | Sin `main.l` ni `main.g.x` | Igual al original | `main.l`: string; `main.g.x`: object |

Los hashes y tipos, sin valores de conexión, están en
`results/open_layout_comparison_2026-10-26.json`. La comparación no interpreta
`main.l` y `main.g.x` como obligatorios: los archivos contienen configuraciones
y notas distintas. No se copian valores desconocidos de una conexión a otra.

**Diferencia estructural demostrada:** los archivos anteriores decían `none`
pero seguían llevando HPR1, sidecar y la lista de capacidades del original
bloqueado. **Causalidad del mensaje del importador:** todavía no se ha
capturado la excepción ni se ha probado en Android la nueva migración.
Es la siguiente hipótesis controlada, no una certificación de causa única.

## Reconstrucción experimental nueva

El script `hc_open_layout_experiment.py` exige una referencia abierta real que
se autentique, con `none`, `profiles` y perfiles HPC1 directos sin sidecars.
No utiliza sus servidores, credenciales, notas o campos de presentación como
plantilla de conexión.

Para el original autorizado:

1. Autentica todo el archivo original, incluida la capa HPR1 y el sidecar.
2. Cambia el modo a la cadena `none`.
3. Añade la capacidad observada `profiles` tanto a `envelope.f` como a `main.c`.
4. Deriva nuevamente la clave y AAD: **la lista de capacidades participa en
   HKDF/AAD**, por lo que modificarla sin volver a cifrar invalida los tags.
5. Retira HPR1 del perfil, conservando su HPC1 descifrado y autenticado.
6. Cuando hay sidecar UTF-8, migra su texto a la opción **ya existente**
   `customPayload` del JSON de opciones HPC1. No lo inserta a ciegas en el
   campo auxiliar binario que el lector denomina `payload`: esa cadena no
   representa siempre el custom payload (la referencia aportada la usa para
   otro parámetro de conexión). Se rechaza un valor existente distinto, una
   opción ausente o un sidecar binario de semántica no establecida.
7. Elimina el sidecar solo después de comprobar la migración. Rechaza metadatos
   desconocidos dentro de un sidecar que habrían de perderse al eliminarlo.
8. Vuelve a sellar main, secciones y sobre, preservando los demás metadatos.
   Todos los bytes HPC1 fuera de la cadena de opciones permanecen idénticos;
   dentro de las opciones solo cambia el token `customPayload`.
9. Compara todos los parámetros efectivos de conexión y autentica cada tag con
   PyCryptodome y con el backend puro Python.

La migración de `customPayload` conserva el dato completo y utiliza una clave
existente con ese nombre; su consumo por el importador original en este modo
sigue pendiente de prueba. No se presenta como una conexión ya comprobada.

El perfil cifrado `j` necesariamente cambia en esta investigación: conservar
sus bytes impedía ensayar la estructura abierta observada. No se cambia
ningún servidor, puerto, usuario, contraseña, SNI, opción ajena, expiración,
HWID ni política remota. Los originales no se sobrescriben.

Los campos desconocidos del sobre se conservan como valores JSON. Se mantiene
el texto original del sobre fuera de las sustituciones `f`, `i.b/i.c` y `j`;
la colección `j` se serializa de nuevo para retirar `d` y renovar sus tags.
No se promete identidad lexical de esa colección modificada.

## Casos generados

| Archivo | Propósito | Estado |
| --- | --- | --- |
| `A_owned_open_rewrap.hc` | Reencriptación de `Test Oppen.hc` sin cambios de contenido | AEAD local correcto; importación pendiente |
| `D_open_layout.hc` | Original con `none`, HPC1 directo, `profiles` y custom payload migrado | 3 tags correctos; importación/edición pendientes |
| `E_open_layout_combined.hc` | D más nota y URL solicitadas | 3 tags correctos; importación/edición pendientes |
| `diagnostics/B_hpc1_only.hc` | Solo retirar HPR1; conserva capacidades y sidecar | Diagnóstico para aislar la envoltura; no ensayo final |
| `diagnostics/C_hpc1_profiles.hc` | Retirar HPR1 + `profiles`; conserva sidecar | Diagnóstico para aislar capacidades; no ensayo final |

Los dos diagnósticos mantienen el payload auxiliar intacto y autenticado, pero
no reproducen completamente la referencia abierta. No se solicitan como
primeras pruebas si D/E ya permiten determinar el resultado.

Hashes: `results/open_layout_matrix_2026-10-26.json`. El ZIP privado incluye
estos archivos, una guía y plantilla de resultados. Las muestras no están en
Git. `create_hc_access_followup.py` ahora solo reproduce los negativos anteriores
con `--reproduce-rejected-layout`. El rewrap simple bloquea por defecto
`lock_all → none` si conservaría HPR1; no vuelve a presentarlo como candidato.

## Reproducir y comprobar

```bash
python temporary/original-app-config-export/scripts/compare_hc_layouts.py \
  --source /ruta/privada/source_original.hc \
  --reference '/ruta/privada/Test Oppen.hc' \
  --previous-none /ruta/privada/D_access_none.hc \
  --output /ruta/privada/nueva-comparacion.json

python temporary/original-app-config-export/scripts/hc_open_layout_experiment.py \
  --source /ruta/privada/source_original.hc \
  --reference '/ruta/privada/Test Oppen.hc' \
  --output-dir /ruta/privada/hc-open-layout-nuevo

python temporary/original-app-config-export/scripts/test_hc_export_lab.py -v
python temporary/original-app-config-export/scripts/test_hc_open_layout.py -v
python -m unittest tests.test_http_custom_899 -v
```

Entorno canónico del codec: Python 3.12.14, PyCryptodome 3.23.0, argon2-cffi
25.1.0. Pasan **14 + 7 + 9 = 30 pruebas**. Las nuevas regresiones detectan pérdida
de payload, expiración cambiada, metadatos de sidecar desconocidos, referencias
no abiertas, manipulación criptográfica y cambios binarios no autorizados.

## Qué falta en Android

1. Importar A, control de la nueva muestra propia, para comprobar que se
   reconoce el mismo punto de partida tras reencriptar.
2. Importar D y comprobar aceptación y edición de campos. No iniciar conexión
   hasta separar el resultado de importación del de funcionamiento de la VPN.
3. Importar E y comprobar además la nota. La URL de prueba es la portada
   autorizada; no se certifica como servidor de actualización de configuraciones.
4. Si D falla, los diagnósticos B/C ayudan a separar la capa HPR1, la declaración
   de capacidades y la migración del sidecar. Los campos adicionales `l` y `g.x`
   permanecen como diferencias para investigar, sin asumir que copiarlos sea
   válido o necesario.

**Resultado vigente:** `none` es el valor textual real. El cambio aislado fue
insuficiente y rechazado. La migración de estructura nueva pasa la verificación
local y conserva los datos, pero su compatibilidad original sigue pendiente.
