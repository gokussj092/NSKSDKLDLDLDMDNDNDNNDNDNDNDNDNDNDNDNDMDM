# SP-DECODE — nota HTML personalizada para HTTP Custom

**Actualización 2026-10-27:** el propietario confirmó que los banners HTTP
Custom fueron correctos. Aceptación manual global del paquete F/G, sin nueva
medición de hashes en el teléfono ni desglose de cada propiedad CSS o enlace.
Ver `results/banner_owner_decision_2026-10-27.json`.

Fecha: 2026-10-26, America/Tijuana. Solo laboratorio temporal.

## Estado confirmado y alcance nuevo

El propietario confirmó que **A_owned_open_rewrap.hc, D_open_layout.hc y
E_open_layout_combined.hc se importaron correctamente**. Sus hashes históricos
están en `results/open_layout_matrix_2026-10-26.json`; el reporte manual está en
`results/open_layout_manual_acceptance_2026-10-26.json`. No se afirma una prueba
nueva de conexión, de todas las restricciones o de otros builds.

El cambio actual sustituye cualquier nota anterior por la identidad HTML de
SP-DECODE, incluso cuando la nota está vacía, es null o no tiene campo `v`.
No se integra un exportador permanente en Android, API ni decodificadores.

## Diseño

Plantilla AMOLED con los colores del tema actual de la app y la web pública:
negro `#000000`, panel `#242424`, texto `#f7f7f7`, secundario `#ababab`.
Tipografía de sistema, título fuerte, esquinas redondeadas y botones neutros.
Sin emojis, scripts, formularios, fuentes o imágenes remotas.

| Acción / crédito | Destino o contenido |
| --- | --- |
| Obtener SP-DECODE | `https://spdecode.xyz` |
| Canal oficial | `https://t.me/GhostDeve` |
| Comunidad / grupo | `https://t.me/CodeBreakersHub` |
| Desarrollador | Ghost Developer · `https://t.me/Gh0stDeveloper` |
| Organización | Ghost Nexora Studio |
| Aplicación | SP-DECODE |

Los enlaces de Telegram se contrastaron con README y configuración de la app.
El botón Obtener abre el sitio oficial: no se inventó un APK directo ni una
ficha de Google Play. El sitio del repositorio todavía muestra Google Play
como próximamente; la nota no promete disponibilidad pública de una versión.
La consulta externa de disponibilidad no pudo completarse y no se certifica
que cada destino remoto responda en todo momento.

`notes/spdecode-note.es.html` y `notes/spdecode-note.en.html` son los fragmentos
exactos incrustados. Los `.json` correspondientes contienen un único string
JSON ya escapado una vez, sin coma final. `notes/preview.es.html` y
`notes/preview.en.html` son páginas autónomas para abrir el diseño en navegador;
no son el documento que debe copiarse íntegro dentro de la nota.

## Campo correcto del renderizador

La exportación propia aportada ya contenía el esquema:

```json
{"x":{"v":1,"s":"custom","h":"contenido HTML"}}
```

`x` es `main.g.x`. Su clase nativa `K2867738049988678545` recibe un estilo y
una cadena. Se recuperó el enum `M5871054116968351869` y se ejecutó la rama
nativa `0xae31a4` con JNI modelado y strings sintéticos:

| Estilo | Valor devuelto por la rama nativa |
| --- | --- |
| `default` | null |
| `note` | String de nota normal entregado como argumento |
| `custom` | String HTML personalizado almacenado en el objeto |

Para el modo personalizado no basta con cambiar `main.g.v`. Ahora se escribe:

- `main.g.x.v = 1`, versión observada, con tipo entero exacto.
- `main.g.x.s = "custom"`.
- `main.g.x.h = plantilla HTML nueva`.
- `main.g.v = créditos y enlaces en texto normal`, como alternativa de lectura.
- Si `main.g.e` ya existe y es booleano, se activa. Si no existe, no se inventa.

La plantilla reemplaza los dos contenidos anteriores; no se concatena ninguna
nota ni HTML de terceros. Los demás campos de `g`, incluidos expiración, HWID
y bloqueo, se conservan. Dentro de `x`, los metadatos desconocidos se conservan.
Una versión desconocida de ese esquema se rechaza en lugar de sobrescribirse.

Evidencia nativa: `results/note_renderer_2026-10-26.json`.
Sonda reproducible: `scripts/probe_hc_note_renderer.py`, sobre la biblioteca
fijada por el mismo SHA-256 y requisitos opcionales que la sonda del enum.
La sonda no contiene conexiones reales ni ejecuta Android. Confirma la elección
de la cadena; no prueba el renderizado CSS ni la apertura de enlaces en WebView.

## Inserción sin pérdida de otros campos

`spdecode_note.py` aplica la plantilla; `put_member` añade únicamente el token
que falta dentro de un objeto existente. Así no se normalizan las claves,
escapes, exponentes ni espacios de los campos ajenos. No se adivinan padres
JSON ausentes.

`write_hc_html_note.py` sirve para un archivo ya exportado: cambia solo el JSON
principal y vuelve a sellarlo. La colección cifrada `j`, sus perfiles y los
parámetros de conexión permanecen **byte-idénticos**. Se autentican los tags con
el codec y con el backend puro Python.

El conversor de estructura abierta usa esta nota **por defecto** en sus
candidatos, tengan o no notas de entrada. Los controles sin cambios y los
negativos históricos conservan su función de investigación. Para reproducir
el comportamiento anterior existe el parámetro Python explícito
`personalize_notes=False`; no es la salida habitual.

## Uso

Con las dependencias canónicas de HTTP Custom, desde la raíz del repositorio:

```bash
python temporary/original-app-config-export/scripts/write_hc_html_note.py \
  --source /ruta/privada/D_open_layout.hc \
  --output /ruta/privada/F_spdecode_html.hc \
  --language es

python temporary/original-app-config-export/scripts/hc_open_layout_experiment.py \
  --source /ruta/privada/source_original.hc \
  --reference '/ruta/privada/Test Oppen.hc' \
  --output-dir /ruta/privada/nuevos-html \
  --language es
```

`--language en` selecciona la variante inglesa. Ningún comando sobrescribe una
salida existente. Los `.hc` y las proyecciones privadas no se suben a GitHub.

## Pruebas y entrega

Pasan **38 pruebas**: 14 del laboratorio original, 7 de migración abierta, 8 de
notas y 9 existentes del codec. Se prueban notas previas normales/HTML, estilos
anteriores, notas vacías/null/ausentes, metadatos desconocidos, versiones
incompatibles, activación de un flag existente, conservación de credenciales,
serialización única y creación de nota al convertir con/sin cambio de URL.

La vista previa se renderizó desde el mismo HTML con WeasyPrint y se revisó
visualmente en PNG. A 320 y 390 px no hay texto fuera del ancho disponible.
No es una captura de HTTP Custom: las diferencias de WebView todavía deben
comprobarse en el dispositivo.

El ZIP privado contiene:

- `F_spdecode_html.hc`, basado en D, ya aceptado por el propietario.
- `G_spdecode_html_owned.hc`, basado en su exportación propia, sustituyendo
  también el HTML personalizado anterior.
- Fragmentos ES/EN, strings JSON, páginas de vista previa, PNG y resultados.

**Estado:** la estructura anterior ya tiene importación correcta reportada por
el propietario. Los nuevos archivos con HTML pasan las comprobaciones locales;
su importación y diseño recibieron aceptación global del propietario. Los enlaces
no se reportaron individualmente. No se afirma que la nota elimine restricciones
de la configuración.
