# Visor JSON completo y continuo — 2026-11-05

## Comportamiento

Sustituye el árbol plegable y las páginas de resultados de `JsonTreeViewer` / `LargeResultViewer` por una única superficie de código, tanto para resultados pequeños como grandes.

- Todos los objetos y arrays están desplegados desde el inicio.
- Desplazamiento vertical continuo hasta la última llave o corchete.
- Las líneas largas se recorren horizontalmente; no hay elipsis, resúmenes ni diálogos por valor.
- Números consecutivos desde 1. Número y código comparten exactamente la misma coordenada de línea base y desplazamiento vertical.
- Se conservan colores de sintaxis, controles Copiar / Exportar, cabecera y privacidad.
- El JSON recibido mantiene orden, claves repetidas y valores completos. Las cadenas con JSON escapado se muestran como cadenas completas del JSON original; no requieren expansión.
- El texto de decodificadores antiguos sigue pasando por `ResultJsonDisplay.render` para presentarse como JSON.

## Implementación

`result_engine.cpp` crea un índice iterativo de líneas lógicas sobre los nodos existentes. El índice referencia la fuente original; no construye un DOM Gson ni una copia completa con formato para los JSON directos. Un índice de posiciones cada 128 caracteres permite buscar dentro de valores largos sin recorrerlos desde el principio.

`NativeResultEngine.Document.lineCount`, `columnCount` y `lineWindow` permiten consultar cualquier línea y columna. La ventana JNI es un detalle del dibujo del área visible: no hay paginación en la interfaz ni límites de longitud de valor añadidos. Se conserva la transferencia JNI acotada, UTF-8 válido y pares sustitutos completos.

`ContinuousJsonView` dibuja únicamente las filas y columnas visibles, con caché de 96 ventanas. La columna de números permanece fija horizontalmente. Un `OverScroller` permite desplazamiento táctil; accesibilidad expone el texto visible y acciones para recorrer ambos ejes. Copiar y exportar siguen usando sus rutas existentes de contenido completo.

Al cambiar privacidad se sustituye la vista y su caché. Las credenciales y valores sensibles heredados se enmascaran en el motor antes de cruzar JNI. La propiedad del documento y su cierre pertenecen al ciclo de vida de Compose.

Se mantienen las protecciones previas del motor: 32 MiB de fuente, 200,000 nodos, profundidad 200 y límites de documentos simultáneos. Una entrada que exceda el presupuesto falla explícitamente; nunca se muestra un resultado parcial como si estuviera completo.

## Validación reproducible

```bash
python3 scripts/qa/continuous_json_viewer.py \
  --jni-include "$JAVA_HOME/include" \
  --cache /tmp/spdecode-viewer-kotlin \
  --report /tmp/spdecode-continuous-json-host-qa.json
```

Cobertura sintética:

- Pruebas existentes de índice, exportación original, entradas inválidas y fuzz.
- ASan/UBSan para índice de líneas y acceso aleatorio.
- Documentos de 8,000 / 20,000 / 50,000 registros; verificación del último registro y cierre.
- Clave de 3,500 caracteres, valor de más de 200 KB, Unicode en límites de ventana y profundidad 200.
- Claves repetidas, contenedores vacíos, comas, orden y enmascaramiento heredado.
- JNI real en OpenJDK: conteos completos, última línea, 100 cambios de privacidad y exportación idéntica.
- Sintaxis Kotlin y compilación del wrapper JNI de producción.

Validación local adicional: `ContinuousJsonView` y `NativeResultEngine` compilan contra el `android.jar` oficial API 36. La plataforma se obtuvo de `platform-36_r02.zip`, verificada con el checksum publicado en el repositorio Android SDK.

El workflow `json-continuous-viewer.yml` repite la validación host y ejecuta en emulador API 35 las clases `JsonTreeViewerInstrumentedTest`, `SingleResultViewInstrumentedTest` y `LargeResultEngineInstrumentedTest`. Cubre vista real, desplazamiento, última línea, valor largo, números, privacidad y acciones de la tarjeta. Su resultado debe consultarse en la ejecución del commit; agregar los tests no equivale a haberlos ejecutado satisfactoriamente.

No se cambian métodos de proveedores, endpoints, versiones, firma ni publicación en Google Play.
