# F7-A6 — Selección continua, historial cifrado y eventos reales (2026-11-07)

Rama \`feat/nuevas-integraciones\`. Esta fase se implementó de manera coordinada
en Android y Cloud; no modifica el decodificador VPN, HPKE V2, ni los límites
de los módulos anteriores. No se realiza merge a \`main\` hasta validar CI.

## Android — visor compartido
- \`ContinuousJsonView.kt\`: selección nativa continua directamente en el
  visor, mediante pulsación prolongada y dos extremos arrastrables. El arrastre
  próximo al borde desplaza el documento sin paginarlo. Se mantiene búsqueda,
  coloreado, numeración de líneas, desplazamiento horizontal y zoom.
- \`LargeResultViewer.kt\`: copia arbitraria del rango seleccionado desde
  \`NativeResultEngine.Document.selectedText\` fuera del hilo principal. No
  vuelve a aparecer el diálogo de selección de un fragmento fijo.
- El visor sigue virtualizando líneas (hasta 150 en la región inicial), sin
  construir un \`Text\` Compose gigante. Para evitar \`TransactionTooLarge\`,
  la copia de más de 700.000 caracteres se rechaza explícitamente, recomendando
  exportación, nunca se copia un resultado truncado.
- \`mask=true\` mantiene las credenciales redactadas también durante copia,
  no solo durante renderizado.

## Análisis APK — informe, exportación e historial
- \`ApkQaAnalysisScreen.kt\`: botón **Exportar JSON** mediante el selector SAF
  \`CreateDocument("application/json")\`, en UTF-8, sin comentarios, bloques
  Markdown, números de línea ni paginación.
- \`ApkReportMarkdown.kt\`: se conserva el JSON original (sin convertirlo
  repetidamente con Gson), se muestran los artefactos adicionales que lleguen
  en el informe, cada uno con su formato y opción de copia.
- \`ApkQaHistoryStore.kt\`: índice cifrado y un registro cifrado por análisis,
  AES-256-GCM con clave no exportable AndroidKeyStore, archivos \`AtomicFile\`
  en \`noBackupFilesDir\`. La persistencia ocurre antes de poner el checkpoint
  de WorkManager en estado terminal. No guarda el APK, URI o token remoto.
  No hay limpieza automática de reportes: borrar es manual y confirmado.
  Las actualizaciones de la misma aplicación firmada conservan los datos.
- Historial visible en el apartado APK: abrir un resultado anterior, volver
  al actual, exportar y eliminar registros seleccionados. Un análisis activo
  sigue siendo único y se puede reconectar al reabrir la app.
- Informe fallido sin JSON: se conserva el estado, pero nunca se exporta un
  archivo .json vacío.

## Cloud — eventos verídicos de progreso
- \`qa_service.py\` publica las fases como \`RUNNING\`, \`DONE\`, \`PARTIAL\`
  o \`FAILED\`. Las marcas verdes solo aparecen cuando hay un evento terminal
  verificable de esa fase. La inspección avanzada desactivada o incompleta se
  presenta como parcial, nunca como descifrado completado.
- \`qa_tooling.py\` clasifica \`EXIT_ZERO\`, \`EXIT_NONZERO\`, \`TIMEOUT\`
  y \`START_FAILED\`; \`jadxAttempted\`, \`jadxExecuted\`,
  \`jadx.status\`, \`jadx.terminationReason\` y
  \`jadx.referenceScanStatus\` permiten distinguir un informe parcial de un
  decompilador terminado. No devuelve el código fuente, logs ni credenciales.
- Queda deshabilitado Ghidra en perfil JADX Lite, sin falsificar resultados.

## QA
- Python: \`tests.test_f7_apk_qa_service\`,
  \`tests.test_f7_apk_qa_android_resume\`,
  \`tests.test_f7_apk_qa_jadx_refs\` y demás suites F7.
- Android instrumentado:
  \`ApkQaHistoryAndSelectionInstrumentedTest.kt\` verifica selección de más
  de 1.000 líneas, protección de claves y persistencia cifrada.
- Pendientes hasta CI en verde: ejecutar \`assembleRelease\` firmado con
  keystore persistente, test real en dispositivo para el arrastre de ambos
  controles y autodesplazamiento; verificar una exportación de 1.300 y de
  8.000+ líneas, búsqueda/zoom, volver a abrir la app y recuperar informes
  antiguos. No se puede validar un comportamiento táctil desde GitHub Actions
  sin un emulador/dispositivo instrumentado.
- La APK beta ya instalada no recibe estos cambios hasta que se instale el
  nuevo artefacto release; el VPS necesita el despliegue del servicio QA.

## Actualización del VPS (solo después de CI backend satisfactoria)

\`\`\`bash
sudo spdecode update all feat/nuevas-integraciones
sudo spdecode apk-qa enable
sudo spdecode apk-qa enable-lite
sudo spdecode apk-qa status
\`\`\`

La opción \`enable-lite\` conserva límites de RAM del worker y no habilita
Ghidra ni soporte público/pagos. Mantener una sola APK/APKS activa y un máximo
de 100 MB por carga. Revisar uso real de RAM con
\`sudo docker stats --no-stream\`.
