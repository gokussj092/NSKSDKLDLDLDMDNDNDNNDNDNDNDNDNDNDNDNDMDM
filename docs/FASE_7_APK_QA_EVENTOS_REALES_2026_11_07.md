# F7 — Eventos reales de actividad del análisis APK/APKS (2026-11-07)

**Rama:** `feat/nuevas-integraciones` · **Estado:** código integrado, sin certificación Android/VPS E2E; no desplegado en producción.

## Contrato de actividad

El servicio privado de QA registra en `state.json` una lista ordenada `events`, que solo entrega a la aplicación tras autenticación, atestación y transporte HPKE V2 existentes. Cada entrada es `{sequence, code, status, at}` y tiene únicamente identificador numérico, código de fase permitido, estado `RUNNING|DONE|FAILED` y hora Unix. No envía nombres de herramientas, rutas de scripts, claves, técnicas, trazas, código fuente o algoritmos.

| Código público | Situación que realmente ocurrió |
| --- | --- |
| `UPLOAD_STARTED` | Se aceptó el inicio del envío |
| `UPLOAD_RECEIVED` | Se verificó SHA-256 del archivo completo y se entregó al proceso |
| `UPLOAD_REJECTED` | Falló la verificación del SHA-256 completo |
| `PACKAGE_VALIDATION` | Inició la validación del contenedor |
| `PACKAGE_VALIDATED` | `inspect_input` finalizó sin error |
| `COMPONENT_INSPECTION` | Comenzó la inspección del inventario estático |
| `COMPONENTS_INSPECTED` | Finalizó la inspección del inventario |
| `REPORT_PREPARATION` | Se inició la persistencia del informe |
| `REPORT_READY` | El informe se guardó y el trabajo se marcó completado |
| `ANALYSIS_FAILED` | El inspeccionador lanzó un error, con reporte genérico |

`DONE` no equivale a descifrado exitoso de una VPN, ni a decompilación, ni a ingeniería inversa de métodos de tercero. El resultado de esta etapa sigue siendo `COMPLETED_PRELIMINARY` si termina correctamente. No se anuncian métodos alternativos ni "segundo intento" porque el analizador QA **aún no ejecuta tales alternativas**. Cuando un orquestador real se añada, los reintentos se mostrarán solo si un evento verificable confirma el fallo anterior y el nuevo trabajo; nunca revelar su técnica interna.

## Cambios integrados

- Backend: `cloud/apk_analysis/qa_service.py` agrega eventos **en disco** con secuencia estable y los devuelve desde `result`; `qa_static.py` anuncia progreso únicamente cuando pasa cada punto observable. Se conservan aislamiento y autorización originales.
- Android: `CloudApkQaClient` valida los códigos admitidos y los entrega a `MainActivity` para mostrarlos en `ApkQaAnalysisScreen`, con estilo AMOLED y textos de actividad para los 14 idiomas. El progreso de bytes es determinate durante subida e indeterminado cuando el servidor procesa. Polling V2 cada 12 s después del envío para respetar límites de frecuencia.
- Límite **exclusivo** de QA APK/APKS: `100_000_000` bytes (100 MB decimales), idéntico en cliente y servicio; las restricciones de decodificación existentes no se modifican. XAPK y ZIP directos continúan deshabilitados.
- La suite `tests/test_f7_apk_qa_service.py` añade cobertura de secuencia, etapas observadas, ausencia de información interna y rechazo de 100 MB + 1 byte.

## Pendientes bloqueantes para pruebas reales del propietario

1. **CI**: confirmar PASS real de `F7 APK QA First-Pass Real Integration`, validación general y compilación Android JNI; no inferir funcionamiento por el simple hecho de que el repositorio sea público o aparezcan runs en cola.
2. **Continuidad Android**: la sesión del analizador sigue siendo volátil en `MainActivity`. Salir de la Activity/cerrar el proceso interrumpe el coroutine/polling; **no hay recuperación de uploadToken/jobId ni del avance del envío tras reiniciar**. Diseñar almacenamiento cifrado por Keystore, reanudación autorizada y servicio/WorkManager según restricciones de Android, sin guardar tokens en SharedPreferences legibles.
3. **Durabilidad servidor**: hoy usa hilo daemon y estado temporal; reiniciar el servicio durante `PROCESSING` puede dejar la tarea sin terminar. Crear cola duradera/reconciliación y cancelación remota antes de declarar background real.
4. **Análisis profundo**: JADX, ELF, métodos, selección de estrategia/reintentos y herramientas originales no están conectados al QA estático. No reportar esas etapas hasta ejecutarlas verdaderamente.
5. **Seguridad y despliegue**: validar cifrado de APK en reposo, recursos, permisos/volúmenes, TTL, archivos autorizados y smoke test firmado Android→VPS→resultado. Ya no hay inscripción manual de dispositivos; la sesión V2 verificada vincula los trabajos automáticamente. No habilitar acceso público ni exponer el servicio QA.
6. **Historial**: almacenar informes completos de manera cifrada con retención y exportación definidas, no solo conservarlos 12 horas en el servicio temporal.

**Entrega actual:** primer incremento de eventos verificables, pantalla y límite. **NO** equivale a APK compilada, servidor desplegado, prueba de dispositivo físico o sistema comercial finalizado.
