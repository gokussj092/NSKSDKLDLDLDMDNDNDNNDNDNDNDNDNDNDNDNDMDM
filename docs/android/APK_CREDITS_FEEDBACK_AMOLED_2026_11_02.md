# SP-DECODE — APK, Créditos y Errores/Sugerencias AMOLED (2026-11-02)

## Aprobación
Implementar la vista previa interactiva presentada en el chat. Cambios específicos: quitar «Uso previsto: 1 análisis APK = 1 crédito» de Créditos, y mantener «Detalles de la solicitud» oculto hasta que el usuario elija una categoría. La referencia visual es AMOLED negro con paneles grises.

## Pantalla APK
- Cabecera principal de SP-DECODE: sustituir acceso de Ajustes por «Créditos: 1+» únicamente en la pestaña APK. Es texto provisional, no consulta de saldo.
- «Análisis de APK»: «Importar APK» arriba y deshabilitado; centro: icono, «Próximamente» y descripción breve.
- Quitar tarjetas anteriores de proceso, suscripción, precios y advertencias extensas. No habilitar selector de archivos, análisis local ni subida de APK.
- El resto de pestañas conserva el acceso original a Ajustes.

## Créditos
- Pantalla separada, accesible desde la cabecera APK; regresar con botón y Android Back; cambiar pestaña cierra Créditos.
- Tarjeta «Próximamente» sin saldo real.
- Tarjetas de compra: 1 crédito y paquetes; ambos botones deshabilitados y marcados «Próximamente».
- Precios y suscripciones: «Próximamente», sin cifras monetarias.
- No mostrar «Uso previsto: 1 análisis APK = 1 crédito».
- No integrar facturación, compras, saldo persistente, nuevos endpoints ni backend de suscripción.

## Errores y sugerencias
- Tarjeta de categorías con iconos, subtítulos y resaltado monocromático al seleccionar.
- Estado inicial sin selección. La tarjeta «Detalles de la solicitud» aparece únicamente después de seleccionar nuevo método, reportar error o sugerir mejora.
- Método: URL + descripción. Error: lista existente de incidencias + descripción opcional. Mejora: descripción. Todas: campo adicional opcional.
- Mantener validaciones y envío existentes, sin enviar automáticamente. La información adicional se adjunta al texto del reporte, respetando el máximo existente de 2 000 caracteres y el mismo esquema API.
- Conservar navegación, errores, respuestas y estado mientras el usuario edita.

## Pruebas y recursos
- 14 recursos de idioma añadidos en ux_preview_strings.xml para inglés, español, árabe, alemán, persa, francés, hindi, indonesio, italiano, japonés, portugués BR, ruso, turco y vietnamita.
- Tests de contrato: tests/test_cloud_apk_feedback_ux.py.
- Tests Compose Cloud: ApkFeedbackUxInstrumentedTest.kt.
- C0 actualizado en docs/cloud/C0_UI_APPROVED_1_1_26.json; línea base histórica sin cambios.
- No incrementar versión 1.1.26 build 41, publicar APK, cambiar firma o fusionar main sin validación.

## Seguridad
Solo UI/UX. Sin modificaciones de descifradores C++ del servidor, HPKE, políticas Cloud, GitHub Secrets ni VPS.
