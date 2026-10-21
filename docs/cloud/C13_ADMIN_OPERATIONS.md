# C13 — Diagnóstico operativo del panel (Cloud)

## Objetivo

El panel administrativo diferencia **éxitos**, **errores reales**, **advertencias de compatibilidad** y **solicitudes sin descifrado**. Las métricas son exclusivamente agregados técnicos anónimos con retención de 8 días. Nunca se guardan contenido de archivos, nombres originales, payloads, URL remotas, contraseñas, HWID, tokens, IP ni texto de respuestas de proveedores.

## Reinicio selectivo de errores

La pantalla **Informes / Analítica** incluye «Reiniciar todos los errores» y «Reiniciar errores» por extensión o proveedor VPN. El controlador autenticado `POST /api/admin/errors/reset` exige sesión administrativa, validación de mismo origen/CSRF y cuerpos JSON estrictos: `{"scope":"all"}` o `{"scope":"format","format":"vpn-mkk-hyper"}` (identificador sanitizado). No se admite ninguna clave Redis arbitraria. Los cambios **no afectan** datos de éxito, advertencias, volumen histórico, disponibilidad del servicio, catálogos, ni registros de instalaciones.

Los reinicios guardan una **línea base por formato y día UTC** en Redis `spc6:error-baselines` (TTL 8 días) y ocultan únicamente los errores previos al reinicio en los indicadores y en la lista visible de incidencias. Los agregados históricos originales siguen existiendo hasta su caducidad habitual; no se elimina el historial físico ni se borran evidencias técnicas. Los errores NUEVOS del mismo formato vuelven a contabilizarse de inmediato. Reiniciar un proveedor VPN no cambia los errores de otro proveedor. Las cifras totales de uso (`format:*:attempts`) se conservan sin modificaciones. Los errores se recalculan a partir de `format:*:failed` y `formatError:*:CODE` descontando la línea base, evitando que reaparezcan en los resúmenes generales.

La gráfica horaria de 48 horas representa el **histórico bruto**, por lo que todavía puede incluir errores anteriores a un reinicio. No se utiliza como referencia para decidir si una corrección todavía falla: se comprueban los indicadores de «errores nuevos» y las incidencias posteriores al reinicio. Se evita borrar datos horarios agregados que no se pueden reconstruir separando productos retroactivamente.

## Semántica de eventos

- **Correcto**: el motor devuelve un descifrado exitoso; se suma a uso/éxitos.
- **Error real**: respuesta fallida operativa o error del motor; aparece con código saneado, servicio y extensión/proveedor (sin metadatos personales).
- **Advertencia**: `UNSUPPORTED_FORMAT`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_CONFIG_VERSION`; en NPVS, también `DECODE_FAILED`, pues puede tratarse de una configuración no compatible. Esto NO confirma por sí solo que exista una versión más reciente: es una hipótesis para revisión. Las advertencias conservan una señal diagnóstica independiente, sin incrementar los errores reales.
- **Sin operación**: `PASSWORD_REQUIRED`, `HWID_REQUIRED`, `HWID_PASSWORD_REQUIRED`, `USER_CONSENT_REQUIRED`, `USER_CANCELLED`, `CANCELLED`. Ninguna cuenta como descifrado, éxito ni error. La UI Android que muestra un diálogo de contraseña/HWID no informa al servidor si después el usuario pulsa Cancelar: sin una señal adicional el backend solo reconoce que solicitó datos faltantes. Por privacidad no se envía una señal de cancelación.

No se cambia el código HTTP ni las respuestas que recibe la app, el decodificador ni el flujo de credenciales: la clasificación afecta al diagnóstico del panel.

## Gráficas y lecturas

- Historial por día (UTC), carga por hora 48 h (bruta), operaciones por servicio.
- **Top 10** de extensiones de archivos solicitadas, y **Top 10** de proveedores/catálogos Server VPN, ordenados por uso histórico agregado.
- **Top 10** códigos de error activos y advertencias de compatibilidad, con conteos sin PII.
- Tablas con correctos, errores desde reinicio, advertencias, usos totales y botón selectivo por formato.
- Diagnóstico muestra la severidad `error` o `warning` y oculta incidencias anteriores al reinicio del formato.

## Despliegue y QA

Esta modificación solo afecta a la API/panel Cloud; no requiere nueva versión Android, AAB, catálogo ni keystore. **No desplegar automáticamente**, ni fusionar el PR #96. Ejecutar el conjunto `cloud/web/tests/c13-operator-analytics.test.mjs` y los tests C6/C9 y de UI del panel. Probar en panel con administrador de pruebas, provocar error controlado, reiniciar el producto, verificar que el nuevo error posterior reaparece y que los éxitos siguen intactos.

## Pendiente — .rt

NO se elimina ni altera la imagen del resultado `.rt` sin un ejemplo concreto de la respuesta proporcionado por el propietario. Esta tarea queda pendiente de identificación del campo exacto y prueba de no regresión.

**Reset global e incidencias manuales:** se guarda también una marca temporal global `@all` para excluir reportes manuales previos que aún no tengan un contador por extensión. Las advertencias siempre se conservan. El número máximo de etiquetas saneadas por operación es 512.
