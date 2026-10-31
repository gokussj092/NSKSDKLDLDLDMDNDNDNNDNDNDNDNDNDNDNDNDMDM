# SP-DECODE — Panel modular y retiro automático de API V1

Fecha de preparación: 2026-10-31. Rama de desarrollo: `feat/cloud-selector-private-card-notification-chime`.

## Objetivo y limitaciones

Se prepara una actualización del panel web del VPS con un menú hamburguesa a la izquierda, navegación AMOLED adaptable y **17 páginas independientes**: resumen, analítica, incidencias, diagnóstico, estado del servidor, mantenimiento, API V1, API V2, Google Play, proveedores, exportaciones, catálogo, notificaciones, observabilidad, alertas, rendimiento P95 y documentación.

**No se ejecuta GitHub Actions para este trabajo. No se despliega al VPS ni se fusiona `main` desde la preparación.** El repositorio privado puede carecer de créditos de Actions, por lo que cualquier error de build deberá diagnosticarse mediante pruebas locales o una compilación autorizada que no sature el repositorio.

## Desactivación automática de API V1 en 48 horas

1. Desde `/admin/api-v1`, un administrador autenticado pulsa **Programar cierre en 48 horas** y confirma el aviso.
2. `POST /api/admin/v1-retirement` requiere la sesión firmada, control CSRF, límite de solicitudes, coincidencia de revisión y una confirmación literal `API_V1_PROGRAMAR_48H`.
3. El servidor guarda atómicamente `retireAt = Date.now() + 172800000` en `/app/provider-control/v1-protection.json` (sustentado por el volumen de configuración existente). Se utiliza el mismo lock interproceso, y el esquema persistente pasa a `version:3` solo cuando hay una fecha activa.
4. `v1PolicyStatus()` evalúa la fecha en **cada lectura**. Después de `retireAt`, `apiEnabled=false` aunque el valor previo permanezca almacenado. `v1Gate` rechaza rutas `/api/v1/*` con HTTP 410 y el control interno de Nginx rechaza la ruta con 403. Esto funciona sin cron, sin cola y sin GitHub Actions.
5. `POST /api/admin/v1-retirement` con `action:"cancel"`, confirmación `API_V1_CANCELAR_PROGRAMACION` y la revisión vigente elimina la fecha. **Cancelar no habilita una API apagada manualmente**. Se registra un evento administrativo agregado en Redis.
6. API V2 (`/api/v2/transport` y demás endpoints independientes), panel administrativo, web y worker mantienen sus políticas. No se modifica HPKE, Play Integrity ni catálogos.
7. El panel muestra la fecha exacta y el tiempo restante. La cuenta comienza **al confirmar la acción en el panel ya desplegado**, no al hacer commit. No se programa una fecha con anterioridad al despliegue.

### Procedimiento de activación de producción

**Precondiciones:** contar con copia de seguridad del VPS, Docker/Nginx verificados y el código revisado. La programación no está activada en producción por estar presente en GitHub.

- Antes de desplegar: ejecutar `cd cloud/web && node --test tests/v1-retirement-policy.test.mjs tests/v1-policy-admin.test.mjs tests/admin-sidebar-navigation.test.mjs tests/c6-analytics.test.mjs`.
- Ejecutar el resto de `npm test` y `npm run build` en un entorno local con dependencias instaladas, sin habilitar workflows privados.
- Respaldar configuración/archivo persistente, consultar el estado de V1 y V2 y confirmar que V2 sigue funcionando.
- Desplegar únicamente el servicio web/API aprobado (sin cambiar worker, claves HPKE, APK/AAB ni Nginx, salvo que se detecte una configuración previa incompatible).
- Confirmar que todas las rutas `/admin/*` responden con la sesión de administrador y que no están expuestas al sitio público.
- En `/admin/api-v1`, pulsar **Programar cierre en 48 horas**. Guardar internamente `retireAt` y verificar el estado administrativo inmediatamente después. No imprimir cookies, secretos ni perfiles de usuarios.
- Antes del cierre, verificar que API V1 responde como hasta ahora y que API V2 permanece estable. Tras el corte, V1 debe devolver HTTP 410/403 y V2 seguir operativa.
- Si algo falla, **cancelar la programación** antes del plazo o restaurar el servicio a partir del respaldo verificado.

### Relación con el aviso publicado

La novedad editorial en 14 idiomas se preparó anteriormente para V1 (`whats-new-v1.json`, publicación 6) y describe la actualización 1.1.25 por Telegram y las pruebas de Google Play pendientes. **Enviar un anuncio no equivale a ejecutar el cierre técnico**. Esta programación en el panel es la acción que crea el corte efectivo.

## Notificaciones: página independiente

`/admin/notifications` incluye plantillas de redacción, título de 80 caracteres, cuerpo de 500, contadores, vista previa en Android, validación de FCM en modo sin envío, confirmación antes de publicar e historial del feed (títulos, cuerpos y caducidad). Se utiliza la API administrativa existente; no se añaden endpoints públicos ni se afirma entrega garantizada. Los avisos siguen caducando a los siete días.

## Seguridad y navegación

- Solo rutas bajo `/admin`, que ya está restringido al dominio del panel por Nginx.
- Todas las acciones mutantes existentes conservan sus comprobaciones de sesión, CSRF, rate limit y confirmación.
- Menú lateral con estados seleccionados, botón hamburguesa, `Escape` para cerrar, foco visible y capa de cierre en móvil; tema negro AMOLED y páginas independientes.
- No hay scripts dinámicos, seguimiento externo ni publicación automática del repositorio.
- El interruptor V1 antiguo sigue disponible; su estado efectivo después de `retireAt` está subordinado al cierre programado.
- `main` y producción quedan intactos hasta una operación de despliegue explícita.

## Pruebas relevantes

`cloud/web/tests/v1-retirement-policy.test.mjs` cubre fecha exacta, persistencia, retiro tras 49 horas simuladas, gate V1 en todos los métodos HTTP, Nginx, independencia de V2, conflictos y cancelación. `cloud/web/tests/v1-policy-admin.test.mjs` cubre sesión, CSRF, esquema de solicitud y revisiones. `cloud/web/tests/admin-sidebar-navigation.test.mjs` verifica los 17 destinos y el editor de notificaciones. Estas pruebas **se incluyen como código**; no deben describirse como ejecutadas hasta contar con sus resultados reales.
