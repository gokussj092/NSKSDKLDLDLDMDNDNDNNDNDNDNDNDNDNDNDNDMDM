# SP-DECODE — Novedad 1.1.25 exclusiva para API V1

Fecha de edición: 2026-10-31. Rama: `feat/cloud-selector-private-card-notification-chime`.

## Objetivo

Notificar a clientes que consultan API V1 sobre la versión Android **1.1.25**. La APK ya fue difundida en el canal oficial `https://t.me/GhostDeve`; la versión de Google Play para testers está pendiente. Los interesados pueden escribir directamente al desarrollador en `https://t.me/Gh0stDeveloper` para informarse sobre la inscripción.

El contenido anuncia que el soporte de versiones anteriores está programado para retirarse en el plazo de **48 horas**. Este **mensaje no implementa ni confirma por sí solo** la política de bloqueo técnico: dicha política debe configurarse y verificarse independientemente en el servidor.

## Separación entre V1 y V2

- Archivo V1: `cloud/web/content/whats-new-v1.json`; publicación editorial **v6**, schemaVersion 1, fecha 2026-10-31.
- Archivo V2: `cloud/web/content/whats-new.json`; permanece en **v5**. No se modifica su catálogo ni se envía el comunicado de migración de V1.
- La función `whatsNewRequest` selecciona el contenido según `boundRequestClaims(request)`, un contexto en memoria asociado por `v2-transport.mjs` **después de autenticar la sesión V2**. El usuario no puede activar el camino V2 con cabeceras inventadas.
- Los overrides son independientes: `CLOUD_WHATS_NEW_V1_JSON` solo afecta V1 y `CLOUD_WHATS_NEW_JSON` sigue afectando V2. Un override V1 antiguo puede ocultar la publicación v6 en el VPS.

## Traducciones y contrato

Se incluyen traducciones para los 14 idiomas: `en,es,ar,fa,fr,id,ru,de,pt-BR,tr,vi,hi,ja,it`. Los tres ítems tratan de (1) actualización obligatoria, (2) descarga de Telegram y publicación de Google Play aún pendiente, y (3) invitación a testers y contacto privado.

Se conservan los límites de texto, el máximo de 12 ítems, la carga editorial de 16 KiB y el comportamiento de caché: cada versión se muestra como novedad en la aplicación una sola vez tras una consulta y consentimiento. **No se envía como notificación push del sistema**; la aplicación debe conectarse y consultar las novedades.

## Verificación y publicación al VPS

1. Desde el checkout: `cd cloud/web && node --test tests/whats-new.test.mjs` y `npm test`.
2. Respaldar la configuración actual del VPS y comprobar si `CLOUD_WHATS_NEW_V1_JSON` está definida, **sin imprimir valores privados**. Mantener intacta `CLOUD_WHATS_NEW_JSON` del canal V2.
3. Desplegar solamente el servicio web/API desde una revisión aprobada, sin reescribir el worker, catálogo Server VPN ni rutas V2. No se necesita otra APK para este aviso.
4. Solicitar `POST /api/v1/whats-new` con `{"knownVersion":5,"locale":"es"}`: esperar versión 6 y los tres ítems; luego con `knownVersion:6` esperar `unchanged:true`. Repetir en los 14 idiomas.
5. Probar la operación 14 del transporte V2 **con una sesión V2 real y válida**. Debe devolver la publicación 5 sin aviso de 1.1.25. No reemplazar una prueba de sesión por un simple header.
6. Validar por separado los controles de compatibilidad y el plazo de desactivación de versiones anteriores.

**Estado:** configuración editorial y pruebas del repositorio preparadas; despliegue al VPS y comprobación de respuesta pública pendientes.
