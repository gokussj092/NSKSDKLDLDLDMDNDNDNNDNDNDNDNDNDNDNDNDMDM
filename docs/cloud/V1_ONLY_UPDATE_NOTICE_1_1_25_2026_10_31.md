# SP-DECODE — Comunicado exclusivo API V1 (1.1.25)

Fecha editorial: **2026-10-31**. Rama de implementación: `feat/cloud-selector-private-card-notification-chime`.

## Contenido y alcance

- Solo **API V1**: publicación editorial **6** en `cloud/web/content/whats-new-v1.json`.
- Idiomas completos: `en, es, ar, fa, fr, id, ru, de, pt-BR, tr, vi, hi, ja, it`.
- Los tres elementos comunican: (1) actualización necesaria a SP-DECODE **1.1.25** (publicada en el canal oficial `https://t.me/GhostDeve`) y descontinuación **programada**, aún no ejecutada, de versiones antiguas en 48 h; (2) lanzamiento **todavía pendiente** para testers en Google Play, sin afirmar disponibilidad; (3) invitación a contactar a Ghost Developer por Telegram para solicitar acceso como tester.
- No se introdujo URL de mensaje específica porque aún no se dispone del identificador del nuevo mensaje de Telegram, y no se inventa un enlace personal para mensajes directos.
- Este contenido **no activa ni cronometra** ningún bloqueo de versiones ni publica en Google Play; solo muestra el aviso.
- API V2 conserva la publicación editorial **5** de `cloud/web/content/whats-new.json` y el override `CLOUD_WHATS_NEW_JSON` existentes.

## Separación real de API V1 / V2

**No basta con cambiar** `/api/v1/whats-new`: el transporte autenticado `/api/v2/transport` también invoca internamente ese mismo handler como operación **14**.

La nueva selección en `cloud/web/lib/whats-new.mjs` usa `boundRequestClaims(request)`, proporcionado exclusivamente por `cloud/web/lib/v2-transport.mjs` después de verificar su sesión y prueba criptográfica; el contexto se guarda en un `WeakMap` ligado al objeto `Request`, nunca en encabezados enviados por el cliente.

- **V1 directo sin contexto V2 validado**: `loadV1News()` → editorial 6, mensaje 1.1.25.
- **V2 autenticado (op 14)**: `loadNews()` → editorial 5, sin mensaje 1.1.25.
- Un supuesto `X-API-Version: v2` o encabezado similar no puede seleccionar una publicación distinta.
- `CLOUD_WHATS_NEW_V1_JSON` es un override opcional **únicamente de V1**. `CLOUD_WHATS_NEW_JSON` permanece exclusivo de V2. El Compose mantiene ambas entradas separadas.
- V2 puede seguir retornando `apiVersion:"v1"` en el cuerpo interior por compatibilidad del manejador histórico; esta cadena **no identifica** el transporte V2. La clasificación usa el contexto enlazado.

## Publicación en VPS

Un commit en GitHub **no** actualiza el servidor. Para que los usuarios reciban el aviso:

1. Revisar el diff y validar `cd cloud/web && node --test tests/whats-new.test.mjs` y, preferentemente, `npm test` y `npm run build`.
2. En el VPS, comprobar la rama, respaldar configuración y confirmar que `CLOUD_WHATS_NEW_V1_JSON` no tenga un override obsoleto (no imprimir valores privados). **No tocar** `CLOUD_WHATS_NEW_JSON` de V2.
3. Desplegar **solo** el servicio web/API, manteniendo claves HPKE, Redis, workers y los ficheros privados de configuración sin cambios. Seguir `docs/HPKE_VPS_DEPLOYMENT_SAFETY_RUNBOOK_2026_10_30.md` y el runbook de actualización del VPS.
4. En API V1 disponible, comprobar `POST /api/v1/whats-new` con `{"knownVersion":5,"locale":"es"}` → versión editorial 6 y tres filas; con `knownVersion:6` → `unchanged:true`. Probar los 14 idiomas.
5. Comprobar el camino **real autenticado V2, operación 14** con un dispositivo de prueba: conserva editorial 5 y no contiene los IDs `update-1125-v1` ni `join-play-testers-v1`. No enviar credenciales ni tokens a la salida del diagnóstico.
6. Aplicar rollback de web únicamente si aparece regresión; restaurar snapshot de claves y política HPKE sin reemplazarlas.

### Alcance de la entrega

Esta rama contiene el código y contenido editorial; no se ha declarado activación en producción sin ejecutar y comprobar el despliegue del VPS. Una **novedad en la app** no es una notificación push del sistema; Android la solicita tras consentir conexión y cuando se abre/reanuda, con almacenamiento cifrado y versión editorial vista.
