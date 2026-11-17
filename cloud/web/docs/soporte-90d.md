# Expediente: servidor soporte — sesión 90 días + APIs P1

**Rama:** `server/soporte-90d` (base `b79fc51e572a`, local; sin push — la rama remota no existe).
**Fecha:** 2026-11-15. **Tipo:** solo servidor (`cloud/web`). Sin despliegue.
**Origen:** plan `~/workspace/support-tamara-plan/PLAN_SOPORTE_TAMARA.md` §1.4 y §6.1.
**Decisiones de Ghost Developer aplicadas:** sesión de 90 días para staff Y owner (en lugar de
endpoint de refresco); construir las APIs P1 que las apps consumen y no existían;
NO integrar polling/typing; adjuntos/capturas en otra fase.

## 1. Qué cambió

### 1.1 Sesión de 90 días (staff + owner)
- `lib/commerce/staff.mjs`: `TTL 3600 → 90*24*3600` (7.776.000 s).
- `lib/c6-admin-auth.mjs`: `TTL 1800 → 90*24*3600`.
- El TTL es la única fuente: cubre `Max-Age` de la cookie (`staffCookie` /
  `cookieHeader`), `EX` de Redis (`spdecode:staff:session:<jti>` /
  `spc6:admin:session:<jti>`), `exp` del claim y el límite de validación
  (`exp-iat > TTL` rechaza). No se tocó ningún otro TTL: la sesión de cliente
  Better Auth (90 días, `updateAge` 12 h) y los TTL de alertas/catálogo son
  independientes. Las sesiones existentes (1 h / 30 min) siguen validando
  (`exp-iat` menor que el nuevo TTL) y expiran por su propio `exp`; al
  re-loguear obtienen 90 días. Sin endpoint de refresco (decisión de Ghost Developer).

### 1.2 Migración `sql/010_support_reads_avatar.sql` (nueva)
- Tabla `spdecode_shop.support_thread_reads(thread_id, reader_kind, reader_id, read_at)`,
  PK `(thread_id, reader_kind, reader_id)`, FK a `support_threads` con
  `ON DELETE CASCADE`. `reader_id` es `text` (el id del owner es un digest
  hexadecimal de 64 caracteres, no UUID).
- `support_messages.agent_avatar text` (snapshot por mensaje, igual que
  `agent_name`/`agent_role`: el historial no cambia si el agente cambia de avatar).
- `staff_accounts.avatar text` (avatar del staff).
- Registrada en `scripts/commerce-migrate.mjs` (las dos listas) y en los
  `before()` de `tests/account-support-security.test.mjs`,
  `tests/staff-console.test.mjs` y `tests/account-notices.test.mjs`.

### 1.3 No leídos + marcar leído
- `lib/commerce/support.mjs`:
  - `readTimes()` (interna) y `markSupportThreadRead(threadId, reader, {db})`
    (nueva, exportada). Valida el hilo y el acceso: el usuario solo su propio
    hilo (si no, `SUPPORT_NOT_FOUND`); el staff solo hilos asignados a él salvo
    `canSeeAll` (capacidad `support.assign`), si no `SUPPORT_NOT_ASSIGNED`.
    Upsert de `read_at=now()`.
  - `listUserSupport()`: cada hilo lleva `unread` (mensajes `admin` posteriores
    a la última lectura del usuario) y la respuesta lleva `unreadTotal`.
  - `listAdminSupport()`: igual, contando mensajes `user` posteriores a la
    lectura del staff que consulta. Sin `principal` (solo tests) no hay lecturas
    y todo mensaje de usuario cuenta como no leído.
  - Solo campos aditivos; el resto del contrato no cambia.
- `lib/commerce/support-route.mjs`:
  - `POST /api/support` con `action:'read'` → marca leído el hilo del usuario.
  - `POST /api/admin/support` con `action:'read'` → marca leído (staff).
  - Permiso por acción en la ruta admin (antes todo POST exigía
    `support.write`): leer y marcar leído bastan con `support.read`;
    responder/cerrar/reabrir siguen exigiendo `support.write`; asignar sigue
    exigiendo `support.assign`. El CSRF (`validMutation`) se mantiene en todo POST.

### 1.4 `agent.avatar` en mensajes
- `lib/commerce/support.mjs`: `messageRow()` emite
  `agent:{name, role, avatar}` (`avatar` es `null` si no hay). Los SELECT de
  mensajes de `listUserSupport`/`listAdminSupport` incluyen `agent_avatar`.
  `replyAdminSupport()` acepta `operator.avatar` (opcional), lo valida con
  `avatarInput` (misma regla que el avatar de perfil de usuario: data-URI JPEG
  ≤ 85 KB, magic bytes JPEG) y lo guarda como snapshot en `agent_avatar`.
- `lib/commerce/profile.mjs`: `avatarInput` pasa a exportada (sin cambiar su regla).
- `lib/commerce/staff.mjs`: `getStaffAuth`/`listStaff` devuelven `avatar`;
  `safeStaff` lo incluye; `panelPrincipal` (owner) devuelve `avatar:null`;
  `updateStaff` acepta la clave `avatar` (undefined conserva, null borra,
  string válido sustituye; inválido → `INVALID_AVATAR`). `createStaff` no
  asigna avatar (se fija después con `updateStaff`).
- `lib/commerce/support-route.mjs`: el operador de la respuesta lleva
  `avatar:principal.avatar ?? null`.

## 2. Decisiones de diseño (documentadas)
- **Lecturas por actor (tabla) en lugar de columnas `read_at` en el hilo:**
  el usuario y cada staff tienen su propio estado; una columna única no
  distingue quién leyó.
- **Snapshot `agent_avatar` en el mensaje en lugar de derivarlo de
  `staff_accounts`:** coherente con `agent_name`/`agent_role` (snapshot) y
  cubre al owner, que no tiene fila en `staff_accounts`.
- **Formato data-URI JPEG ≤ 85 KB:** mismo patrón que `profiles.avatar_data`;
  sin hosting nuevo de ficheros; los clientes ya saben renderizar data-URI
  JPEG. El WebP de Tamara deberá convertirse a JPEG ≤ 85 KB al asignar el
  avatar (paso operativo del owner, no código).
- **Sin auto-marcado al responder/enviar:** solo el endpoint explícito marca
  leído; marcar al enviar borraría no leídos previos del remitente.

## 3. Qué NO se hizo (fuera de alcance)
Typing/polling, FCM al admin, adjuntos/capturas, plantillas, paginación,
Dashboard, webhook saliente, bot dedicado, unificar `permissions`/`capabilities`,
nombre visible del owner, cambios en apps (Admin/cliente aún no consumen
`unread` ni `agent.avatar`: eso es trabajo de apps, fuera de esta rama).
No se tocó el cifrado AES-256-GCM ni la auditoría de respuestas.

## 4. Verificación (aquí, sin Postgres vivo)
- `node --check` OK en los 6 módulos y 4 tests editados.
- Tests Node (PGlite, BD en memoria; la migración 010 se aplica en cada `before()`):
  - `tests/account-support-security.test.mjs`: 5/5 (incl. nuevo test de no
    leídos, marcar leído con ACL y snapshot de `agent.avatar`).
  - `tests/staff-console.test.mjs`: 7/7 (incl. `expiresIn` staff 90 días y
    avatar de staff válido/inválido/borrado).
  - `tests/c6-admin.test.mjs`: 15/15 (incl. nuevo test de sesión owner 90 días:
    `expiresIn`, `Max-Age=7776000` y `exp-iat` del claim).
  - `tests/account-notices.test.mjs`: 4/4.
  - Archivos que importan los módulos tocados (`commerce`, `c13`, `c14`,
    `c15`, `c6-analytics`, `gifts`, `mobile-admin`): 42 + 4 pass, 0 fail.
- `scripts/commerce-migrate.mjs` en seco NO se pudo ejecutar aquí: `getMigrations`
  exige Postgres vivo y no hay servidor (`ECONNREFUSED` a localhost:5432).
  Es una limitación del entorno, no del cambio (la lista nueva está en el
  script; la SQL 010 se verificó aplicándola en PGlite en los tests).
- Sin verificación contra producción (sin despliegue, por decisión de Ghost Developer).

## 5. Pendientes / decisiones para Ghost Developer
- Crear la rama remota `server/soporte-90d` desde `ci/unity-ads-online-qa` en
  la web de GitHub para poder subir (el conector no puede crearla desde otra
  base). Tras el push, esta rama deberá rebasarse: el remoto
  `ci/unity-ads-online-qa` ya avanzó más allá de `b79fc51e` (head remoto
  `26f07ec4` al 2026-11-15 ~16:12; `patch/20-apps` remoto en `bf16b394`).
- Confirmar en producción que la sesión de 90 días se sostiene (cookies +
  Redis) tras el despliegue.
- Asignar el avatar a la cuenta staff de Tamara (convertir su WebP a JPEG
  ≤ 85 KB y fijarlo con `updateStaff` como owner) cuando la cuenta exista.
- Las apps (Admin y cliente) deben consumir `unread`/`unreadTotal` y
  `agent.avatar` y llamar a los endpoints `read` al abrir un hilo.
