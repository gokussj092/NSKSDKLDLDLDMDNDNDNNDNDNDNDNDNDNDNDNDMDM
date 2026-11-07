# SP-DECODE — F7-A1: identidad híbrida, correo del dominio y recuperación cifrada

**Estado:** fase iniciada; contratos y prototipos aislados, **no login público, no PostgreSQL en producción, no correos reales ni Supabase conectado**. Rama `feat/nuevas-integraciones`.

## Decisión actual del propietario y cambio de roadmap

Esta decisión **sustituye** la restricción anterior de F7-A1/A2 «solo Google, sin OTP ni email/password». SP-DECODE tendrá **dos métodos de entrada**: Google Sign-In y **correo electrónico verificado + contraseña**, con nombre de usuario único y nombre visible editable. Google y contraseña se vinculan voluntariamente a la **misma cuenta interna inmutable**, nunca solo por coincidencia del correo. La cuenta no se obliga a usar funciones VPN gratuitas, pero sí créditos/compras/análisis pagados. La administración C6 sigue siendo separada con MFA para operaciones sensibles.

El identificador de cuenta es `account_id` UUID: el correo puede cambiar mediante revalidación; el `username` es único (normalizado sin mayúsculas); las compras/saldos siempre referencian el ID inmutable.

## F7-A1 — Subfases revisadas

| Subfase | Implementación / aceptación | Estado |
|---|---|---|
| **A1-P01** | Normalización handle/correo/nombre, política contraseña, `scrypt` con sal única, OTP HMAC aleatorio 6 dígitos de 10 min, máximo 5 intentos, continuación de registro de un solo uso | Código y tests integrados; CI pendiente |
| **A1-P02** | PostgreSQL principal ACID: cuentas, identidad Google/contraseña, OTP de registro, sesiones revocables, eventos | Migración SQL **NO aplicada** y contrato de transacciones por validar |
| **A1-P03** | Registro `email + @username + nombre` → «Siguiente» → correo OTP → validación → contraseña → activar cuenta en una transacción; reservar username con concurrencia y no enumerar emails | Pendiente endpoints, mailer y pruebas DB |
| **A1-P04** | Acceder con Google o email/contraseña; recuperación contraseña con OTP/token breve, cambio seguro, avisos new login/device, inicio de sesión sospechoso; revocación de sesiones y MFA admin | Pendiente OAuth, sesiones, envío |
| **A1-P05** | Adaptador proveedor de correo: buzón de soporte, SMTP transaccional, SPF/DKIM/DMARC, bandeja del panel con sanitización | Pendiente definir proveedor, dominio y credenciales |
| **A1-P06** | Respaldo: snapshot PostgreSQL + `cloud.env` cifrados **antes** de salir del VPS, destino Supabase separado, restauración atestiguada | Cifrador offline + tests; sin proyecto conectado, uploader/cron pendiente |
| **A1-P07** | Integrar Android/Next.js UX, idioma, términos/privacidad, pruebas Play real y flujo end-to-end; habilitar solo al cumplir gates | Pendiente |

### Flujo de cuenta previsto

1. «Crear cuenta»: ingresar **nombre visible**, correo y **nombre de usuario único**. Comprobar formato y posible disponibilidad sin crear aún cuenta ni aceptar pagos.
2. «Verificar correo»: generar OTP criptográfico de **6 dígitos**; guardar solo HMAC asociado a destinatario+challenge; enviar desde cuenta transaccional autenticada. Válido 10 min, máximo 5 intentos, reenvío limitado. Nunca persistir OTP plano ni devolverlo en un API response.
3. «Crear contraseña»: después de verificar el OTP, otorgar continuación aleatoria de duración corta; solicitar contraseña segura y confirmar; almacenar **solo hash memory-hard con sal**, y crear cuenta+identidad+consentimientos+consumo del challenge en **una transacción PostgreSQL**. Si dos usuarios eligen el mismo handle, solo un insert gana; reintento guiado al segundo.
4. «Iniciar sesión»: Google (validar firmas y claims server-side) o correo verificado/contraseña; emitir sesión propia revocable con expiración y token hasheado. No usar correo o username como autorización de roles.
5. «Recuperar contraseña»: respuesta idéntica para correo existente/inexistente; desafío de un uso; pedir nueva contraseña solo tras verificación; rotar/revocar sesiones; aviso de seguridad. Avisos de nuevo dispositivo y cambio de credenciales no deben incluir contraseñas ni IP exacta.

**Implementado solo de forma aislada:** `cloud/web/lib/f7-account-identity.mjs`, `cloud/web/tests/f7-account-identity.test.mjs`, `cloud/accounts/sql/001_identity_schema.sql`. `accountPolicy.publicRegistrationEnabled=false`; no existe todavía una ruta de registro externa que admita credenciales; no modificar C6/admin ni V2/HPKE. La elección final de KDF podría pasar a Argon2id tras auditoría de biblioteca y dependencias; hoy scrypt usa parámetros fijos/versionados y no un SHA-256 rápido.

### Correo del dominio: Dynadot, Gmail y SMTP

- **Dynadot API** gestiona dominios/DNS, **no debe suponerse una API para leer la bandeja**. Su **email forwarding** permite reenviar correo entrante al buzón Gmail pero no enviar usando ese alias como servicio de correo. El **plan Pro Email** proporciona SMTP e IMAP; el plan gratuito de alojamiento de correo solo POP3 remoto (verificar plan contratado). Otra alternativa es SMTP transaccional especializado para códigos/avisos y dominio autenticado.
- Para mostrar recibidos en el panel, la opción sencilla con Dynadot Pro es **IMAP de servidor** sobre TLS con credencial propia de soporte y **sin exponerla al navegador**; otra posibilidad es **Gmail API readonly** autorizada exclusivamente sobre el buzón de soporte, que implica OAuth, scopes de lectura y posibles verificaciones de Google. No pedir acceso al correo personal de ningún usuario de SP-DECODE ni copiar su bandeja completa a Redis.
- Separar `no-reply@` o `security@` para códigos/alertas y `soporte@` para respuestas humanas (direcciones solo propuestas, **no se afirma que existan**). Acordar política de DMARC/SPF/DKIM, supresión/ rebotes y límites; **envíos deshabilitados** hasta validación.

Documentación del proveedor: https://www.dynadot.com/help/question/POP3-SMTP-settings y https://www.dynadot.com/help/question/set-email-alias . Gmail API: https://developers.google.com/workspace/gmail/api/guides/list-messages .

### Respaldos de VPS y credenciales: no almacenar .env descifrado

- Capa primaria: base PostgreSQL durable con volumen persistente + WAL/archivado y backups verificables. Redis actual de sesiones NO es la base de usuarios. `pg_dump` consistente y secretos `/etc/spdecode/cloud.env` son **artefactos separados**; jamás subir/copiar un `.env` legible a Supabase, correo, logs o repositorio.
- `scripts/backups/f7_offsite_envelope.py` genera pares X25519 en máquina **fuera del VPS** y permite cifrar en streaming con clave pública y AES-256-GCM. En el VPS solo estará **la pública**; la privada de recuperación debe guardarse offline, con copia independiente y custodia segura. Se verifica etiqueta GCM antes de publicar un restore. **Sin llave privada no se puede restaurar el respaldo.**
- Política propuesta: comprobar cambios cada **2 horas**, snapshot cifrado y subida después de comprobar integridad; si no cambió nada conservar heartbeat y último respaldo bueno. RPO de hasta 2 h si todos los jobs terminan correctamente; exigir alertas por fallos de subida y una restauración a entorno de pruebas regular. Retención sugerida: 24 snapshots de 2h, 14 diarios y 4 semanales, revisada conforme crezca tamaño/costo. Un backup no probado no se presume recuperable.
- Destino futuro: proyecto Supabase independiente, **bucket privado** `spdecode-vps-backups`, sin policy pública, service key solo en proceso de backup y credenciales de acceso mínimo. **Supabase no almacena la clave privada de recuperación**. Los respaldos cifrados de usuarios y los secretos deben estar segregados por prefijo/permiso. Los APK de soporte, si se admiten, irán a **otro bucket privado**, cifrados, con TTL, cuotas y autorización por caso/usuario.
- No usar la base Postgres de Supabase como repositorio de claves plaintext ni almacenar secretos `service_role` en APK/Next.js público. Claves rotadas, mínimo privilegio, recuperación documentada y copia secundaria offline o en otro proveedor. **Una sola nube no es redundancia absoluta.**
- **Free de Supabase**: riesgo de pausa por inactividad, almacenamiento 1 GB y archivo máximo 50 MB; las copias de bases grandes deben dividirse / usar carga resumible TUS, con pruebas de integridad y reensamblado. Antes de habilitar subida periódica confirmar cuenta/proyecto reales, cuotas, cifrado, tarifas y alertas. No crear/modificar proyecto en la cuenta Supabase actual del usuario.

Fuentes: https://supabase.com/docs/guides/storage/buckets/fundamentals ; https://supabase.com/docs/guides/storage/uploads/file-limits ; https://supabase.com/docs/guides/storage/uploads/resumable-uploads ; https://supabase.com/docs/guides/platform/free-project-pausing .

### Seguridad, privacidad y retención

- Restringir registration/login/reset con límites por email + IP + dispositivo, defensa contra abuso y enumeración, CAPTCHA cuando se habilite, colas separadas de correo y auditoría sin secretos.
- MFA obligatorio para operaciones administrativas críticas, nunca asignar `admin` por correo o Google `email` claim. Vincular cuenta Google/contraseña únicamente después de reautenticación y autorización explícita, sin cuentas fusionadas por error.
- Permitir exportación/eliminación de datos y cuentas, registrar consentimientos versionados, políticas de retención para identificadores/OTP/sesiones, facturas y APK; comunicar nuevas finalidades, respaldo internacional y proveedores antes de activar.
- Preparar política términos/privacidad bilingüe **antes** de registro real, sin alterar aún la página pública existente que refleja correctamente el servicio hoy. Revisión legal mexicana necesaria antes del lanzamiento.

## Validación y bloqueos actuales

- **No existen PostgreSQL persistente, rutas de registro, SMTP funcional, OAuth público verificado, sesiones de cuenta, copia enviada a Supabase ni backup restaurado desde otro host.**
- Suite CI separada: `.github/workflows/f7-a1-identity-backup.yml`; Node valida OTP, sal/costo, malformed, handles, continuación; Python valida cifrado por streaming, GCM, corrupción, clave equivocada y no sobrescribir snapshots. Deben aprobarse antes de declarar los primitivos validados.
- **La fase no está DONE ni el servicio de pago listo.** A2 perfiles; A3 ledger; A4 upload; A5 motor; A6 soporte humano; A7 Billing; A8 historial/refunds; A9 integración Android/beta.

## Intervenciones prohibidas en esta tanda

No aplicar migraciones de base de datos productivas, no crear cuentas ni acceder a bandejas personales, no activar login/envíos, no crear cuenta Supabase sin autorización, no recuperar ni copiar `.env` de VPS, no fusionar `main`, no cambiar decodificadores ni los 63 scripts originales. Branch Protection continúa apagada por decisión del propietario.
