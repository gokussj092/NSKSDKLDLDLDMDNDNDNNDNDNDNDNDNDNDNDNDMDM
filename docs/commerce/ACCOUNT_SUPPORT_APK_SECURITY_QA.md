# SP-DECODE QA — Soporte cifrado, eliminación de cuenta y créditos APK

Rama: `ci/unity-ads-online-qa`. Se mantienen Android 1.1.27 (42), la misma firma persistente, la tienda y la arquitectura de descifrado C++/HPKE.

## Soporte en línea

- La aplicación presenta **Soporte técnico** y **Reportar un error** como pantallas completas y conversaciones con respuestas. No son formularios simulados.
- Los usuarios requieren una sesión comercial válida y solo pueden acceder a sus hilos. El panel `/admin/support` requiere autenticación administrativa y protección CSRF en mutaciones. Cada mensaje tiene autor, fecha, contenido e historial; el estado puede ser abierto, respondido o cerrado.
- Las solicitudes de soporte usan HTTPS con token de sesión Better Auth cifrado en Android Keystore. El backend cifra cada mensaje **antes de persistirlo** con AES-256-GCM, nonce aleatorio y AAD ligado a hilo, mensaje y autor.
- El cifrado en reposo requiere `SPDECODE_SUPPORT_ENCRYPTION_KEY` como una cadena hexadecimal de **64 caracteres generada aleatoriamente**, exclusiva del servidor. Mantenerla fuera del repositorio, respaldarla en el gestor de secretos y no rotarla sin plan de migración de mensajes. Si falta, soporte devuelve 503 sin guardar texto plano.
- **No es cifrado de extremo a extremo**: el personal de soporte autenticado necesita ver y contestar las conversaciones. Se recomiendan control de accesos, auditoría y un plazo de retención configurable en una iteración futura.
- Protección ante abusos: límite de 20 mensajes en 15 minutos por cuenta, 10 hilos activos, 4 KiB de texto por mensaje, validación de categorías, límites de historial, sin envío de archivos adjuntos ejecutables.
- El menú hamburguesa ya no incluye «Editar perfil». Esa función sigue en el perfil.

## Eliminación de cuenta

- Flujo separado en `Mi cuenta -> Eliminar cuenta`; exige confirmación expresa y una verificación adicional.
- Contraseña: Better Auth vuelve a verificar la contraseña en el servidor.
- Huella o PIN Android 11+: la clave P-256 privada se genera dentro de Android Keystore con autenticación local obligatoria. Se registra la clave pública en el servidor tras una sesión reciente. El servidor emite un desafío de corta duración, de un solo uso y ligado a la cuenta; exige firma ECDSA validada. **No se envía al servidor huella, patrón ni PIN.**
- Google: inicia de nuevo mediante Credential Manager y requiere una sesión reciente para confirmar la eliminación.
- Se revocan licencias y accesos, se borran datos personales de perfil, mensajes de soporte y credenciales; los movimientos contables sin datos personales se conservan solo cuando la normativa lo permite.
- Los tokens comerciales y API no son aceptados como prueba de propiedad de la cuenta.

## Inicio de sesión rápido

- Cuando la sesión comercial todavía es válida y el usuario activó la protección del dispositivo, la pantalla de correo muestra acceso rápido con huella/PIN. Se valida de nuevo la sesión en el servidor antes de mostrar datos.
- **Esto no crea una sesión sin credenciales**: si el usuario cerró sesión explícitamente o el token expiró, es obligatorio iniciar sesión con correo/contraseña o Google. No se almacena la contraseña ni se elude un cierre de sesión.
- Una futura autenticación sin contraseña tras cierre explícito requiere implementar y auditar passkeys/WebAuthn con credenciales registradas, no simularla mediante un resultado local de BiometricPrompt.

## Análisis de APK y créditos comerciales

- La pasarela V2 conserva HPKE, PoP, verificaciones de integridad y vinculación de dispositivo. Además **exige una sesión real de Better Auth** que se envía en el cuerpo de la petición HPKE y se comprueba en el backend.
- La cuenta debe existir en `shop_user` y poseer al menos un crédito disponible en el mismo modo de facturación (QA o producción). Los créditos solo se gestionan en PostgreSQL; las cifras del cliente no se aceptan.
- Un trabajo de análisis crea una reserva transaccional y se vincula a la cuenta y a la clave del dispositivo. Las operaciones de carga, finalización y consulta exigen esa vinculación.
- La finalización exitosa registra un único débito; un error o rechazo terminal libera la reserva. Los reintentos no deben descontar créditos adicionales.
- **Se deshabilita por defecto** hasta que se habiliten `SPDECODE_ANALYSIS_CREDITS_READY=true`, el servicio APK y la configuración de cuentas y base de datos. El acceso QA antiguo sin créditos deja de ser válido.
- El APK no contiene claves del servidor ni decide el saldo.

## Despliegue y QA

1. Aplicar migración aditiva `005_account_support_apk.sql` después de `002_shop.sql`, `003_ads_free.sql`, `004_gifts.sql`, usando `node scripts/commerce-migrate.mjs --apply` dentro del contenedor/web con las variables de entorno aprobadas.
2. Configurar el secreto `SPDECODE_SUPPORT_ENCRYPTION_KEY` en el VPS (no en GitHub en claro); verificar disponibilidad de Google OAuth, Better Auth, PostgreSQL y cookies de sesión.
3. Verificar acceso a soporte con una cuenta y otra distinta, respuestas de administrador, controles CSRF, mensajes cifrados en la tabla, cierre y reactivación de conversaciones.
4. Probar renovación de sesiones, acceso local con huella/PIN sin contraseña y rechazo después de cerrar sesión.
5. Probar desafío de eliminación con firma válida, vencida, repetida, cuenta distinta y contraseña incorrecta; confirmar eliminación y revocación.
6. Probar balance de 0 y 1 créditos, trabajos simultáneos, pausa/reintento, análisis exitoso, error terminal, reversión de reserva y pertenencia a otro dispositivo.
7. Verificar build Android, firma persistente, certificado, archivo hash y que la interfaz de regalo revela el premio solo tras el canje.

**Pendiente de despliegue:** cambios guardados en la rama QA, sin tocar `main` ni el VPS ni activar métodos de pago reales.
