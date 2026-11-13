# SP-DECODE Online QA — Actualización visual y despliegue seguro

Rama de trabajo: `ci/unity-ads-online-qa`. No se modifica `main`. Android sigue en 1.1.27 (42), con la keystore de firma persistente, C++/JNI y Unity Ads existentes.

## Interfaz de autenticación

- Una única pantalla de bienvenida, centrada, utiliza **`R.mipmap.ic_launcher` real** en vez de iconos genéricos. Tiene pestañas `Iniciar sesión` y `Crear cuenta`.
- `Iniciar sesión` ofrece Google y correo + contraseña; `Crear cuenta` usa Google verificado para evitar duplicados y el registro abierto por correo permanece deshabilitado.
- Existe un solo consentimiento con enlaces a términos y privacidad.
- Las sesiones siguen renovándose durante 90 días y el token está cifrado en Android Keystore. Si el backend comercial se encuentra temporalmente deshabilitado, el cliente puede volver a validar la sesión al recuperarse el servicio sin revocar el bearer por ese motivo. No concede beneficios offline basándose en el caché.

## Eliminación de cuenta

Cabecera e icono centrados, advertencia y botones destructivos en rojo intenso, texto y confirmación expresos. Se conservan las verificaciones existentes: contraseña, reautenticación Google y desafíos firmados por una clave privada no exportable de Android Keystore.

## Soporte técnico y agentes

- Los mensajes de soporte mantienen AES-256-GCM en reposo y autenticación de sesión. **No** es cifrado de extremo a extremo.
- Migración aditiva `006_support_agent_identity.sql` añade, a cada respuesta del personal, identificador interno, nombre visible y rol autenticado. Los datos se guardan como fotografía de identidad del agente al responder para preservar el historial.
- Para el panel de administración actual, el servidor utiliza `SPDECODE_SUPPORT_AGENT_NAME` si está configurado; en su defecto `CLOUD_ADMIN_USERNAME`. La identidad es derivada de la sesión del administrador y la configuración privada, nunca enviada por Android.
- Esto prepara el modelo para futuros empleados de soporte. **No** se delegan permisos administrativos hasta implementar gestión de roles y sesiones individuales. Un nombre de usuario no constituye por sí mismo un permiso.
- El usuario ve el nombre y rol de quien respondió. El panel muestra también los agentes responsables de cada respuesta.

## «Sin anuncios» y precios

- Los precios de la oferta de 30 días se obtienen de `/api/store/catalog`. Se refrescan al volver a entrar en la tienda y mediante el botón `Actualizar precios`; la cotización se invalida cuando cambia la oferta.
- El total definitivo, los impuestos y la disponibilidad de Stripe/PayPal siguen definidos por el servidor mediante `/api/store/quote` y `/api/store/checkout`. No hay precios ni confirmaciones de pago inventados por la APK.
- La UI muestra la vigencia de la licencia obtenida de `/api/account`.
- **`checkoutPending` ya no quita anuncios**. Unity Ads solo se suprime cuando existe un entitlement verificado por el servidor y no expirado, o mientras la validación de sesión se encuentra sin resolver. Ni tocar «Comprar» ni volver del navegador sustituyen el webhook de pago.

## VPS: usar el actualizador existente

La ruta correcta es `/opt/spdecode/repo` y la configuración `/etc/spdecode/cloud.env`. **No utilizar** `cd /opt/spdecode && docker compose ...` para esta instalación.

Para actualizar el código de web y worker y después preparar y migrar las tablas comerciales (sin habilitar cobros):

```bash
sudo spdecode update all ci/unity-ads-online-qa && sudo spdecode commerce init && sudo spdecode status
```

`spdecode commerce init` ejecuta la preparación privada, crea `SPDECODE_SUPPORT_ENCRYPTION_KEY` con 32 bytes criptográficamente aleatorios **solo si aún no existe**, no la imprime, conserva secretos antiguos y marcas de activación, valida los permisos 0600, reconcilia la base comercial, ejecuta migraciones aditivas y recrea la web con el secreto.

Para provisionar únicamente la clave, sin preparar el resto de comercio, después de instalar la nueva versión de CLI:

```bash
sudo spdecode commerce support-key
```

El nombre visible opcional del administrador de soporte se configura por `SPDECODE_SUPPORT_AGENT_NAME` en `cloud.env` (y se proyecta únicamente a web). Si falta, se muestra el nombre de usuario del administrador autenticado.

**Importante:** la migración y los cambios del servidor deben realizarse antes de probar en Android los endpoints de soporte, cuentas y licencias. Las claves HPKE persistentes y la firma de APK no se regeneran con esta operación.

## Pruebas obligatorias

1. Cambiar entre iniciar sesión y crear cuenta y confirmar icono real, centrado, consentimiento y traducciones.
2. Cerrar/reabrir la aplicación y recuperar sesión válida. Simular caída comercial temporal sin perder el token cifrado, pero nunca aceptar un entitlement local sin servidor.
3. Confirmar eliminación de cuenta: advertencia roja, comprobación real, no se modifica ningún usuario por pruebas automatizadas de producción.
4. Usuario escribe a soporte; administrador responde y la app enseña el nombre y rol del agente, sin aceptar identidad arbitraria enviada por cliente. Rechazar lectura de mensajes de otras cuentas.
5. Obtener precio sin anuncios desde catálogo, refrescar, comprobar cotización actualizada, renovación por pago verificado y supresión de anuncios solo con entitlement activo.
6. Repetir las pruebas de migración del VPS: clave inicial, idempotencia, clave existente, clave inválida, permisos privados.
7. Ejecutar CI firmado, verificar el hash y probar APK en dispositivo antes de cualquier despliegue público.
