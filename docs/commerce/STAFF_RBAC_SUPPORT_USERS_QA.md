# SP-DECODE Online — personal autorizado, atención y directorio

Implementación QA: rama `ci/unity-ads-online-qa`. El código C++/JNI, Unity Ads, HPKE y firma persistente de Android no se alteran.

## Interfaces

- Soporte Android: bandeja compacta con estado, asunto, última respuesta y acceso tocando la fila; conversación completa en burbujas, nombre/rol del agente, marcas horarias y editor multilínea con botón circular. La bandeja usa scroll propio y no tiene botones enormes.
- Consola: `/admin/support` con vista de dos columnas, filtros de estado, chat y acciones de asignación, prioridad, cierre y reapertura.
- Personal: `/admin/staff`, propietario únicamente para crear/editar cuentas o restablecer contraseñas. Al crear una cuenta se devuelve una contraseña aleatoria de 192 bits, visible **una vez**, se almacena únicamente el hash scrypt.
- Primer acceso: `/admin/staff-password`, cambio obligatorio de contraseña temporal (mínimo 16 caracteres). El cambio revoca todas las sesiones anteriores.
- Clientes: `/admin/users`, búsqueda paginada y detalle: foto, ID de cuenta, nombre, @usuario, correo, acceso Google/correo, pedidos, licencias, beneficios, sesiones y créditos. **No revela** contraseñas, hashes, tokens OAuth, secretos API ni credenciales privadas.
- Auditoría: `/admin/staff-audit`, altas, cambios, restablecimiento, consulta detallada de clientes, respuesta y asignación de tickets.

## Seguridad y roles

La cuenta propietaria actual, definida en el archivo privado del VPS, continúa siendo la única autorizada para operaciones de infraestructura, claves y administración completa. **No se reutiliza su contraseña** para otros operadores.

| Cargo | Acceso autorizado |
|---|---|
| Propietario | Todos los módulos existentes, personal, clientes, soporte y auditoría |
| Administrador | Soporte, asignación, clientes, personal (consulta), auditoría |
| Soporte | Solo tickets asignados; lectura y respuesta |
| Moderación | Tickets, asignación y consulta de clientes |
| Facturación | Consulta de cuentas/compras; no responde soporte |

Las rutas heredadas de VPS e infraestructura continúan exigiendo la sesión del propietario. Los permisos de personal se validan **en cada endpoint**, no únicamente en el menú. Las sesiones del equipo tienen cookie independiente, HttpOnly, Secure, SameSite=Strict, TTL 1 hora, firma HMAC y registro servidor Redis. Suspender, cambiar cargo, username o contraseña incrementa `session_version`, invalidando todas las sesiones activas.

La cuenta de soporte únicamente ve los tickets asignados y no puede asignarse otros ni modificarse permisos. Un administrador/propietario asigna previamente cada conversación.

Las contraseñas temporales solo se muestran en la respuesta inmediata de creación/restablecimiento. Deben compartirse por un canal seguro, preferentemente distinto del mismo soporte público. En una futura entrega se recomienda agregar TOTP/WebAuthn obligatorio para personal privilegiado.

## Datos personales y privacidad

El directorio está limitado a 30 cuentas por página y consultas de longitud máxima 80 caracteres. La ficha detallada registra el acceso en auditoría. Las credenciales privadas, tokens, contraseñas, secretos de facturación y contenido de análisis no forman parte de las respuestas. El acceso del cargo Facturación a datos financieros no concede funciones de devolución o alteración de pagos.

Los mensajes de soporte conservan el cifrado AES-256-GCM en reposo. Cada respuesta queda atribuida al agente autenticado con fecha y copia histórica del nombre y cargo; modificar el nombre después no reescribe los mensajes anteriores. **No es cifrado de extremo a extremo**, ya que el servidor y operadores autorizados deben descifrar y responder.

## Despliegue

La migración aditiva `007_staff_permissions.sql` agrega tabla de personal, auditoría y asignación de tickets. La ejecuta el instalador comercial de SP-DECODE junto con las migraciones anteriores; no almacena ninguna contraseña en claro ni activa medios de pago. Para crear el primer usuario del equipo, iniciar sesión con la cuenta propietaria existente y visitar `/admin/staff`.

El VPS no se actualiza automáticamente desde este cambio. Primero revisar GitHub Actions y aplicar la rama QA mediante el actualizador oficial ya verificado:

```bash
sudo spdecode update all ci/unity-ads-online-qa && sudo spdecode commerce init && sudo spdecode status
```

Se conserva la configuración privada en `/etc/spdecode/cloud.env`. La clave de soporte ya se genera de manera idempotente si no existe, sin exponerla en terminal.

## Matriz de QA

1. Inicio de sesión propietario y soporte, cambio obligatorio de contraseña, inicio con contraseña nueva.
2. Crear/modificar/desactivar/reiniciar credenciales, confirmar hash no recuperable, revocación de cookies y prohibición de escalado a propietario.
3. Los usuarios soporte no ven ni ejecutan endpoints de infraestructura, personal, créditos o administración de compras.
4. Asignación de ticket a agente, rechazo de respuesta por agente distinto, reenvío y estado en la app.
5. Nombre y cargo exacto del agente, visualización de mensajes cifrados y separación estricta entre cuentas comerciales.
6. Directorio de clientes paginado, búsquedas, compras, saldo, sesiones y detalle sin credenciales.
7. Migración idempotente, pruebas con PostgreSQL, build Next.js, compilación Android y firma persistente.
