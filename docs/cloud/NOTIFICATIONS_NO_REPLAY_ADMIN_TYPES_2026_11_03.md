# SP-DECODE — anti-spam de notificaciones y selección de avisos (2026-11-03)

**Rama:** `fix/http-jireh-current-method`, sin modificación de `main`. **No publicado en VPS, Google Play ni Telegram.**

## Diagnóstico confirmado
FCM envía un UUID como señal al tema `spdecode-notices-v1`, pero el cliente consulta el feed V2 completo y mostraba todos los registros válidos de los últimos siete días no marcados como vistos. La suscripción nueva al tema FCM no reproduce avisos anteriores por sí sola: la ráfaga proviene de la consulta al feed del servidor.

## Política implementada
- En el momento exacto de optar por notificaciones, Android guarda una marca temporal local. El servidor incluye `serverTime` en la respuesta autenticada de la operación V2 de avisos. Al primer fetch, el cliente convierte el tiempo transcurrido desde la activación al reloj del servidor y guarda un corte persistente en preferencias privadas. No presenta registros cuyo `createdAt` sea anterior al corte.
- Para dispositivos existentes que aún no tienen el corte (migración), se toma el primer sincronizado como inicio: se descarta el historial anterior; las publicaciones futuras se muestran normalmente. Esta migración deliberada puede no mostrar avisos recientes que aún no se habían visto.
- Al desactivar y reactivar notificaciones se reinicia el punto de corte. Una instalación nueva o una reactivación no recupera notificaciones antiguas.
- Si la respuesta no trae reloj del servidor, Android falla de forma segura y no muestra una ráfaga.
- Los avisos válidos se ordenan por importancia y fecha y se muestran como máximo 3 por sincronización. Los antiguos omitidos se registran como procesados para no aparecer en el siguiente sondeo.
- Categorías disponibles: general, actualización, mantenimiento, catálogo VPN y seguridad.
- Urgencia: normal o importante. Importante ajusta la prioridad de la señal FCM y la prioridad Android pre-26; **no** sobrescribe la configuración del canal de notificaciones del usuario.
- Método de entrega: FCM + recuperación periódica o solo recuperación periódica (sin FCM).
- Caducidad: 6 h, 24 h (predeterminada), 3 días, 7 días (límite máximo). Historial administrativo independiente de la visualización de notificaciones.
- Se mantiene el soporte de avisos antiguos de cinco campos, sin convertirlos ni perder sus datos en el volumen durable. Los nuevos guardan metadatos enumerados de categoría, urgencia y entrega.
- La cuenta de servicio FCM solo permanece en el servidor. Nada de claves en el APK; no se permiten URLs, intents ni destinos desde el panel.
- API y publicación mantienen sesión administrativa, CSRF, controles de tamaño e idempotencia.

## Limitaciones operativas
- **Los dispositivos con APK antiguas mantienen el fallo hasta actualizar.** El servidor no conoce la fecha real de instalación de esos clientes antiguos y no puede distinguirlos sin cambiar su protocolo.
- FCM acepta mensajes pero no garantiza entrega inmediata; el sondeo de WorkManager está sujeto a Doze y conectividad.
- No se implementan envíos a usuarios individuales, estadísticas de recepción reales ni un registro de destinatarios que no existe en el backend.
- El tipo y la urgencia son elecciones del publicador. No implican que Google Play cambie el flujo de actualizaciones Flexible/Immediate.
- El servidor y Android deben desplegarse coordinadamente para que `serverTime` esté disponible antes de la nueva APK; la compatibilidad del contrato V2 se mantiene para clientes existentes.

## QA requerido antes de publicación
1. Tests de Node: idempotencia, CSRF, feed antiguo/nuevo, caducidad, prioridad FCM y modo sin push.
2. Android: pruebas de política de opt-in, migración y filtros anti-replay; compilación Cloud AAB y APK Telegram.
3. Dispositivo limpio: instalar, habilitar notificaciones después de publicar varios avisos, verificar que no llegue ninguno anterior; publicar uno nuevo, comprobar recepción. Repetir desactivación/activación, revocar permiso y usar clientes antiguos.
4. Prueba con >3 avisos durante offline; máximo 3 visibles al reconectar y sin repeticiones.
5. No enviar avisos de prueba reales a la audiencia general ni desplegar hasta autorización del propietario.

Referencia: `docs/cloud/CATALOG_AND_NOTIFICATIONS.md`.
