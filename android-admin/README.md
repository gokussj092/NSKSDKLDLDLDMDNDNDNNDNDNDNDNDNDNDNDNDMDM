# SP-DECODE Admin — contrato visual aprobado

Proyecto Android independiente, nativo, sin WebView, sin anuncios; package com.ghostdeveloper.spdecode.admin. Rama base ci/unity-ads-online-qa. No alterar android/app, Cloud, Offline ni despliegue.

## Especificación de interfaz
- AMOLED #000000, superficie #111516, acento #34D9A4, advertencia #F4C76A, error #F87171. Texto #F7F7F7 y secundario gris. Tarjetas 12–20 dp, campos de búsqueda redondeados, iconografía lineal, espaciado 12–16 dp.
- Login: escudo centrado, SP-DECODE y ADMINISTRATION, usuario, contraseña, botón esmeralda, acceso biométrico.
- Dashboard: estado del servidor, cuadrícula 2×2 de usuarios/ingresos/tickets/licencias, gráfica y barra inferior Dashboard/Usuarios/Soporte/Ajustes.
- Menú lateral: Dashboard, Usuarios, Roles, Soporte, Compras, Productos, Licencias, Gift codes, API comercial, Créditos, Catálogo, Servidor, Notificaciones, Seguridad, Mantenimiento, Ajustes.
- Usuarios: contadores, búsqueda, filtros, avatar, correo, estado. Detalle: perfil, compras, dispositivos/sesiones, licencias, actividad y suspensión.
- Roles: tarjetas por cargo, icono, miembros y creación de cargo.
- Soporte: bandeja estilo Telegram, avatar, estado, hora, no leídos; chat con burbujas, adjuntar, enviar circular compacto, asignación.
- Comercio: ingresos y gráfica, métodos de pago; transacciones, productos, licencias, gift codes, API por IP, créditos.
- Infraestructura: servidor, CPU/RAM/disco, servicios; catálogo con versión, búsqueda y estados; notificaciones masivas multiidioma; auditoría, mantenimiento.
- Seguridad: biometría, 2FA, dispositivos y sesiones, contraseña; ajustes: AMOLED/oscuro/claro, idioma, notificaciones, actualizaciones, acerca de.
- Mantener diseño mostrado al propietario; contrastar capturas de las pantallas antes de aprobar cambios.

## Gate de producción
El cliente no debe contener secretos de servidor ni roles confiables localmente. No usar login simulado como autenticación real: cualquier maqueta con datos ficticios se limita a debug sin red ni acciones mutables. Implementar API administrativa con autorización servidor por permiso, sesión revocable, MFA, reautenticación para operaciones críticas, auditoría, Keystore y firma independiente. Validar contratos reales y paridad web antes de habilitar producción. No despliegue ni cambios al backend en esta fase.
