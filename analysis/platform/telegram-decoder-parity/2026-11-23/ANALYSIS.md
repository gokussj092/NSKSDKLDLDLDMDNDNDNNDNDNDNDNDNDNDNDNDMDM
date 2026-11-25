# Paridad del bot de Telegram con los motores de Cloud

La integración parte de `fc63958b950a3cb0000eecdf2ae2f6bd1e5aa109`.
El registro histórico del bot contiene 246 extensiones. El registro de
ejecución de Cloud contiene 282 y selecciona motores distintos para 27
extensiones compartidas. Este cambio conecta los documentos y textos del
bot a los motores que ya están en el repositorio.

La revisión abarca el despacho y la entrega del resultado en Telegram.
Se reutiliza la evidencia existente de cada lector. No se analizó un APK,
no se extrajeron claves y no se probaron servicios de terceros.

- HTTP Custom histórico: [build 564 y revisiones 57](../../../xyz.easypro.httpcustom/564/RESULTS.md).
- HCCFG recientes y límites pendientes: [build 934](../../../xyz.easypro.httpcustom/934/RESULTS.md).
- Tunneltweak: [build 53](../../../com.tunneltweak.loyalteams/53/RESULTS.md).
- Integraciones suministradas: [expediente previo](../../supplied-integrations/2026-11-14/REPRODUCE.md).

HMAC de archivos: se conserva la identificación y validación del lector de
cada formato, incluida la autenticación de HCCFG. El HMAC de transporte VPN
y el de autenticación de conexión quedan UNCONFIRMED para este expediente.
Las pruebas usan entradas autorizadas ya versionadas o datos sintéticos.
