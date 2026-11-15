# F7 — APK QA sin login, créditos ni cobros (primera pasada)

**Implementación en rama:** `feat/nuevas-integraciones`. **Estado: CÓDIGO INTEGRADO, PRUEBAS CI Y DESPLIEGUE REALES PENDIENTES**. Nunca declarar el analizador automático comercial completado por esto.

> **Actualización posterior (2026-11-07):** el código ahora incluye un único trabajo QA global por vez, checkpoint Android cifrado, WorkManager con reintentos, START idempotente, reanudación por `nextChunk` confirmado y reconciliación del servidor tras reiniciar. Ver [continuidad y un solo trabajo](FASE_7_APK_QA_CONTINUIDAD_Y_UNICO_TRABAJO_2026_11_07.md). Las menciones originales a «recuperación pendiente» describen el estado anterior a esa implementación: **siguen pendientes las pruebas reales E2E, la certificación CI y el despliegue**, no la incorporación inicial del código.

## Alcance verificable

- Android: selector SAF para `.apk`/`.apks`, consentimiento explícito, hash SHA-256 y subida de 2 MiB por fragmento cifrado con HPKE V2/JNI. Progreso, cancelación local, reintento por errores transitorios, polling y visualización del JSON preliminar. Idiomas actualizados: 14. Sin login ni débitos. La pantalla de tienda permanece desactivada.
- Autorización: **no anónima**. Continúan la sesión V2 cifrada HPKE, PoP, atestación, Play Integrity cuando corresponda y controles de reintento. **No se registra ningún dispositivo ni se introduce un código o token en Android.** El gateway deriva automáticamente la identidad del trabajo a partir del canal V2 verificado. El secreto entre contenedores lo genera la CLI del VPS de forma privada.
- Servidor: gateway de cuatro operaciones V2 (21 start, 22 chunk, 23 finish, 24 result), credencial interna autogenerada exclusivamente entre contenedores, Docker sin puerto QA publicado y 320 MiB de memoria. **Un solo APK/APKS activo a la vez**, con reanudación cifrada. No se ejecutan los 63 scripts originales; no hay login, pagos ni códigos regalo.
- El parser actual **sí examina los bytes reales** de un APK: archivo ZIP y manifest, DEX (cabeceras y número de clases/métodos), bibliotecas nativas, recursos y hashes. **No** hace descompilación JADX/Ghidra, ingeniería inversa de algoritmos ni descifrado automático de catálogos. Los resultados son `COMPLETED_PRELIMINARY`, nunca `VERIFIED_REAL` de métodos VPN.
- Límite QA: 100 MB exactos (100,000,000 bytes) por APK/APKS; XAPK y ZIP directos no admitidos. Datos transmitidos con V2 HPKE, pero la copia temporal de APK en volumen del laboratorio todavía **no se cifra en reposo**. Se elimina el APK al finalizar el análisis; las subidas caducan tras 1h de inactividad y los informes tras 12h, con barrido cada cinco minutos. Probar solo APK autorizados sin contenido confidencial. La cancelación por ahora detiene el trabajo en Android, **no revoca inmediatamente** el trabajo del servidor (caduca automáticamente).

## Configuración privada de laboratorio — NO producción

1. Revisar recursos del host: el VPS actual reducido puede quedarse sin RAM si se añade el analizador al worker existente; se recomienda un host de QA dedicado o dimensionamiento medido. No reiniciar producción para probar sin aprobarlo.
2. **Sin configuración manual de tokens ni dispositivos:** tras actualizar el VPS y confirmar que la API Cloud V2 está activa, ejecutar `sudo spdecode apk-qa enable`. El comando genera/reutiliza una credencial interna secreta, guarda la configuración privada y construye web + apk-qa. Nadie necesita copiar el ID del móvil ni pegar claves. No se publica ningún puerto del contenedor QA.
3. Después de aprobar CI: `sudo spdecode apk-qa enable`; verificar con `sudo spdecode apk-qa status`. La nueva CLI garantiza que el laboratorio sigue en su red privada.
4. Primero comprobar la rama por CI y pruebas manuales: `python -m unittest tests.test_f7_apk_qa_service -v`, `node --test cloud/web/tests/f7-apk-qa.test.mjs` en `cloud/web`, compilación Android con JNI y test de APK firmado propio. Verificar hashes, clases, bibliotecas, código de error de ZIP/XAPK, transferencia >8 MiB, permisos, sobrecarga, cancelación y limpieza. Ninguna prueba de APK externo se realizó desde este chat.
5. No habilitar para usuarios ajenos hasta completar cuentas, cuotas y políticas de privacidad. El trabajo de recuperación de subida ya tiene código, pendiente de pruebas E2E; siguen pendientes cancelación remota, cifrado temporal en reposo y orquestador completo.

## CI y bloqueo

Última revisión de las ejecuciones: [F7 APK QA run 42403333789](https://github.com/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42403333789) = **FAILURE sin pasos ni logs**, [Validate 42403333506](https://github.com/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/42403333506) = lo mismo, [F7 Evidence 42403333472](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/42403333472) = lo mismo. GitHub Status no indica una interrupción activa para el momento de la consulta. Esto puede ser problema de facturación, permisos o provisión de runners **sin diagnóstico confirmado**; revisar el banner de Actions/Settings/Billing de la cuenta. No modificar métodos ni pruebas para forzar verde.

## Relación con el resto de Fase 7

F7-A0-P08 había pasado [79 Python +69 Node sobre código existente](https://github.com/gokussj092/NSKSDKLDLDMDNDNNDNNDNDNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/42340438190). P09 y otras revisiones A0 de licencias/corpus permanecen pendientes. Las 9 etapas F7-A1–A9 del plan comercial original siguen sin terminar: **cuentas**, perfiles, ledger, almacenamiento duradero cifrado, orquestación de análisis completo, soporte humano, compras Play, historial/reembolsos e integración beta. La nueva prueba QA es una vía temporal antes de la comercialización, no una conclusión de esas etapas.

No se hizo merge, no se creó rama nueva, no se tocó método VPN operativo, no se entregó APK/AAB compilado ni se desplegó el VPS.
