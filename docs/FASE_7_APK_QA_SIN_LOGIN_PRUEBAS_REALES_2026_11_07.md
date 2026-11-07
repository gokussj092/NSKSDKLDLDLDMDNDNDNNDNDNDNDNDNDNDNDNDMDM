# F7 — APK QA sin login, créditos ni cobros (primera pasada)

**Implementación en rama:** `feat/nuevas-integraciones`. **Estado: CÓDIGO INTEGRADO, PRUEBAS CI Y DESPLIEGUE REALES PENDIENTES**. Nunca declarar el analizador automático comercial completado por esto.

## Alcance verificable

- Android: selector SAF para `.apk`/`.apks`, consentimiento explícito, hash SHA-256 y subida de 2 MiB por fragmento cifrado con HPKE V2/JNI. Progreso, cancelación local, reintento por errores transitorios, polling y visualización del JSON preliminar. Idiomas actualizados: 14. Sin login ni débitos. La pantalla de tienda permanece desactivada.
- Autorización: **no anónima**. Continúan obligatorias la atestación del dispositivo, la sesión V2, PoP, Play Integrity cuando lo exige el servidor y los controles de reintento. Se añade allowlist de **SHA256 de clave pública del dispositivo** (no de contraseña). El botón «Copiar ID de mi dispositivo de prueba» entrega ese hash para inscribirlo en el servidor. Sin allowlist, las subidas se rechazan.
- Servidor: gateway de cuatro operaciones V2 (21 start, 22 chunk, 23 finish, 24 result), secret interno distinto al de descifrado, servicio Docker de análisis en red privada sin puerto publicado, 320 MiB de límite de contenedor y dos trabajos simultáneos como máximo. Los 63 scripts de investigación no se ejecutan ni modifican. No hay cuentas, compras ni gift codes aún.
- El parser actual **sí examina los bytes reales** de un APK: archivo ZIP y manifest, DEX (cabeceras y número de clases/métodos), bibliotecas nativas, recursos y hashes. **No** hace descompilación JADX/Ghidra, ingeniería inversa de algoritmos ni descifrado automático de catálogos. Los resultados son `COMPLETED_PRELIMINARY`, nunca `VERIFIED_REAL` de métodos VPN.
- Límite QA: 96 MiB por APK/APKS; XAPK y ZIP directos no admitidos. Datos transmitidos con V2 HPKE, pero la copia temporal de APK en volumen del laboratorio todavía **no se cifra en reposo**. Se elimina el APK al finalizar el análisis; las subidas caducan tras 1h de inactividad y los informes tras 12h, con barrido cada cinco minutos. Probar solo APK autorizados sin contenido confidencial. La cancelación por ahora detiene el trabajo en Android, **no revoca inmediatamente** el trabajo del servidor (caduca automáticamente).

## Configuración privada de laboratorio — NO producción

1. Revisar recursos del host: el VPS actual reducido puede quedarse sin RAM si se añade el analizador al worker existente; se recomienda un host de QA dedicado o dimensionamiento medido. No reiniciar producción para probar sin aprobarlo.
2. En un despliegue privado con secretos protegidos (fuera del repo): `CLOUD_APK_QA_ENABLED=true`; `CLOUD_APK_QA_INTERNAL_TOKEN=<token aleatorio de al menos 32 caracteres>`; `CLOUD_APK_QA_ALLOWED_KEY_SHA256=<64 hex copiados del dispositivo de prueba>`. El botón Android calcula el hash de la **clave pública** de ese dispositivo; no incluir claves privadas. Máximo 8 valores SHA256 hex delimitados por comas. Se exige red y reverse-proxy V2 existente; no se añade endpoint público directo.
3. Levantar solo con aprobación del propietario: `docker compose -f cloud/compose.yaml --profile apk-qa up -d --build web apk-qa`; comprobar que el contenedor QA **no tiene port binding externo**, está aislado del decoder-worker y conserva los límites; verificar `/health` internamente.
4. Primero comprobar la rama por CI y pruebas manuales: `python -m unittest tests.test_f7_apk_qa_service -v`, `node --test cloud/web/tests/f7-apk-qa.test.mjs` en `cloud/web`, compilación Android con JNI y test de APK firmado propio. Verificar hashes, clases, bibliotecas, código de error de ZIP/XAPK, transferencia >8 MiB, permisos, sobrecarga, cancelación y limpieza. Ninguna prueba de APK externo se realizó desde este chat.
5. No habilitar para usuarios ajenos hasta cerrar la fase de cuentas/saldos, cifrado at-rest, cuotas y política de privacidad pública. Recuperación de upload entre reinicios, cancelación remota y orquestador completo de JADX/ELF/métodos siguen pendientes.

## CI y bloqueo

Última revisión de las ejecuciones: [F7 APK QA run 42403333789](https://github.com/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42403333789) = **FAILURE sin pasos ni logs**, [Validate 42403333506](https://github.com/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/42403333506) = lo mismo, [F7 Evidence 42403333472](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/42403333472) = lo mismo. GitHub Status no indica una interrupción activa para el momento de la consulta. Esto puede ser problema de facturación, permisos o provisión de runners **sin diagnóstico confirmado**; revisar el banner de Actions/Settings/Billing de la cuenta. No modificar métodos ni pruebas para forzar verde.

## Relación con el resto de Fase 7

F7-A0-P08 había pasado [79 Python +69 Node sobre código existente](https://github.com/gokussj092/NSKSDKLDLDMDNDNNDNNDNDNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/42340438190). P09 y otras revisiones A0 de licencias/corpus permanecen pendientes. Las 9 etapas F7-A1–A9 del plan comercial original siguen sin terminar: **cuentas**, perfiles, ledger, almacenamiento duradero cifrado, orquestación de análisis completo, soporte humano, compras Play, historial/reembolsos e integración beta. La nueva prueba QA es una vía temporal antes de la comercialización, no una conclusión de esas etapas.

No se hizo merge, no se creó rama nueva, no se tocó método VPN operativo, no se entregó APK/AAB compilado ni se desplegó el VPS.
