# SP-DECODE API V2 — Panel de compatibilidad de atestación

Fecha: 2026-10-31. Rama: `feat/cloud-selector-private-card-notification-chime`.

## Incidente y hallazgos

Usuarios de Android 1.1.25 informan que no pueden descargar el catálogo Server VPN, mientras el mismo APK funciona en otro teléfono. El backend responde correctamente a operaciones locales de versión, catálogo, cifrado y 49/49 iconos. En un período observado el VPS registró **37 eventos `OS_PATCH_OUTDATED` y 16 `VERIFIED_BOOT`**, pero no se ha correlacionado cada evento con un usuario; la comprobación de limitación HPKE tenía 17 peticiones/minuto como máximo, lejos de 180.

Un usuario comunicó parche visible de **26-jul-2026**, que por sí solo no debería fallar el límite estricto de 12 meses. Un evento `OS_PATCH_OUTDATED` puede corresponder a otro usuario o a un valor de atestación distinto del texto de Ajustes. La app envía por JNI/C++ una cadena del Android Keystore que el servicio independiente valida criptográficamente: `CloudRequestProof.attest()`, `CloudNativeTransport.attestHardwareKey()`, `cloud/web/lib/device-security.mjs` y `cloud/attestation/src/main/kotlin/Server.kt`. No hay evidencia de que la app invente las fechas. Los límites de paquetes, firmas, certificados y pruebas de sesión son independientes.

`VERIFIED_BOOT` no equivale a detección concluyente de root. Se deriva del estado de Verified Boot y del bootloader proporcionado por hardware. Una ROM personalizada, bootloader abierto o verificación fallida puede producirlo. No puede afirmarse con este dato que un dispositivo tenga root.

## Controles nuevos en panel

Ruta `/admin/api-v2`; estado leído desde `/api/admin/session` como `v2DevicePolicy`.

- **Antigüedad máxima de parches:** 12 (por defecto), 18, 24, 36 o 48 meses. Incluye OS, vendor y boot cuando el hardware ofrece dichos campos.
- **Exigir parches recientes:** activado por defecto. Desactivar omite *solo* la comparación de fechas del sistema durante la ventana de prueba.
- **Exigir Verified Boot/bootloader bloqueado:** activado por defecto. Desactivar omite *solo* esa comprobación. No implica que el servidor pueda determinar con certeza si hay root.
- **Duración de la excepción:** 1, 6, 24 o 48 horas. Toda relajación se restablece automáticamente al perfil estricto, calculado durante cada lectura de política, incluso tras reinicios. El reset manual aplica de inmediato.
- **Diagnóstico agregado:** recuentos por categoría `OS_PATCH_OUTDATED`, `VENDOR_BOOT_PATCH_OUTDATED`, `VERIFIED_BOOT`, `APP_ID_MISMATCH`, etc. desde el último arranque del servicio. No se registran datos del equipo, IP, certificado o credencial.

Los ajustes se guardan atómicamente en `/app/provider-control/v2-device-admission.json` con revisión CAS, autenticación del administrador, defensa CSRF, tasa limitada, confirmación explícita y auditoría agregada Redis. El valor de prueba se pasa del backend al servicio de atestación por su enlace privado con autenticación mediante el token de servicio. Android **no** controla ese valor y nunca se le entregan las credenciales de administración.

## Límites de seguridad que NO se desactivan

La validez de la cadena de certificados de Google, revocaciones, desafío, clave pública del dispositivo, el hardware TEE/StrongBox requerido, identidad del paquete `com.ghostdeveloper.spdecode`, versión mínima, digest de la firma APK, PoP firmado, sesiones individuales y HPKE **permanecen obligatorios**. Deshabilitar ambos interruptores no equivale a un acceso anónimo a V2.

La política de API V1, su fecha de retiro y el acceso beta de Play Integrity V2 son independientes. Este cambio no añade descifradores, ni modifica catálogos, ni necesita otra APK.

## Archivos implicados

- `cloud/web/lib/v2-device-admission-policy.mjs`: almacenamiento y caducidad del perfil.
- `cloud/web/lib/c6-admin-api.mjs`, `cloud/web/app/api/admin/v2-device-admission/route.js`: estado, mutación, controles CSRF/admin, auditoría agregada y diagnósticos.
- `cloud/web/app/admin/admin-dashboard.jsx`, `cloud/web/app/admin/admin-theme.css`: controles API V2, selector y contadores.
- `cloud/web/lib/device-security.mjs`: incluye el perfil vigente en la solicitud privada y autenticada de atestación.
- `cloud/attestation/src/main/kotlin/Server.kt`: verifica la excepción de máximo 48h sin omitir autenticación, y permite consultar `GET /stats` solo con token interno.
- Pruebas Kotlin `cloud/attestation/src/test/kotlin/PolicyTest.kt`; Node `cloud/web/tests/v2-device-admission-policy.test.mjs`, `cloud/web/tests/v2-device-admission-admin.test.mjs` y `cloud/web/tests/device-security.test.mjs`.

## Publicación: DOS contenedores

**La instalación requiere recompilar web Y key-attestation.** Ejecutar solo `spdecode update web` incorpora la UI, pero el servicio de atestación antiguo ignoraría `devicePolicy`; los interruptores no producirían el resultado esperado.

No ejecutar GitHub Actions en el repositorio privado con créditos insuficientes. Antes de cualquier despliegue:

1. Ejecutar pruebas locales `cd cloud/web && node --test tests/v2-device-admission-policy.test.mjs tests/v2-device-admission-admin.test.mjs tests/device-security.test.mjs`. También `npm test` y `npm run build`.
2. Compilar/verificar `cloud/attestation` mediante Gradle o Docker; el Dockerfile ejecuta `gradle test installDist`. Verificar pruebas de una cadena válida, root de confianza inválida, firma de app incorrecta, parche de 30 meses, bootloader abierto, TTL y expiración.
3. Respaldar `/etc/spdecode/cloud.env` y estado del VPS con `spdecode backup`. No imprimir claves. `spdecode update web feat/cloud-selector-private-card-notification-chime` valida continuidad HPKE.
4. Con la revisión aprobada y el repositorio ya actualizado, reconstruir **solo** `key-attestation` usando Compose, el perfil `hardware-security`, el env-file protegido y el compose de `/opt/spdecode/repo/cloud/compose.yaml`. Evitar tocar Redis, el worker y HPKE.
5. Revisar que el verificador responda `/ready` en la red privada y que el panel reciba sus métricas; la función `/stats` requiere el token privado, nunca una URL pública.
6. Desde `/admin/api-v2`, comenzar con 24 meses y ambos controles activados, durante una hora. Pedir a un tester que vuelva a intentar la descarga; revisar diferencias de recuentos. Si sigue fallando, probar 36 meses, después Verified Boot solo de manera temporal y vigilada. No desactivar simultáneamente dos controles como primer paso.
7. **Restaurar el perfil estricto** tras las pruebas o esperar caducidad; las dos medidas afectan el riesgo de ejecutar en dispositivos no confiables.
8. Si es necesario rollback de la web, restaurar la revisión anterior con el procedimiento documentado. Si se restaura el backend anterior, reiniciar también el verificador anterior, manteniendo los respaldos.

**Estado:** código guardado en rama; simulación del almacenamiento de política 8/8 aprobada; suite Node completa, pruebas de Gradle/Docker y despliegue VPS todavía no ejecutados. Los nuevos interruptores no están activos hasta instalar ambos servicios.
