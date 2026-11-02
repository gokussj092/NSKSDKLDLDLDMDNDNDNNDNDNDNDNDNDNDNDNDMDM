# SP-DECODE Android 1.1.26 (41) — Fase 8, validación y preparación de producción

**Fecha:** 2026-11-02  
**Rama:** `fix/http-jireh-current-method` (NO `main`).  
**Versión candidata:** 1.1.26 / `versionCode 41`, ahora configurada en `android/app/build.gradle.kts`.  
**Estado:** **preparada para validación CI; NO certificada, NO firmada y NO publicada**. No afirmar que un APK/AAB exista hasta que el workflow de compilación lo demuestre.  
**Restricción del propietario:** no se usa ni distribuye una **aplicación QA**. Las pruebas de instrumentación pueden compilar temporalmente un `debug` interno dentro del runner para inspeccionar la misma aplicación; ese paquete no se sube como APK descargable ni reemplaza un release.

## Alcance y dependencias

El plan general está en `docs/PLAN_ANDROID_1_1_26_BUILD_41_2026_11_02.md`, la arquitectura comercial futura en `docs/FASE_7_ARQUITECTURA_SUSCRIPCIONES_CREDITOS_APK_2026_11_02.md` y la documentación previa de infraestructura/compatibilidad en `docs/ADMIN_COMPATIBILIDAD_Y_SOLICITUDES_2026_11_02.md`.

| Fase | Prueba de aceptación en la rama |
| --- | --- |
| 1: navegación | Formatos solo desde Ajustes; regreso a Ajustes; sin descargar automáticamente al cambiar de pantalla |
| 2: análisis APK | `Próximamente`, importación deshabilitada; cero cargos y sin ejecutar APK externas |
| 3: etiquetas | Nuevo/Actualizado/En mantenimiento, prioridad, expiración y contrato de revisión en catálogo existente |
| 4: errores/sugerencias | Tipos y campos válidos, casillas múltiples, idempotencia, errores de red sin pérdida de datos, endpoint V2 autorizado |
| 5: administración | Filtros/estados/prioridades, sesión/CSRF, persistencia TTL, concurrencia `expectedRevision` |
| 6: Acerca de | AMOLED, enlaces oficiales, versión/build desde BuildConfig, número real de idiomas, acceso a privacidad/términos |
| 7: créditos | SOLO documentación: sin Play Billing operativo, precio de suscripción inventado ni saldo falso |
| 8: release | Compilación y pruebas, 14 idiomas, R8, ABI nativas, compatibilidad V2 y seguridad, firma definitiva |

## Cambios preparados en la fase 8

- Cambios de versión y build en Gradle **1.1.25/40 → 1.1.26/41**; misma `applicationId` y no modificar firma/keystore.
- Pruebas `tests/test_android_phase8_source.py`: config de release, recurso de tres grupos nuevos en 14 idiomas, pantalla Acerca de con versión real, formulario/estados y pantalla de pago informativa e inerte.
- Auditoría `scripts/ci/verify_phase8_native_abis.py`: abre el APK release sin firmar y el AAB reales compilados, comprueba presencia de `libv7q3.so` por arquitectura y valida los encabezados ELF: `armeabi-v7a`, `arm64-v8a`, `x86` y `x86_64`.
- `.github/workflows/validate.yml`: mantiene Python, Node, seguridad de recursos, paridad, build de release R8 y bundle, locales en AAB, auditorías Cloud/HPKE y pruebas Android API35; añade la verificación de cuatro ABI. Conserva un debug interno solo como arnés de pruebas **sin publicar ningún APK de QA/debug**.
- No existe mecanismo de análisis APK activo ni nuevos productos Billing.
- No se usan secretos o claves privadas en este cambio; la firma permanente sigue detrás del workflow de `main`.

## Ejecución CI y política de publicación

**Etapa A: PR de validación sin merge**
1. Crear PR en modo `draft` desde la rama de desarrollo hacia `main` para activar `Validate SP-DECODE` sobre el HEAD real.
2. Examinar los jobs `validate` y `android-parity` y sus resultados, no inferir éxito solo porque arranque.
3. Si falla, corregir en la misma rama y volver a validar; preservar los métodos de descifrado.
4. Mantener `main` y `feat/version-offline-apk` sin cambios, sin mover secretos.

**Etapa B: firma y AAB definitivo (solo después de autorización de integración)**
- El workflow actual `android-signed-release.yml` exige `main` y una validación exitosa de ese commit exacto; no debilitar esta condición para firmar una rama no validada.
- Se usa exclusivamente keystore permanente de GitHub Secrets, no se genera otra identidad. Verificar `apksigner` V1/V2/V3, coincidencia de certificado, zipalign 16KiB, R8, hashes SHA-256, nombre/versión/build.
- Confirmar si el pipeline de distribución también firma **AAB** con identidad de subida prevista: compilar el bundle no equivale a un AAB firmado apto para Google Play.
- La publicación en Play/GitHub y el despliegue VPS son operaciones distintas. No realizarlas por preparar una versión ni por abrir un PR.

## Matriz de aceptación de calidad

| Dimensión | Evidencia requerida |
| --- | --- |
| Android/UX | Navegación atrás, accesibilidad, pantalla pequeña y RTL; test en API35 + prueba física |
| Localización | Los 14 idiomas, paridad de claves, placeholders, formato de mensajes, AAB sin pérdida de idiomas |
| Descifrado | Ficheros originales y compatibilidad Cloud/V1 heredada, no alterar scripts ni exportación unlocked |
| Red | Confirmar que al ver Formatos o etiquetas no hay nueva petición; cada actualización voluntaria descarga 1 catálogo |
| Backend | Panel de solicitudes, estado de métodos, antigüedad de TTL, CSRF, política V2, atestación, HPKE |
| Seguridad | Anti-replay, PoP, Play Integrity (según perfil), no claves ni recursos sensibles en APK, validaciones JNI/ELF |
| Empaquetado | `assembleRelease` y `bundleRelease`, auditorías R8, 4 ABI con headers, 16 KiB |
| Firma | Clave permanente, V1/V2/V3 y Play app signing coherentes, instalación y actualización desde versión anterior |
| Distribución | NO-GO si falla algún punto obligatorio; sin publicar ni fusionar automáticamente |

## Evidencia pendiente para cerrar la fase 8

Al redactar este documento, **no hay resultados nuevos** de CI/firma o de un dispositivo físico que permitan declarar GO. Un PR abierto no equivale a pruebas aprobadas. Registrar cada job, su run ID, SHA y conclusión en una revisión posterior.

**Acciones prohibidas en este ciclo:** generar/distribuir una app QA, usar claves temporales de firmado, fusionar a main sin autorización, modificar la rama offline, desplegar VPS, afirmar que APK/AAB están firmados sin resultados, activar suscripciones/créditos o análisis APK reales.
