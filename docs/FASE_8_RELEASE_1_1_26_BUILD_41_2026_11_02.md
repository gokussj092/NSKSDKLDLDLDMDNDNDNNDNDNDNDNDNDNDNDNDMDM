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

## PR de validación
- PR borrador: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/pull/109
- Rama fuente: `fix/http-jireh-current-method`, destino `main`.
- Este cambio documental adicional se confirma **sin `[skip ci]`** para que el evento synchronize del PR ejecute las validaciones. No realiza ninguna fusión ni publicación.
- Los resultados de los checks deben leerse de GitHub Actions; hasta entonces no atribuirles estado de aprobación.

## Registro de correcciones detectadas por CI (no evidencia de GO)

Durante la primera ejecución del PR #109 se observaron y corrigieron estos puntos en la **rama de desarrollo**:
- El nuevo formato `.hexcm` de Hex Tunnel se separa del inventario C0 histórico de 239 rutas sin desregistrarlo.
- El bloqueo de hash de nueve fuentes UI se conserva; las modificaciones aprobadas de tres fuentes tienen hashes exactos en `docs/cloud/C0_UI_APPROVED_1_1_26.json` sin modificar el baseline original.
- Se restablece el contrato `SERVER_VPN_METHODS`; el catálogo incluye los campos aditivos `methodRevision` y `maintenance` por proveedor, con bloqueo de descifrado en mantenimiento.
- El generador de muestras Threefish de IZPH invierte correctamente el orden MIX/permutación; no se altera el motor real.
- Se actualizan las pruebas ancladas al catálogo 60/61 y a los 254/255 formatos antiguos para el piso 62 y 256 formatos, conservando las rutas históricas.
- La operación 18 de sugerencias sigue siendo **válida y autenticada**, no se convierte en desconocida para satisfacer un test antiguo.
- El consentimiento del operador para la publicación de 1.1.26 **no** está otorgado. `release/android-readiness.json` continúa en NO-GO.
- El empaquetado manual de Play en `.github/workflows/play-beta-artifacts.yml` queda apuntando a 1.1.26/build41; no fue lanzado. No hay aplicación QA distribuible.

**El PR no debe fusionarse ni publicarse hasta que los workflows contra el HEAD posterior a estas correcciones terminen y se revisen sus fallos, además de pasar validación física, firma permanente, VPS y el resto de evidencias de release.**

## Validación posterior a correcciones C0–C7

La ejecución de integración `41534170991` **aprobó** la auditoría C0 sobre el commit `8e4e8bae`. Los otros trabajos de ese mismo commit mostraron más aserciones heredadas de los cambios previos de navegación, Cloud y catálogo; en la rama se ajustaron únicamente comprobaciones sustentadas por la implementación actual, conservando el motor, autenticación y los gates de publicación.

- La interfaz principal ahora abre HTTP Injector Cloud a través de `decodeOnlineReference`, no con el nombre de función anterior. Los tests C4 reflejan el flujo unificado y tres hashes UI aprobados; los otros seis siguen bloqueados por la línea base original.
- En C5 se comprueba el retorno del preanálisis HC por la función actual `decodeFile("hc",bytes,onCompatibleExport=...)`.
- Los tests de metadatos se adaptan a los campos aditivos `methodRevision`/`maintenance`; los contadores de formatos reflejan `.hexcm`.
- Los diagnósticos V2 se presentan en el componente independiente `AdminV2Diagnostics`. La política de expiración se obtiene del proveedor de políticas, no se parsea en el verificador local.
- La operación V2 18 sigue requiriendo sesión autenticada; se conserva el error 401 para uso sin bearer.

**Decisión actual:** NO-GO. Sin evidencia nueva de artefactos firmados ni prueba física. El nuevo HEAD exige reejecutar los gates antes de considerar que la fase 8 está completada.

## Correcciones en curso — validación nativa, compilación y regresiones (2026-11-02)

**Política estricta:** endpoints de transporte/API Cloud y validación criptográfica permanecen en **libv7q3.so**; se añade prueba `tests/test_android_native_trust_boundary.py` para impedir direcciones privadas, rutas API y secretos backend en Kotlin. Se conserva Android Keystore/Google Play SDK como puente de plataforma sin trasladar la autoridad de compra al cliente. El módulo comercial permanece deshabilitado y sin creditar saldo; ninguna compra puede considerarse validada sin verificación transaccional del backend.

- Kotlin: `FeedbackDraft` deja de ser `internal` en firmas públicas, y Nube global enlaza el callback de una referencia al selector automático existente.
- JNI host: prueba JVM actualizada a los **27** métodos reales registrados por `JNI_OnLoad`, prueba HTTP sobre bytes opacos y stub de Context *solo* para host. Gradle y las fuentes Android de producción no reciben el stub.
- Catálogo: pruebas conservan el conjunto original C0 de 239 excluyendo `hexcm`, y comprueban las 256 rutas de archivo del worker extendido sin quitar ningún método.
- Ningún release firmado, producto de compra, despliegue o merge se activa por estas correcciones.

**Se ejecuta un nuevo ciclo CI en este commit para identificar regresiones todavía existentes. El estado se mantiene NO-GO hasta evidencia completa de APK/AAB release, JNI, R8 y hardware real.**

## Corrección de compilación Cloud y regresión aislada — siguiente ronda

- Las fuentes normales del formulario usan `onDecodeCloud(String)`; el panel global Cloud generado usa `onDecodeCloud(String,String)`. `prepareCloudHistoryUiSource` adapta **solo** `MainActivity.kt` generada a la segunda firma, conservando la fuente y el hash UI de la aplicación principal.
- Verificada por CI anterior la inscripción real de los 27 métodos JNI y el transporte binario HTTP de host. Ese CI encontró después una incompatibilidad Kotlin de callback; corregida en el generador Gradle, que debe validarse de nuevo.
- Los tests reflejan el catálogo 256/30 overlays y preservan la base 239. Se actualizó el cifrador independiente sintético Threefish de IZPH (no el decoder real).
- La verificación de los productos de pago y la contabilidad son siempre **del servidor**: una aplicación Android no puede autoacreditar ni verificar compras definitivamente. Google Play Billing requiere el SDK Android como interfaz de plataforma; cualquier futura política de validación cliente sensible será nativa y la autorización definitiva server-side. No existe un flujo de cobro activo.
- No hay rutas API, secretos backend, claves HPKE ni certificados privados nuevos en Kotlin. `libv7q3.so` conserva origen/rutas y enlace de criptografía nativa. Los resultados visibles, controles Android y el token de Play, cuando exista el SDK, pueden necesitar una interfaz JNI mínima; no se considerarán secretos del servidor ni fuente de autoridad.
- **NO-GO** hasta validar los workflows y el APK/AAB firmados. Sin fusión, sin QA distribuible y sin despliegue.

## Estado de revisión CI de compilación (2026-11-02; cambios pendientes de certificación final)

Sobre `6318a1db6be0ea8c630d6589b0103ee9946de580`:
- Aprobados C0, C1, C2, C3, C4, C5, C6, C7 y seguridad de hardware (9 de 12 workflows).
- El job de Python de `Validate SP-DECODE` aprobó todos los tests; el job instrumentado Android falló en **compilación de pruebas**, no por una regresión confirmada del APK: tres archivos `androidTest` tenían imports Compose inválidos (`assertExists`, `assertDoesNotExist`, `performScrollTo`). Se corrigen eliminando imports de métodos existentes en `SemanticsNodeInteraction` e importando la acción de scroll.
- C8 ya tiene verdes los dos jobs de VPS/docker; la compilación APK/AAB CI-only y V2 aún estaban en curso en el momento de esa revisión.
- Se mantiene validación fail-closed y prohibición de distribución/pago hasta completar todos los gates y firma permanente.

**Esta actualización desencadena CI sobre la revisión actual posterior a las tres correcciones de instrumentación**. La versión oficial sigue en estado **NO-GO**.
