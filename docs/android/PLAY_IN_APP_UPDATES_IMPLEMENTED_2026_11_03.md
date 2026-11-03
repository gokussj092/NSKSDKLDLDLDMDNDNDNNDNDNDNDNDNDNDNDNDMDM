# SP-DECODE — Play In-App Updates, AAB only (2026-11-03)

## Alcance y cambio de estado
Implementación fuente en la rama `fix/http-jireh-current-method`. **No desplegado, no publicado, pendiente de compilación CI y prueba real por Google Play.** No modificar `main`.
La verificación del usuario en VPS confirmó OAuth Android Publisher OK, `com.ghostdeveloper.spdecode`, pistas production/beta/alpha/internal, y eliminación del edit temporal. La cuenta actual de Play Integrity sirve para autenticación Android Publisher, pero NO se empaca en Android.
No se incorporó publicación automática ni nueva credencial.

## Distribución estricta
* Telegram: `gradle :app:assembleRelease` con Cloud, sin Play updater, sin biblioteca `app-update`, sin asset marcador. Se mantienen avisos de novedades/Telegram.
* Play: `gradle -PspdecodePlayAab=true :app:bundleRelease` (invocación distinta), incluye `app-update:2.1.0`, `lifecycle-runtime-compose` y `PlayInAppUpdateHost`. AAB conserva paquete y firma habitual. **Nunca ejecutar ambos targets en la misma invocación con la bandera Play**.
* `play-beta-artifacts.yml` compila primero APK, después AAB y ejecuta `scripts/ci/verify_play_update_artifacts.py`; no publica a Play ni a VPS.
* UI C0 original permanece intacta; el host se inyecta solo en copias Cloud generadas y nunca compila para Telegram.
* No guardar claves ni endpoints privados en Android o el repositorio.

## Comportamiento
* Solo se consulta `AppUpdateManager.appUpdateInfo`; Cloud/versionCode no autoriza un flujo Play.
* 0–3: diálogo normal AMOLED gris grafito/negro, dos acciones Actualizar ahora/Más tarde, y flujo Flexible de Google. Pausa de 24 horas por versionCode si el usuario pospone.
* 4–5: flujo Immediate **nativo de Google Play**, si `isUpdateTypeAllowed(IMMEDIATE)`. No es posible cambiar el diseño/título de Google; si Immediate no está permitido, se puede ofrecer Flexible cuando Google lo permite.
* Si la persona cancela el flujo: enfriamiento de una hora por versionCode, sin bloqueo artificial.
* El host recupera `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS`, escucha `DOWNLOADED`, ofrece Reiniciar e instalar (llama `completeUpdate`) y libera el listener al salir.
* Se difieren avisos mientras el usuario descifra, está en consentimiento legal, primer uso, mensajes de error u otros diálogos. Play y Telegram no muestran actualizaciones a la vez.
* Cadena local para 14 idiomas disponibles, según idioma seleccionado en la app o del sistema. Sin barra de progreso duplicada. El código de versión mostrado viene de Play; no se inventa la versión semántica.

## QA bloqueante antes de Play
1. `python3 -m unittest tests.test_android_play_update_artifact_contract -v`.
2. En CI con firma permanente y Cloud, construir ambas distribuciones separadamente. Exigir integridad de AAB, APK, 14 locales, R8, 16KiB y `verify_play_update_artifacts.py`.
3. Dispositivo con app instalada desde Play, test account inscrita, versión instalada menor, nuevo versionCode visible en la misma pista. Para probar actualización de 1.1.26 build 41 es necesaria una posterior 42 o mayor.
4. Probar: sin actualización; Flexible -> descarga -> reinicio; cancelar y volver; Immediate cuando `updatePriority>=4` y Google lo permite; interrupción/reanudación; instalación externa Telegram; rotación/14 idiomas y prioridades.
5. Probar que mantener la firma del AAB de subida y la App Signing certificate de Play no rompe `ReleaseIntegrity`.
6. Solo tras CI exitoso y validación física, solicitar autorización específica del propietario para publicar. Los workflows actuales no llaman Android Publisher para publicar ni utilizan la cuenta de servicio.

## Referencias
* `docs/android/PLAY_IN_APP_UPDATES_PENDING_2026_11_02.md` (decisiones originales).
* https://developer.android.com/guide/playcore/in-app-updates/kotlin-java
* https://developer.android.com/guide/playcore/in-app-updates/test
