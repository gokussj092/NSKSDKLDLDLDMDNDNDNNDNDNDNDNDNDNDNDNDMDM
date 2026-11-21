# Android 17: rechazo del firmante híbrido al abrir la distribución de Play

Fecha: 2026-11-21. Rama: `ci/unity-ads-online-qa`. Base: `e994a0f09ce2be27c3c89c24b3abe5c7d451e93d` (1.1.31/46). Corrección: 1.1.32/47.

Estado: incompatibilidad del verificador nativo comprobada en código y reproducida mediante JNI real con resultados sintéticos de PackageManager. Pendiente confirmar el arranque desde Google Play en un Android 17 afectado. No se dispone de logcat ni del APK servido por Play a ese dispositivo; no atribuirle todavía todos los cierres posibles a esta causa.

## Qué estaba mal

`verifyReleaseSigner` consultaba `SigningInfo.getApkContentsSigners()` y exigía que cada certificado ACTUAL coincidiera con la clave de subida o con el certificado clásico de Play. `MainActivity.onCreate` y `onResume` ejecutaban `finishAndRemoveTask()` si esa comparación fallaba. Esa salida voluntaria puede no aparecer como crash en Play Vitals.

El informe previo afirmaba incorrectamente que los certificados híbridos no eran firmas de la app. Google documenta que Play utiliza un par de claves híbridas para Android 17+ y una clave clásica diferente para Android 16 e inferiores. Android 17 incorpora la clave clásica híbrida al historial y trata la clave PQC como identidad actual. Tener embebida la huella clásica correcta no garantiza que coincida con el certificado actual en Android 17.

Esto explica la combinación reportada: el APK de Telegram conserva la firma de subida permitida; Play en Android anteriores presenta la clásica permitida; Play con v3.2 en Android 17 presenta la identidad híbrida que el código antiguo rechaza.

Fuentes oficiales consultadas el 2026-11-21:

- [Play App Signing: claves híbridas, versiones Android y registro con proveedores API](https://support.google.com/googleplay/android-developer/answer/9842756).
- [AOSP: APK Signature Scheme v3.2 e historial de rotación implícita](https://source.android.com/docs/security/features/apksigning/v3-2).
- [PackageManager.hasSigningCertificate: comprobación de firma e historial de rotación](https://developer.android.com/reference/android/content/pm/PackageManager#hasSigningCertificate(java.lang.String,%20byte[],%20int)).

## Contrato corregido

La decisión permanece en C++/JNI. La identidad del paquete, la prohibición de release depurable y los controles existentes se conservan.

1. Un firmante actual que coincide exactamente con una huella permitida sigue siendo válido.
2. Para un único firmante no reconocido en API 28+, se consulta `PackageManager.hasSigningCertificate(packageName, playAnchorSha256Bytes, CERT_INPUT_SHA256)`.
3. Solo se acepta si el sistema confirma que la app instalada pertenece al historial de firma de la clave clásica de Play ya fijada. Se utiliza la prueba de rotación validada por Android; no se acepta un historial aportado por la app ni se usa el nombre del instalador como prueba.
4. Los APK con varios firmantes siguen exigiendo que TODOS los firmantes actuales estén fijados. Un firmante permitido junto a uno desconocido no concede confianza. La nueva excepción de rotación no se aplica al historial de la clave de subida.
5. Huellas malformadas, historial ajeno, errores de PackageManager y contexto inválido siguen denegando acceso.

Las dos huellas de BuildConfig se mantienen. No hace falta sustituir la clave clásica por la PQC ni ampliar indiscriminadamente la lista permitida: la clave clásica sirve como ancla del historial autenticado. No se desactiva la verificación en Android 17.

La app muestra un diálogo de rechazo con `RELEASE_SIGNER_REJECTED` en los 14 idiomas en lugar de desaparecer inmediatamente. No inicia la interfaz funcional, anuncios por cambios de foco ni nuevas importaciones mientras está bloqueada. No se introducen registros logcat ni datos privados.

## Pruebas reproducibles

Requisitos: JDK 17+, g++, make, Python 3 y acceso al archivo oficial Mbed TLS 3.6.7 cuyo SHA-256 comprueba el script.

```sh
bash scripts/ci/run_release_signer_jni.sh
python3 tests/native_jni_contract.py
python3 scripts/ci/current_android_contracts.py --check
python3 scripts/ci/verify_aab_locales.py --source-only
python3 scripts/android_s3_security_audit.py
python3 scripts/android_s4_provisioning_audit.py
python3 -m unittest tests.test_android_play_compatibility tests.test_android_play_update_artifact_contract tests.test_android_unity_release_contract tests.test_cloud_c8_user_errors tests.test_android_production_workflow.AndroidProductionWorkflowTest.test_production_signer_pin_is_derived_from_permanent_keystore -q
```

Evidencia local:

| Comprobación | Resultado y alcance |
| --- | --- |
| Verificador original de `e994a0f` con el nuevo arnés JNI | FALLA en `Android 17 verified Play-to-PQC rotation rejected`, reproduciendo el defecto con historial sintético |
| Verificador corregido, JNI real, `-Xcheck:jni` | PASS, 32 casos; sin advertencias JNI |
| Firma de subida/clásica/ajena en API 26, 28, 33, 36 y 37 | Acepta las permitidas y rechaza las ajenas |
| Rotación Play→clásica híbrida→PQC, certificado sin ancla, varios firmantes, release depurable, excepción del sistema | Resultados esperados de aceptación/rechazo |
| Transporte JNI existente | PASS: registro real, UTF-8, cabeceras de prueba, destino, presupuestos y limpieza de excepciones |
| Suites focalizadas de Android/Play | PASS, 50 pruebas |
| Descriptores JNI | PASS, 28 métodos |
| Auditorías de seguridad S.3/S.4 y 14 idiomas | PASS |

La batería ampliada de 58 pruebas incluye tres fallos y un error preexistentes, reproducidos también en el checkout limpio de `e994a0f`: supuesto de workflow de main, metadatos antiguos de publicación, ruta en AppAnalysisClient y archivo FeedbackScreen.kt eliminado. No se modificaron ni deshabilitaron esas comprobaciones para ocultarlos.

Estos tests ejecutan la biblioteca C++ de producción contra dobles Java del framework: NO verifican un bloque v3.2 real ni una instalación de Play. La validación de la prueba criptográfica de rotación la realiza Android en producción. La compilación Android/NDK de las cuatro ABI y R8 se verifican por separado en el workflow del AAB firmado.

## Entrega y aceptación en dispositivo

El workflow `android-online-play-aab-signed.yml` conserva la keystore persistente de GitHub Secrets, R8, Unity Ads y los controles de alineación y locales; ejecuta además el arnés del firmante antes de compilar. Produce un AAB 1.1.32/47 para revisión y carga manual. No publica automáticamente en Play. Se conserva el estado previo de Play In-App Updates desactivado para no mezclar otra modificación con esta reparación.

Para validar el incidente hay que cargar el AAB corregido en la prueba cerrada y actualizar DESDE PLAY en los teléfonos Android 17 afectados. Un APK generado localmente, aunque derive del AAB, conserva otra firma y no valida esta diferencia.

- Abrir y reabrir desde el icono y desde Play; confirmar que llega a Inicio.
- Pasar a segundo plano y volver; el control también corre en onResume.
- Conservar una comprobación de arranque en Android 14/16 y del APK directo.
- Si se muestra `RELEASE_SIGNER_REJECTED`, conservar versión, API y certificados actual/históricos de la instalación afectada; no quitar protección para forzar la apertura.
- Si hay otro cierre, capturar logcat durante el arranque para distinguir excepción Java, fallo nativo o terminación voluntaria.

El inicio de sesión y la admisión Cloud son verificaciones independientes del cierre: la documentación oficial exige registrar también los certificados híbridos con proveedores API. Revisar sus listas de huellas si fallan esas operaciones después de abrir, sin revertir código de login ni eludir Play Integrity/atestación. Las huellas híbridas suministradas por el propietario son públicas: clásica `f3f2561edb2e0d0d9a81be52da4e30c87dc837231432f65092f0d57adfcf3642`, PQC `472166b71a72cc28d5303ddd5d767f9baba4547d9fefbe94fa6d5f74971950bf`; volver a contrastarlas con Play Console antes de configurar servicios.

Alcance: arranque local, UI de rechazo, pruebas y build Android. No cambia ningún contrato HPKE/V2, operación 1/2/5/7/10/12, descifrador, catálogo, servidor ni clave privada. La aceptación en el dispositivo afectado sigue siendo necesaria antes de declarar la incidencia resuelta.
