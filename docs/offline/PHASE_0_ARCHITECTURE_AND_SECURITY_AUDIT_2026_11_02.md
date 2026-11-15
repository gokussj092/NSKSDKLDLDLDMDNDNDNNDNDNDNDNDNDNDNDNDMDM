# SP-DECODE Offline — Fase 0: auditoría de arquitectura y seguridad

**Fecha:** 2026-11-02  
**Rama:** feat/version-offline-apk  
**Commit baseline:** 848f63066908269e47734bd117fcb06048ec2579  
**Tree baseline:** 8dd04124112b4e1fe83911273a91f012ed78c36d  
**Estado:** inventario de fuentes y documentación realizado; pruebas ejecutables de regresión pendientes.

## 1. Alcance aprobado

- Edición Android estrictamente offline: descifrado de archivos y protocolos de texto sin VPS ni API Cloud.
- Todo algoritmo de descifrado, construcción criptográfica de formatos, serialización sensible y exportación de configuraciones se implementará en **C++**. Kotlin/Compose estará limitado a UI, navegación, Android SAF, ciclo de vida, presentación y adaptación mínima al sistema Android.
- NPV Tunnel: generar localmente en C++ la Public Key y la Private Key y conservar internamente el material necesario de modo protegido. **No incluir funcionalidades de importación ni exportación de claves privadas.** No mezclar estas identidades con HPKE Cloud.
- **Catálogo Server VPN excluido**: sin lista remota de proveedores, descargas, actualizaciones ni controles de servidor. Archivos individuales como .solid podrán evaluarse únicamente como descifrado local, sin integrar catálogos de proveedores.
- Conservar interfaz AMOLED, 14 idiomas, historial cifrado, formatos offline compatibles y exportación JSON/Unlocked para variantes realmente comprobadas.
- No añadir análisis de APK por créditos, suscripción ni funciones comerciales planificadas para la edición Cloud 1.1.26. No tocar main, Play Store, VPS ni producción.
- No lanzar workflows de GitHub Actions ni compilar APK durante esta auditoría documental.

## 2. Inventario estructural confirmado

El árbol Git del snapshot, sin truncamiento, contiene **2.740 entradas**, de ellas **2.444 archivos**. Dentro de android/app/src/main/java/com/ghostdeveloper/spdecode/parity/ hay **107 archivos Kotlin** que incluyen motores, primitivas, perfiles, parsers, catálogos y enrutadores. El número de archivos no equivale a 107 motores independientes.

android/app/src/main/cpp/ tiene **20 archivos**, incluyendo CMakeLists.txt y componentes Cloud HPKE, JNI, Keystore, seguridad, sesión, integridad y catálogo. El target real es **v7q3** y su biblioteca Android **libv7q3.so**; usa C++17 y Mbed TLS 3.6.7 fijado. No contiene una migración completa de los motores de archivos Kotlin.

android/app/src/main/assets/ tiene **13 archivos fuente**. El catálogo decoder_catalog.json registra las familias siguientes:

| Familia | Rutas registradas | Implementación base |
|---|---:|---|
| A — heredados | 61 | Motores Android Kotlin |
| B — genéricos | 81 | GenericVpnPort.kt / perfiles Kotlin |
| C — Ultra/Sandok | 41 | UltraSandokPort.kt |
| D — RENZ | 16 | RenzPort.kt |
| E — especiales | 27 | SpecialE1/E2/E3Port.kt |
| F — independientes | 13 | IndependentF1/F2Port.kt |
| **Total A–F** | **239** | **No equivalente a C++ certificado** |

Los contadores del registro son androidNativePortSuffixes=239, androidPendingNativeSuffixes=0, syntheticLinuxCoveredSuffixes=238 y **androidCertifiedSuffixes=0**. La palabra “native” en este registro significa portado a Android Kotlin, no implementado en C++. Las cifras no certifican archivos reales actuales ni exportaciones compatibles. Los protocolos de texto G se cuentan aparte.

Se identificaron **63 archivos androidTest** y **6 cloudAndroidTest**, más pruebas host para formatos y NPVS. No se ejecutaron dichas pruebas en esta fase, por lo que no se afirman resultados PASS.

En el baseline, android/app/build.gradle.kts declara **versionName 1.1.25** y **versionCode 40**. La rama de origen fix/http-jireh-current-method tiene un commit posterior a la creación de la rama Offline; cualquier integración de ese commit deberá evaluarse antes de sincronizar.

## 3. Arquitectura Gradle y aislamiento pendiente

La variable SPDECODE_CLOUD_API_BASE_URL determina enableCloud. La tarea prepareCloudOnlySources excluye parity/** (salvo metadatos de catálogo de interfaz), usa fuentes Android Cloud y src/cloud/AndroidManifest.xml. Sin Cloud se conservan los motores Kotlin legados y prepareSecureAssetVault.

**El manifiesto principal android/app/src/main/AndroidManifest.xml aún declara android.permission.INTERNET.** El build legado sin Cloud no puede considerarse automáticamente una edición Offline de distribución. En Fase 1 debe crearse una variante explícita con manifiesto fusionado sin INTERNET y sin dependencias de cliente Cloud o Server VPN, preservando por separado la compilación Release Cloud.

Puntos de entrada y dependencias:
- MainActivity.kt, SpDecodeApp.kt y FunctionalSettingsPanel.kt requieren un mapa de navegación y llamadas al backend.
- AndroidOfflineDecoderRouter.kt hace dispatch a motores Kotlin por sufijo y familia.
- CompatibleExportArtifact.kt recibe bytes preparados por servidor y no implementa un exportador Offline.
- NpvsIdentityVault.kt utiliza Android Keystore, pero el mecanismo Cloud actual no es el generador local C++ solicitado.

## 4. Recursos criptográficos, vault y JSON

prepareSecureAssetVault protege con SPV1 y AES-256-GCM:
- embedded_kotlin_profiles.json
- flex_f_profiles.json
- generic_b_profiles.json
- hc_source_keys.json
- http_tweak_source_tables.json
- legacy_epro_npv2_keys.json
- npvs_v5_tables.b85
- nur_tunnel_server_endpoint.json
- npv_whitebox.bin (opcional, generado en build)
- renz_d_profiles.json
- ultra_c_profiles.json

El cifrado actual genera una clave por build y una clase VaultBuildKey.kt con shares XOR; SecureAssetVault.kt ejecuta el descifrado en Kotlin. Esta envoltura evita lectura trivial del ZIP, pero **la clave está dentro de la APK y es recuperable por ingeniería inversa**. No constituye una frontera absoluta de secreto.

También deben revisarse decoder_catalog.json, legacy_module_english_labels.json, nodehat_original_layout.json y archivos JSON de salida generados. El requisito para la edición Offline es no empaquetar perfiles, tablas ni JSON sensibles como recursos legibles, ni persistirlos en claro en historial, caché o logs. El APK final debe auditarse en DEX, recursos y ELF, no solo código fuente.

**Límite técnico:** cuando un usuario elija ver o exportar un JSON descifrado, habrá una representación legible temporal en memoria o en el documento de salida. La interfaz JNI debe minimizar su permanencia mediante handles opacos, buffers acotados y limpieza; C++ u ofuscación no puede garantizar confidencialidad frente a control total del proceso.

## 5. NPV Tunnel y gestión de claves

Los documentos NPVS_RECIPIENT_IDENTITIES.md y NPVS_PROTECTED_FILES.md describen v5/v6 y modalidades de clave de aplicación, contraseña y destinatario ECDH P-256. Migrar a C++ con comprobaciones de firmas, autenticación AEAD, metadatos, inventario, HKDF y rechazo sin fallback ante claves erróneas. El generador P-256 C++ creará y gestionará localmente las claves necesarias, con almacenamiento protegido mediante Android Keystore cuando proceda.

**No habrá función de importar o exportar claves privadas**, ni envío de esas privadas al servidor. Nunca incluir la clave privada HPKE del VPS en esta edición.

## 6. Riesgos bloqueantes

| ID | Riesgo | Prioridad | Criterio de cierre |
|---|---|---|---|
| O-01 | Manifiesto legado con INTERNET | Crítica | APK final sin permiso de red ni llamadas a API |
| O-02 | Gradle Release y UI acoplados a Cloud | Crítica | Variante Offline separada y builds independientes |
| O-03 | 239 rutas Kotlin, 0 certificadas según registro | Crítica | Pruebas por versión y referencia real |
| O-04 | Clave del vault recuperable dentro del APK | Alta | Auditoría APK/DEX/ELF y diseño de materiales nativos |
| O-05 | JSON descifrado cruza a la UI | Alta | JNI con buffers/handles limitados y consentimiento de exportación |
| O-06 | NPVS v5/v6 con modos diferentes | Crítica | P-256, firmas, AEAD y credenciales probadas |
| O-07 | Unlocked dependiente del backend | Alta | Exportador C++ con reimportación probada |
| O-08 | Server VPN excluido | Alta | Sin clases, pantallas, recursos ni endpoints en APK Offline |
| O-09 | Faltan métricas de baseline | Crítica | Ejecutar regresiones y corpus privado autorizado |

## 7. Checklist de Fase 0

- [x] Rama, commit y árbol base identificados.
- [x] Inventario estructural de motores, assets, CMake, pruebas y variantes.
- [x] Distinción entre motor Android Kotlin y motor C++ establecida.
- [x] Alcance, exclusiones y riesgos documentados.
- [x] Matriz de migración y criterios de aprobación redactados.
- [ ] Obtener corpus privado de fixtures autorizados por versión y modo, sin guardar secretos en GitHub.
- [ ] Ejecutar baseline reproducible host y Android y documentar paridad.
- [ ] Probar exportaciones reales en aplicaciones de destino.
- [ ] Evaluar por separado el commit posterior de la rama madre, sin traerlo automáticamente.

**Conclusión:** inventario documental terminado; **Fase 0 no está cerrada en paridad dinámica**. No se ha alterado el código de aplicación, un APK, main, VPS, Play Console ni workflows.

## 8. Referencias en el repositorio

- android/app/build.gradle.kts
- android/app/src/main/AndroidManifest.xml
- android/app/src/main/cpp/CMakeLists.txt
- android/app/src/main/assets/decoder_catalog.json
- android/app/src/main/java/com/ghostdeveloper/spdecode/parity/AndroidOfflineDecoderRouter.kt
- android/app/src/main/java/com/ghostdeveloper/spdecode/parity/SecureAssetVault.kt
- android/app/src/main/java/com/ghostdeveloper/spdecode/parity/NpvsPort.kt
- android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/NpvsIdentityVault.kt
- android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CompatibleExportArtifact.kt
- docs/android/PHASE_H_PRODUCTION_AUDIT.md
- docs/android/PHASE_S_SECURE_ASSET_VAULT.md
- docs/NATIVE_HPKE_CPP_MIGRATION.md
- docs/SECURITY_CXX_BOUNDARY_AND_DEPENDENCIES_2026_10_30.md
- docs/NPVS_RECIPIENT_IDENTITIES.md
- docs/NPVS_PROTECTED_FILES.md
- docs/cloud/COMPATIBLE_EXPORT_VARIANT_COVERAGE_2026_10_31.md
