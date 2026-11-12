# SP-DECODE Offline — Fase 0: matriz de migración, pruebas y certificación

**Rama:** feat/version-offline-apk · **Baseline:** 848f630 · **Fecha:** 2026-11-02.

La matriz refleja rutas actuales y riesgos. Ninguna de las 239 rutas históricas está certificada en C++ en este snapshot. El inventario exacto por sufijo debe derivarse de android/app/src/main/assets/decoder_catalog.json, no de un recuento supuesto.

## 1. Familias y fuentes

| Grupo | Sufijos | Código actual | Referencia de QA | Acción C++ | Estado |
|---|---:|---|---|---|---|
| A — Legados Android | 61 | parity/*Port.kt, LegacyPortPrimitives.kt | docs/android/DECODER_MATRIX.md, tests/test_android_a23_*.py | Migrar algoritmo por formato y versión | Inventariado |
| B — Genéricos | 81 | GenericVpnPort.kt, GenericProfileStore.kt | tests/test_android_b_generic_parity.py | Cripto, tablas y parser C++ | Inventariado |
| C — Ultra/Sandok | 41 | UltraSandokPort.kt, UltraProfileStore.kt | tests/test_android_c_ultra_parity.py | Algoritmos y perfiles C++ | Inventariado |
| D — RENZ | 16 | RenzPort.kt, RenzProfileStore.kt | tests/test_android_d_renz_parity.py | Derivación y formato C++ | Inventariado |
| E — Especiales | 27 | SpecialCrypto.kt, SpecialE1/E2/E3Port.kt | tests/test_android_e_special_parity.py | Rutas y variantes C++ | Inventariado |
| F — Independientes | 13 | IndependentCrypto.kt, IndependentF1/F2Port.kt, IzphNativePort.kt | tests/test_android_f_independent_parity.py | Motores C++ | Inventariado |
| G — Texto y enlaces | Aparte, no sumar a 239 | TextProtocolDecoder.kt, TextPhaseGPort.kt | tests/test_android_g_text_parity.py | Reconocimiento y descifrado nativo | Inventariado |
| **Total A–F** | **239** | **Android Kotlin** | **0 certificados según registro** | **Migración C++ pendiente** | **Pendiente** |

## 2. Componentes de riesgo especial

| Área | Fuentes actuales | Validación futura |
|---|---|---|
| Enrutador de formatos | AndroidOfflineDecoderRouter.kt, AndroidDecoderCatalog.kt | Ningún formato anunciado usa cripto Kotlin; selección exacta por sufijo/versión/credenciales |
| HTTP Custom | HcPort.kt, HcHccfgPort.kt | Variantes/contraseñas/HWID con compatibilidad explícita |
| HTTP Injector | EhiPort.kt, EhilPort.kt | Prueba de descifrado y exportación con muestras independientes |
| Dark Tunnel | DarkPort.kt, protocolos dt:// | Sin banners insertados; prueba de reimportación |
| NPV antiguos | Npv2Port.kt, Npv4Port.kt, NpvtPort.kt | Vectores de versiones reales sin fallback de claves |
| NPVS v5/v6 | NpvsPort.kt, NpvsPrimitives.kt, NpvsEnvelope.kt, NpvsFields.kt, NpvsJson.kt, NpvsSignature.kt, NpvsWhitebox*.kt | app-key/password/recipient por separado; firma y AEAD obligatorios |
| Claves NPV | cloud/NpvsIdentityVault.kt, docs/NPVS_RECIPIENT_IDENTITIES.md | Generar P-256 en C++, almacenar privada localmente cifrada; **sin importación ni exportación** |
| TLS/e-V2Ray | TlsReferencePort.kt, V2RayReferencePort.kt | Compatibilidad por versión/metadata |
| Archivo .solid | NurTunnelPort.kt | Descifrado únicamente local; no integrar Server VPN |
| Recursos JSON | SecureAssetVault.kt, assets/, build.gradle.kts | Sin JSON sensible legible en APK final; parseo autenticado nativo |
| Unlocked | cloud/CompatibleExportArtifact.kt, pruebas compatible_export | Generación local C++ y certificación con app de destino |
| UI/historial | MainActivity.kt, SpDecodeApp.kt, SecureDecodeHistory.kt | Kotlin sin algoritmos de descifrado; historial cifrado y SAF |
| Build | AndroidManifest.xml, build.gradle.kts, src/cloud | APK Offline sin INTERNET ni cliente Cloud |
| Catálogo Server VPN | ServerVpnDirectory.kt, cloud/ServerVpnCatalogRepository.kt | **EXCLUIDO por decisión del propietario** |

## 3. Requisitos para declarar un formato VERIFICADO

1. Identificar aplicación emisora, versión/build, extensión/protocolo, modalidad (normal/bloqueado/password/HWID/recipient) y límites de entrada.
2. Conservar un fixture **autorizado** positivo y uno o más negativos: truncado, firma/tag manipulado, clave incorrecta, tamaño fuera de rango y entradas maliciosas.
3. Comparar campo por campo el resultado del motor Python/Node existente, Kotlin baseline y C++ Offline. Un JSON sintácticamente válido por sí solo no demuestra paridad.
4. Probar en Android ARM64 físico, modo avión, importación SAF, rendimiento, cancelación, historial y estabilidad.
5. Para Unlocked, comprobar que la aplicación de destino importa y permite editar la configuración; no basta un round-trip criptográfico sintético.
6. Auditar APK empaquetado para excluir perfiles/tablas/JSON sensibles en claro; asegurar que las claves privadas NPV permanecen locales y no existe import/export de claves privadas.
7. Ante errores criptográficos de autenticación: fallo terminal, sin probar otra familia ni enviar la operación a Cloud.

Estados de avance propuestos: INVENTORIED → BASELINE_TESTED → CXX_MIGRATED → DEVICE_TESTED → VENDOR_VERIFIED. Cuando corresponda: UNSUPPORTED o MAINTENANCE. Los contadores de rutas no sustituyen evidencia por versión.

## 4. Pruebas y corpus ya previstos (no ejecutados en este turno)

- tests/test_android_a23_*.py y tests/test_android_a23_goldens.py
- tests/test_android_b_generic_parity.py
- tests/test_android_c_ultra_parity.py
- tests/test_android_d_renz_parity.py
- tests/test_android_e_special_parity.py
- tests/test_android_f_independent_parity.py
- tests/test_android_g_text_parity.py
- tests/test_android_s_vault_audit.py
- tests/test_npvs_v5.py, tests/test_npvs_protected.py, tests/test_npvs_identity.py
- tests/test_compatible_export.py, tests/test_compatible_export_integration.py
- tests/native_*.cpp y tests/native_jni_contract.py

La existencia de rutas no significa que se hayan ejecutado ni aprobado pruebas en este snapshot. Los archivos reales y los secretos del usuario no deben subirse al repositorio.

## 5. Checklist de cierre Fase 0

- [x] Arquitectura, branch y commit auditados.
- [x] Exclusiones firmes: **sin Server VPN**, **sin import/export de claves NPV**.
- [x] 239 rutas A–F identificadas y texto G tratado por separado.
- [x] Motores Kotlin, vault, JNI/C++, Gradle, permisos y dependencias Cloud inventariados.
- [x] Riesgos, variantes de prueba y criterios de paridad documentados.
- [ ] Ejecutar baseline host/Android y guardar resultados sanitizados.
- [ ] Preparar corpus privado autorizado por aplicación emisora y versión.
- [ ] Certificar exportación Unlocked e interoperabilidad de versiones reales.
- [ ] Revisar posibles cambios posteriores de fix/http-jireh-current-method antes de sincronizar.

**Estado:** auditoría documental Fase 0 finalizada; **gate de pruebas funcionales pendiente**. No se modificó código funcional, main, VPS, Play ni APK distribuida.
