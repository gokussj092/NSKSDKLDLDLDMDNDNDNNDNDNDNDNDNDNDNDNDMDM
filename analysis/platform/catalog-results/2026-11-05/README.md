# Evidencia de plataforma: catálogo y resultados

Estado: `HOST_CHECKS_PASSED_DEVICE_GATES_PENDING`. No es la certificación de un método VPN ni de un despliegue. XXPICore tiene su propio expediente en `analysis/pro.xxpicore.tunnel/118/`.

- Diseño/implementación y límites: `docs/cloud/CATALOG_RESULTS_IMPLEMENTATION_2026_11_05.md`.
- Runner real: `scripts/qa/catalog_results_host.py`.
- Parser PSI y dependencias SHA-256 fijadas: `scripts/qa/kotlin_syntax.py`, `scripts/qa/catalog-results-dependencies.json`.
- Fixture sintética del publicador real: `scripts/qa/catalog_fixture.mjs`.
- Recursos de 14 idiomas: `scripts/qa/catalog_result_strings.py`.
- Native/JNI: `tests/native/result_engine_test.cpp`, `tests/native/result_engine_jni/NativeResultEngine.java`.
- Kotlin real y sustitutos declarados de Android/HTTP: `tests/host/`.
- API/publicación/edición/HPKE: tests `catalog-snapshots`, `catalog-edition`, `v2-hpke` y regresiones Node del checkout.

`host-qa.json` conserva salidas de pruebas sintéticas y dependencias, sin cuerpos de configuraciones reales. Los jars, cabeceras de terceros, bibliotecas host y fixtures temporales no se suben. `upstream-qa.json` identifica las cabeceras temporales JNI/Mbed TLS y el parser temporal de JSX. No se certifica que LeakSanitizer, Gradle, Compose, Android Keystore, ARM64 o un VPS hayan sido ejecutados.

Los tests Android añadidos son gates pendientes; el commit usa `[skip ci]` para no activar la compilación firmada automática de la rama. Mantener el PR como borrador hasta revisión/QA. No se ha mergeado ni desplegado.
