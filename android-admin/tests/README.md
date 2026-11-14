# Comprobación del panel Android

El módulo debug no tiene permiso INTERNET. Usuarios, cargos, compras, licencias, códigos, API, catálogo y avisos usan datos locales de demostración. Los registros de prueba no se convierten en credenciales o permisos de servidor.

```sh
./android-admin/gradlew -p android-admin :app:assembleDebug :app:lintDebug :app:testDebugUnitTest :app:assembleDebugAndroidTest
sh android-admin/tests/run-native.sh
sh android-admin/tests/run-jni-host.sh
# Con kotlinc instalado:
sh android-admin/tests/run-kotlin-host.sh
# Con dispositivo/emulador Android:
./android-admin/gradlew -p android-admin :app:connectedDebugAndroidTest
```

Usar JDK 17/21, SDK 35, NDK 27.2.12479018, CMake 3.22.1 y Gradle 8.11.1. No versionar local.properties ni material privado de firma.

La suite de estado comprueba cantidades monetarias exactas, estados de compras y reembolsos, inmutabilidad de precios históricos, API por IP, claves DEMO, revocaciones aisladas, créditos e historial, publicación atómica del catálogo, 14 idiomas y permisos relacionados. La suite de interfaz recorre los módulos y realiza operaciones de prueba sobre ellos. Las capturas son de los componentes Android ejecutados, sin datos reales.
