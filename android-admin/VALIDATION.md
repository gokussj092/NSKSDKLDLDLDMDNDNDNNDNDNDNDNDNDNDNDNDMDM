# Validación del panel Android — 14 de noviembre de 2026

Base remota: `ae64cd718fa43bb5a820fc0643cfc35a0cca572a`, rama `feat/android-admin-panel`.

La revisión local anterior no llegó a publicarse por el bloqueo de autorización y su entorno temporal se reinició. Se recuperó el paquete persistente `SP-DECODE-Admin-integracion-UI-JNI.zip`, se reconstruyeron los flujos de usuarios/personal/soporte y se integraron las nuevas secciones comerciales y de plataforma. El propietario autorizó explícitamente la subida a esta misma rama en este turno.

## Verificado localmente

- `assembleDebug`: PASS. Aplicación Android nativa con bibliotecas C++ para arm64-v8a, armeabi-v7a, x86 y x86_64.
- `lintDebug`: PASS sin errores. Consultar el resultado final del workflow para la revisión de esta revisión exacta.
- `testDebugUnitTest`: PASS, 15 pruebas (4 de reglas y 11 de estado).
- `assembleDebugAndroidTest`: PASS. La compilación de pruebas no equivale a su ejecución en dispositivo.
- `run-native.sh`: PASS, métodos/rutas/límites/codificación y rechazo de operaciones fuera de la lista.
- `run-jni-host.sh`: PASS, carga real de la biblioteca JNI en JVM y consultas UTF-8.
- Gradle 8.11.1 incluye wrapper con SHA-256 de distribución verificado.
- `git diff --check`: PASS.

Las pruebas de lógica comprueban importes exactos, IP literales, dependencias de permisos, CSV seguro, identidad de usuarios, conservación de Premium, mensajes locales, precios históricos de pedidos, exclusión de pendientes/reembolsados, claves DEMO, créditos, catálogo atómico, 14 idiomas y protección del cargo propietario.

## Pendiente hasta observar el resultado en Android

Este entorno local no tiene `/dev/kvm`. Se prepararon 12 pruebas instrumentadas, captura de 22 secciones de referencia, pantalla compacta a 320 dp con texto al 130% y teclado, modo horizontal y tema claro. El workflow las ejecuta en un emulador acelerado. No declarar aprobada la prueba visual ni la ejecución instrumentada hasta consultar ese resultado y revisar sus capturas.

## Límites

No hay permiso INTERNET ni sesión real en la Activity. No se verificaron APIs remotas, MFA, biometría, Keystore, autorización de servidor, firma de producción, servicios VPS, pagos, licencias reales, push ni adjuntos. Todas las escrituras del modelo son locales y las credenciales generadas llevan DEMO. Release continúa deshabilitado.
