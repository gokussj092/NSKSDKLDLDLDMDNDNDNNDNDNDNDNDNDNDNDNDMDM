# C5 — SP-DECODE Android Cloud: aislamiento de motores y secretos

Rama: feat/cloud-c5-apk-secret-minimization (base C4 PR #90).

En compilaciones Cloud, Gradle genera un árbol con Kotlin exclusivo del cliente: no compila las 107 clases originales parity/ ni los decodificadores locales de textos, HTTP Injector Cloud o NUR. Solo conserva AndroidDecoderCatalog como catálogo público de formatos para la pantalla existente.

Cuatro fachadas ligeras en android/app/src/cloud/java permiten que los componentes existentes sigan compilando. Ninguna implementa descifrado ni contiene claves. C++ JNI libspdecode.so mantiene el transporte HTTPS.

Los assets Cloud contienen exclusivamente decoder_catalog.json. No se empaquetan perfiles, claves, tablas, endpoint privado de NUR, whitebox o los archivos .spv del antiguo Secure Asset Vault. No se genera la clave local de ese vault ni se añade Bouncy Castle al build Cloud.

El diálogo de contraseña/HWID permanece intacto: la inspección se realiza por la API Cloud, que devuelve PASSWORD_REQUIRED, HWID_REQUIRED o HWID_PASSWORD_REQUIRED, sin derivar claves localmente. Ante errores de red no existe fallback de descifrado offline.

Los archivos visuales congelados en C0 permanecen sin cambios. C5 conserva los motores históricos en el repositorio y para builds locales de regresión, nunca dentro del APK Cloud. Los datos de historial del usuario siguen cifrados localmente por su protección independiente.

El workflow cloud-c5.yml compila un APK debug con un host HTTPS sintético y verifica físicamente el ZIP y DEX. No publica APK, no modifica el bot ni fusiona a main. La compatibilidad real y despliegue con Play Integrity y VPS siguen pendientes.