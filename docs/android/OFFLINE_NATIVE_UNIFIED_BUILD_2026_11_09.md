# SP-DECODE Offline: port a la rama unificada y compilación

**Destino:** feat/nuevas-integraciones. **Fuente:** feat/version-offline-apk.  
**Importación:** fuente UI y recursos de la variante Offline, motor nativo, pruebas y workflow adaptado sin fusionar el historial antiguo.

## Dos aplicaciones independientes
- Online: \`com.ghostdeveloper.spdecode\`, Cloud, versión y reglas de publicación actuales; no recibe librerías de descifrado offline.
- Offline: \`com.ghostdeveloper.spdecode.offline\`, código Android aislado en \`android/app/src/offlineNative\` y motor \`liboffdecode.so\`; no incluye catálogo Cloud ni publicidad.
- Esta fase importa el código existente. **La primera activación de licencias documentada por el proyecto aún no está implementada.** El manifiesto offline continúa sin permiso INTERNET; agregarlo exclusivamente para la futura activación cuando se implemente, sin subir archivos ni resultados al servidor.
- La versión Offline y la Online pueden instalarse juntas sin sobrescribirse.
- La variante se selecciona en tiempo de **compilación**, no mediante botón de cambio de modo.

## Construcción local de prueba
Requisitos: JDK 17, Gradle 8.11.1, Android SDK API 36, NDK 27.2.12479018, CMake 3.22.1 y acceso de compilación a las dependencias nativas fijadas por commit/sha.
Desde el directorio \`android/\`:

\`\`\`bash
export SPDECODE_OFFLINE_NATIVE=true
unset SPDECODE_CLOUD_API_BASE_URL SPDECODE_CLOUD_RELEASE
gradle --no-daemon --max-workers=2 :app:assembleDebug
\`\`\`

Salida esperada: \`android/app/build/outputs/apk/debug/app-debug.apk\`. **Debug no usa la firma persistente y no debe entregarse a clientes**.

## Compilación release con la firma persistente
El workflow \`.github/workflows/offline-native-apk.yml\` está configurado para la rama \`feat/nuevas-integraciones\` y utiliza **los mismos GitHub Actions Secrets existentes** que el pipeline de firma de Online:
- \`SPDECODE_SIGNING_KEYSTORE_BASE64\`
- \`SPDECODE_SIGNING_STORE_PASSWORD\`
- \`SPDECODE_SIGNING_KEY_ALIAS\`
- \`SPDECODE_SIGNING_KEY_PASSWORD\`

Reconstruye el PKCS12 **solo en el runner**, valida el certificado, ejecuta \`SPDECODE_OFFLINE_NATIVE=true gradle :app:assembleRelease\`, verifica identidad de paquete y firma V1/V2/V3 y publica **solo el APK release firmado**, con hashes y reporte. No almacenar el keystore ni contraseñas en Git o en la app.

La misma clave de firma es aceptable para dos paquetes independientes; cada paquete mantiene su propio historial de \`versionCode\` y actualizaciones. Comprobar SHA-256 del certificado antes de entregar.

## CMake y JNI
El CMake actual incorpora un target \`offdecode\` exclusivo cuando se activa \`-DSPDECODE_OFFLINE_NATIVE=ON\`, y retorna antes de crear la biblioteca de transporte Cloud \`v7q3\`. La biblioteca de resultados de Cloud queda también deshabilitada para Offline. C++ nativo usa bibliotecas/compilaciones fijadas: Mbed TLS 3.6.7, Argon2 y nlohmann/json, y genera tablas NPV con \`scripts/build_offline_npv_tables.py\` en el host CI (nunca ejecutadas en Android).
R8 conserva solo las firmas JNI necesarias, sin evitar la ofuscación general. No llevar métodos C++ a Kotlin.

## Pruebas requeridas
1. Workflow de paridad HC, EHI, Dark, Hat, NPV y contrato UI.
2. Build debug y release; instalación lado a lado con Online. Verificar \`aapt dump badging\` y \`apksigner verify\`.
3. Offline sin permiso INTERNET, sin bibliotecas Cloud ni SDK de anuncios.
4. R8 no elimina \`com.ghostdeveloper.spdecode.offline.NativeOffline\`, y \`liboffdecode.so\` está en el APK.
5. Firmas V1/V2/V3 de release derivadas del secreto persistente; ningún fallback a llave temporal.
6. Pruebas funcionales reales de archivos/importación/visor JSON, verificadas por propietario; pruebas CI sintéticas no sustituyen esta QA.
7. Sin cambios a la app Online: backend, versión \`1.1.27\`, firma y Play AAB-only update siguen independientes.

**No se incluye tienda, servidor de licencias ni bloqueo inicial de licencia en este port.** Su especificación está en \`docs/MONETIZACION_LICENCIAS_OFFLINE_API_IP_2026_11_09.md\`. La firma persistente del APK es independiente de la futura clave que introducirá el comprador.
