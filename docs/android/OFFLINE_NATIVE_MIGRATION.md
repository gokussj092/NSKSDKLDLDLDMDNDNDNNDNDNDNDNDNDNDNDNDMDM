# SP-DECODE Offline — Migración a C++ nativo

Rama: feat/version-offline-apk. La variante nativa solo se selecciona con
SPDECODE_OFFLINE_NATIVE=true, sin SPDECODE_CLOUD_API_BASE_URL.
Este commit es una integración alfa; NO completa los cuatro descifradores.

## Aislamiento de distribución
- Identificador: com.ghostdeveloper.spdecode.offline
- Etiqueta del launcher: SP-DECODE Offline
- Fuentes: android/app/src/offlineNative/java; biblioteca liboffdecode.so.
- Sin permiso INTERNET, cliente Cloud, catálogo VPN ni decodificadores antiguos de Kotlin.
- El motor Cloud y los métodos Python no se modificaron.
- El resultado NetMod conserva el JSON original completo (no el resumen aplanado del bot).
- El usuario debe proteger cuidadosamente las claves privadas NPV exportadas.

## Estado real
| Función | Estado | Método Python de referencia |
|---|---|---|
| NetMod Syna .nm | C++ AES-128-ECB/PKCS7 integrado, pendiente QA de Android | decoders/Python/nms.py |
| NPV generador P-256 | C++ clave pública SEC1 comprimida, privada PKCS8, pendiente interoperabilidad | decoders/Python/npvs_identity.py |
| HTTP Custom .hc | PENDIENTE; formatos legacy ChaCha y nuevos envelopes | decoders/Python/HTTPCUSTOM.py |
| HTTP Custom contraseña/HWID/ambos | PENDIENTE; KDF Argon2id, HCCFG/HCX4 y AEAD | cloud/workers/python/hc_bridge.py |
| HTTP Injector .ehi | PENDIENTE; AES-CBC, XXTEA, Argon2id, ChaCha20-Poly1305 | decoders/Python/HTTPINJECTOR.py |
| NPV Tunnel descifrado .npv4/.npvt/.npvs | PENDIENTE; whitebox, ECDH, firmas y AEAD | decoders/Python/NPVTUNNEL.py y npvs.py |

El JNI rechaza explícitamente los formatos pendientes. No habrá fallback a Kotlin ni Cloud.

## Condiciones para declarar la versión terminada
1. GitHub Actions compila y verifica package, firma, ausencia de INTERNET y liboffdecode.so.
2. Pruebas diferenciales C++/Python para .nm con archivos legítimos, errores de Base64, padding y tamaño.
3. Interoperabilidad P-256 comprobada con npvs_identity.normalize y Android NpvsIdentityVault.validate.
4. Puerto completo HC para normal, contraseña, HWID y ambos con alteración de datos y secretos incorrectos.
5. Puerto EHI y NPV con archivos exportados reales, JSON íntegro y autenticación estricta.
6. No publicar una compilación final de cuatro métodos hasta pasar los controles anteriores.
