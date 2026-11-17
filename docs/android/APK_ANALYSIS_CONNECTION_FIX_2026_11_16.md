# Conexión de la sección APK: firma nativa V2

Base revisada: `ci/unity-ads-online-qa`, commit
`14d7dc791785a74d3d2614e62e30f3a2e30520e8` de Muse. APK Online 1.1.29/44.

## Causa reproducida

La pantalla solicita el saldo mediante la operación V2 **25**, antes de
habilitar la importación. `CloudNativeTransport.post()` prepara HPKE y llama
a `CloudRequestProof.signBytes()` antes de abrir HTTPS. La firma pasa por
`spdecode::formatProof()`, cuya validación todavía rechazaba `op > 24` con
`CLOUD_NATIVE_PROOF_INVALID`.

Por tanto las operaciones 25–30 terminaban **antes de enviar la petición**.
`MainActivity` convertía esa IOException en el error genérico de la captura.
El descifrado (5/6) funcionaba porque estaba dentro del rango admitido.
Los diagnósticos de servidor añadidos por Muse no podían registrar una
petición que la app no había enviado.

Existe además un segundo bloqueo: `inlineActionBinding()` no admitía **26 y
28** (inicio/finalización). El servidor ya las incluye en `protectedActions`.
Solo corregir el saldo dejaría esas dos operaciones bloqueadas cuando la
política de la sesión requiere Action Integrity inline.

## Cambio acotado

- Permitir 25–30 en la firma nativa, manteniendo el rechazo de 0, 3 y 31.
- Incluir únicamente 26/28 en la vinculación de acciones, como exige el
  servidor. Preflight/chunk/status/history no se convierten en acciones.
- Incluir el archivo nativo y su cabecera en el filtro del workflow Online
  existente para que la corrección produzca una APK con la firma persistente.

No se cambia Kotlin, pantallas, login, soporte, el analizador, la facturación,
el saldo, la reserva de créditos, el volumen de resultados ni los diagnósticos
de Muse. Se mantienen versión 1.1.29/44, firma persistente, HPKE, PoP, TLS,
atestación e Integrity. No se modifica ni despliega el servidor.

## Evidencia ejecutada

`tests/native_app_analysis_transport.cpp` compila los **archivos reales**
`spdecode_security.cpp` y `spdecode_hpke.cpp`. Su contraparte Node usa los
primitivos existentes del servidor: abre HPKE, comprueba el mensaje firmado
y la firma P-256, contrasta el hash de Action Integrity y cifra una respuesta
que C++ abre y autentica. El saldo de esa respuesta es una fixture sintética,
no el de una cuenta real. Una alteración del ciphertext invalida la firma.

| Estado de C++ | Resultado |
| --- | --- |
| Base de Muse sin la corrección | 25–30 fallan; 5/6 pasan: 2/8 |
| Solo rango de firma corregido | 26/28 siguen fallando: 6/8 |
| Ambos cambios | 25–30 y regresión 5/6: **8/8** |

Otras comprobaciones:

- `cloud/web/tests/app-analysis.test.mjs`: **24/24**, incluidas preflight con
  créditos, cuenta sin saldo, aislamiento de cuenta, chunk de 2 MB y cola.
- Contrato C++ de prueba de posesión y nonce: correcto; operaciones inválidas
  y acciones que no corresponden siguen rechazadas.
- `tests/native_jni_contract.py`: 28 descriptores JNI correctos.
- `tests.test_android_unity_release_contract`: **34/34**.
- La suite estática `tests.test_android_native_trust_boundary` tiene dos
  problemas **también reproducidos en el checkout limpio de la base**:
  referencia a `FeedbackScreen.kt` ausente y ruta de descarga en
  `AppAnalysisClient.kt`. Se conservan para no alterar el trabajo de Muse;
  no se presentan como pruebas aprobadas.

Entorno de las pruebas nativas: C++17, Node 24.22.1, Mbed TLS 3.6.7 oficial
(SHA-256 del archivo: `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`),
CMake 3.31.10 instalado solo en el entorno de pruebas. No son dependencias
nuevas de la app ni del servidor.

## Reproducir

Con el source y build oficiales de Mbed TLS 3.6.7 disponibles, desde la raíz:

```sh
c++ -std=c++17 -O2 -Wall -Wextra -Werror \
  -I "$MBEDTLS_SOURCE/include" \
  tests/native_app_analysis_transport.cpp \
  android/app/src/main/cpp/spdecode_security.cpp \
  android/app/src/main/cpp/spdecode_hpke.cpp \
  "$MBEDTLS_BUILD/library/libmbedcrypto.a" -pthread \
  -o /tmp/spdecode-app-analysis-transport
node tests/native_app_analysis_transport.mjs /tmp/spdecode-app-analysis-transport
node --test cloud/web/tests/app-analysis.test.mjs
python3 tests/native_jni_contract.py
python3 -m unittest tests.test_android_unity_release_contract -q
```

## Validación pendiente en el teléfono

La corrección reside en `libv7q3.so`: requiere **instalar una APK recompilada**;
actualizar solamente el VPS no cambia el código que está instalado en Android.
No se ha probado AndroidKeyStore/Play Integrity ni el saldo real de la cuenta
del propietario en un teléfono desde este entorno.

Tras instalar la APK firmada de este commit, abrir APK y pulsar Actualizar.
La operación 25 debe llegar al servidor y el saldo debe responder para la
cuenta autenticada. Continuar con la importación autorizada para comprobar
26/27/28; la ejecución del análisis y el soporte siguen a cargo de la otra IA.
