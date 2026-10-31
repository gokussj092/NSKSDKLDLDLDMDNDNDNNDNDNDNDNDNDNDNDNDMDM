# SP-DECODE — R0: línea base verificable de RASP y seguridad de despliegue

**Fecha:** 2026-10-30  
**Rama:** `feat/post-native-security`  
**Alcance de este checkpoint:** inventario de código, ampliación de contrato RASP no intrusivo y corrección puntual del setup Node en CI. **No está cerrada la fase R0; no se ha implementado R1–R6.**  
**Base:** `ANDROID_RASP_ANTI_TAMPER_ROADMAP_2026_10_30.md` y `HPKE_VPS_DEPLOYMENT_SAFETY_RUNBOOK_2026_10_30.md`.

## 1. Inventario verificado

| ID | Control y frontera | Evidencia en código | Evaluación actual |
| --- | --- | --- | --- |
| R0-01 | Inicio y retorno a foreground | `MainActivity.kt` invoca `ReleaseIntegrity.isTrusted` en `onCreate` y `onResume` | Implementado; en release se cierra la Activity si falla |
| R0-02 | Antes de operaciones Cloud | `CloudDecodeClient.kt` / `requireLegalConsent` llama a `ReleaseIntegrity.isTrusted` en varias operaciones | Defensa local; no es sustituto de autorización de servidor |
| R0-03 | Firma, package y debugger propios | `ReleaseIntegrity.kt` → `CloudNativeTransport.verifyReleaseSigner` → `spdecode_transport.cpp` | Compara firmantes permitidos, package y estado de debugger; `BuildConfig.DEBUG` tiene semántica distinta |
| R0-04 | Indicadores runtime en proceso propio | `spdecode_runtime_guard.cpp` lee `/proc/self/status` y `/proc/self/maps` con límite de tamaño | Bit 1: TracerPid; bit 2: marcadores de librerías. No detecta con certeza todos los hooks |
| R0-05 | Privacidad y no espionaje de terceros | `spdecode_runtime_guard.cpp` sólo accede a `/proc/self/*` | No enumera procesos/paquetes Termux, Shizuku ni VPN; la mera presencia de esas apps no bloquea |
| R0-06 | Transporte HPKE | `spdecode_hpke.cpp`, `spdecode_transport.cpp`, `cloud/web/lib/v2-hpke.mjs` | Ya implementado; validación de dispositivo real tras incidente de VPS **pendiente** |
| R0-07 | Play Integrity / prueba de solicitud | `CloudDecodeClient.kt`, `cloud/web/lib/v2-transport.mjs` | Integridad local y Play/PoP del servidor son controles separados; verificar con entorno Play real |
| R0-08 | Hardening de ELF | `CMakeLists.txt`, `spdecode.exports` | Hay visibility hidden, stack protector, fortify, RELRO/NOW y exports limitados; inspección ELF real por ABI pendiente |
| R0-09 | VPS y rollback | `cloud/infra/vps/spdecodectl` | `update` comprueba HTTP liveness; **no valida obligatoriamente keyring y KID HPKE del contenedor** |
| R0-10 | CI de seguridad V2 | `.github/workflows/cloud-v2-security.yml` | Se añadió instalación de dependencias Node antes de `npm test`; pendiente validar en runner |
| R0-11 | Test de señales RASP | `tests/native_runtime_guard_contract.cpp` | Casos positivos y controles benignos ampliados; deben incorporarse a ejecuciones de CI vigentes |

**Nota:** la función nativa `verifyReleaseSigner` actualmente trata `runtimeRisk()!=0` como rechazo en release. Un marcador de nombre en `maps` no equivale a prueba criptográfica de hooking; R2 deberá modelar evidencia/certidumbre y analizar falsos positivos antes de endurecer su uso. Las lecturas vacías de `/proc` se reducen a bitmask 0, lo cual no demuestra que la inspección se realizó: requiere estado explícito `UNKNOWN` en una fase posterior.

## 2. Matriz R0 de pruebas

| ID | Caso | Resultado esperado | Estado |
| --- | --- | --- | --- |
| T-R0-01 | `TracerPid: 0` + mapa ordinario | riesgo 0 | Contrato host incluido |
| T-R0-02 | `TracerPid: 512` | bit 1 | Contrato host incluido |
| T-R0-03 | Frida-Gadget / Xposed / Substrate en mapas sintéticos del propio proceso | bit 2; combinable con bit 1 | Contrato host incluido |
| T-R0-04 | Referencias a Termux, Shizuku y VPN sin marcador de instrumentación | riesgo 0 | Contrato host incluido |
| T-R0-05 | Texto `AdbEnabled: 1` sin proceso trazado | riesgo 0 | Contrato host incluido |
| T-R0-06 | Estado proc vacío, TracerPid ilegible/negativo | sin señal positiva; **no** afirmar dispositivo limpio | Contrato host incluido; diseño triestado pendiente |
| T-R0-07 | APK re-firmada y certificado Play real | rechazada / aceptada respectivamente | PENDIENTE de dispositivo Play y QA |
| T-R0-08 | Build 37, Android físico, descifrado real autenticado HPKE | respuesta íntegra y sin error de servicio | PENDIENTE de confirmación |
| T-R0-09 | `spdecode update` con HPKE ausente, KID incorrecto o contenedor desconfigurado | abortar antes de promoción / rollback íntegro | PENDIENTE de implementación de pre/postflight |
| T-R0-10 | ABI, R8, idiomas, JNI, Play attestation, latencia P95 y batería | sin regresiones frente a baseline | PENDIENTE de medición y runners específicos |

## 3. Verificación sin APK ni despliegue

Ejecutar **desde la raíz de un checkout del repositorio**:

```bash
g++ -std=c++17 -O2 -Wall -Wextra -Werror \
  tests/native_runtime_guard_contract.cpp \
  android/app/src/main/cpp/spdecode_runtime_guard.cpp \
  -o /tmp/spdecode-r0-runtime-guard
/tmp/spdecode-r0-runtime-guard
python3 tests/native_jni_contract.py
python3 -m unittest tests.ci.test_release_signer_pins -v
```

El contrato RASP se validó en un entorno Linux host con copia textual del código auditado y de los nuevos casos; **esto no acredita todavía una ejecución de CI sobre el commit ni una prueba de Android real**. No requiere claves, redes, ADB ni un APK. El workflow V2 previo ejecutaba `npm test` sin instalar previamente `cloud/web` dependencies; ahora instala con `npm install --no-audit --no-fund --ignore-scripts --no-package-lock`. No hay lockfile independiente en `cloud/web`; no utilizar `npm ci` en ese subdirectorio sin introducir uno.

### Ejecución futura de Node en checkout

```bash
cd cloud/web
npm install --no-audit --no-fund --ignore-scripts --no-package-lock
node --test tests/v2-hpke.test.mjs
```

Requiere red para instalar dependencias públicas. No imprimir variables `CLOUD_V2_HPKE_KEYRING`, private keys ni tokens durante diagnósticos.

### CI host ejecutada y verificada (2026-10-30)

`.github/workflows/post-native-r0-host.yml` permite lanzar `workflow_dispatch` desde la rama `feat/post-native-security` y comprueba JNI, certificados con fixtures sintéticos, el contrato C++ de RASP y `bash -n` del operador VPS. No incluye Gradle, firma, generación APK/AAB, descarga de dependencias Android ni operaciones en el VPS. **Actualización verificada:** run `41164324659` en commit `7997b4b2b47e3e8e8b9b493a81a37ab219f31c07`, conclusión **success**. Comprobados 23 descriptores JNI, cinco fixtures de certificados, contrato de señales nativas, diez pruebas C4/NPVS y sintaxis Bash del operador. No se compiló Android.

## 4. Decisiones y riesgos abiertos

1. **Prioridad operativa HPKE:** preflight/postflight del keyring y KID dentro del proceso web, con checks sin volcar secretos. No implantar cambios de VPS hasta definir aceptación de coexistencia y rollback. Liveness HTTP no constituye readiness del transporte.
2. **R0 CI heredado:** revisar resultados reales de workflows después del PR #108: test UI/UX y contrato JNI antiguos, dependencias Node de HPKE y condiciones `if` que sólo ejecutan en ramas de migración anteriores. No afirmar CI global verde sin un run que lo demuestre.
3. **R1 signers y Play:** verificar que la APK distribuida por Play use el certificado de **App Signing** y que el canal QA use un certificado explícitamente autorizado; los pins públicos del cliente no reemplazan la validación Play del backend.
4. **R2 detección:** reemplazar decisión monolítica basada en un solo marcador por señales acotadas y niveles de confianza, con estado `UNKNOWN` para /proc inaccesible. No escanear procesos externos ni bloquear ADB, Shizuku o Termux por presencia.
5. **R3–R6:** hardening y anti-dump, veredictos oficiales sobre captura/control, política de servidor, telemetría agregada y matrices físicas se mantienen pendientes. Cada fase requiere pruebas negativas y falsos positivos.
6. **Sin impacto operacional:** este checkpoint no modifica `main`, la versión APK/AAB, las claves, `cloud/compose.yaml`, el API ni el VPS; no crea archivos de firma, ni dispara compilaciones firmadas por diseño.

## 5. Criterios para declarar R0 completo

- Inventario de rutas y puntos de evaluación revisado por código/versión y tabla de amenazas.
- Contratos JNI/firmantes/runtime y tests de seguridad Node en CI sobre un SHA actual, y resolución de regresiones heredadas sin rebajar protección.
- Al menos una ejecución real de Build 37 en Android físico con Play Integrity y HPKE correctos; evidencia no sensible.
- Inventario de falsos positivos + baseline de tiempo/CPU/RAM en dispositivos reales.
- Gate de despliegue HPKE diseñado y validado con rollback seguro en ambiente de pruebas.
- Aprobación explícita antes de fusionar o promover nuevos controles.

**Estado checkpoint:** R0 parcial. No hay justificación para declarar R1–R6 implementadas ni desplegar el estado actual a producción.

## 6. Evidencia R0 adicional (auditoría de la rama)

### Regresiones previas identificadas por CI, sin nueva ejecución

- **Validate/main**: run `41158379188` falló en pruebas unitarias: hash de `FunctionalSettingsPanel.kt` desactualizado y test NPVS que esperaba una llamada anterior a HPKE. El trabajo de fase R0 cambia sólo el baseline aprobado y el contrato de test; **no** modifica la funcionalidad Kotlin.
- **V2 bound transport**: run `41158317638` falló porque `@hpke/core` no estaba instalado al ejecutar la batería de tests Node. El workflow de la rama ahora instala dependencias de `cloud/web` antes de ejecutar `npm test`. **Sin resultado nuevo de CI aún**.
- **C0/C4/C5**: runs `41158317507`, `41158317565`, `41158317459` fallaron por los mismos contratos anteriores; no se recomienda repetir todos los pipelines hasta superar primero el gate host R0.

### Auditoría de la excepción C0: revisión exacta

Se comparó el Git blob anterior `af689df583243df41864d27fea3302e526f05a84` con el blob `94c75029f5931a49c51e56f729ed7c772706769a` de `FunctionalSettingsPanel.kt`. **Única línea lógica sustituida:** `DeviceCredentialSettingsSection()` → `// Settings additions injected here by the Android Gradle task.`. El script `scripts/android_s4_provisioning_audit.py` exige expresamente que la sección de aprovisionamiento anterior se haya retirado y que exista el anchor único, y `android/app/build.gradle.kts` utiliza ese anchor para insertar los ajustes Cloud en una copia generada. Los otros **ocho** archivos del manifiesto C0 coincidían ya con sus SHA de Git; no fueron rebaselined. La actualización del hash C0 retiene las nueve comprobaciones, sin deshabilitarlas.

### Contrato NPVS tras migración HPKE

La suite `tests/test_android_npvs_identity.py` ahora exige que `protectedPost` pase **el mismo `prepared` wire cifrado** cuando obtiene el token Play Standard ligado a `requestHashHex(prepared.wire)` y que descarte el estado al finalizar. El contrato viejo sólo verificaba una llamada anterior con cinco argumentos y rechazaba la nueva llamada correcta. Esto preserva la verificación de material cifrado; **no introduce bypass**.

### Siguiente gate ejecutable de bajo coste

El workflow manual `.github/workflows/post-native-r0-host.yml` incluye ahora JNI, pins con fixtures, guard de instrumentación C++, **C4/UI rebaseline** y **NPVS**, más comprobación de sintaxis del operador VPS. Se debe ejecutar **una sola vez** sobre el último SHA de la rama antes de decidir si habilitar PR o CI más amplio. Se configuró excepcionalmente un disparador `push` restringido a cambios de **ese workflow** dentro de la rama R0, y se verificó **success** en run [`41164324659`](https://github.com/gokussj092/NSKSDKLDLDMDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/41164324659). El resto del pipeline global no se ejecutó. La ejecución no prueba funcionamiento real de Android ni dependencias Node.

## 7. QA físico y condiciones de salida de R0

Registrar únicamente códigos de resultado, versión y métricas agregadas (sin contenidos VPN, HPKE private keys ni tokens):

| Prueba en Android | Evidencia mínima | Gate |
| --- | --- | --- |
| APK firmada por Google Play/internal y build 37 | Instalación, versión, canal y firma esperada | Firma válida y sin cierre prematuro |
| Un archivo de fixture no sensible vía HPKE | Tiempo, status, errorCode tipado y éxito | Respuesta cifrada autenticada; no sólo HTTP 200 del health |
| Regreso foreground y arranque frío | Misma instalación / estado UI | Sin crash/denegación espontánea |
| ADB activado sin debugger adjunto | Resultado de acción legítima | Sin bloqueo sólo por ADB |
| Termux/Shizuku instalados, sin instrumentar SP-DECODE | Resultado de acción legítima | Sin bloqueo por presencia de herramientas |
| APK de laboratorio re-firmada (sin datos reales) | Resultado local/servidor | Operaciones sensibles rechazadas |
| Debbuger/hook controlado del proceso propio | Código de diagnóstico y estado | Rechazo de operación sensible y recuperación normal |
| Android físico (al menos dos OEM y varias API) | Inicio, rendimiento, p50/p95 de operación | Sin falsos positivos observados en matriz acordada |
| VPS tras recrear web | HPKE_ENABLED, KID compatible, salud E2E, sin secretos | Sin errores 503 de configuración y rollback revisado |

**Pendiente:** no confundir pruebas de código host o hashes de fuente con Play Integrity real, anti-dump, integridad de segmentos ELF en dispositivo, ni con una aplicación lista para producción. La fase R0 no se declarará cerrada hasta verificar estos gates.
