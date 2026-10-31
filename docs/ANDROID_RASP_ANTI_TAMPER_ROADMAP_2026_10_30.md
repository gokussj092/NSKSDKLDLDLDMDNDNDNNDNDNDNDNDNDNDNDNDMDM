# SP-DECODE — Hoja de ruta de protección Android: RASP, antimanipulación y anti-dump

**Fecha:** 2026-10-30 · **Rama base de continuidad:** feat/post-native-security · **Estado:** DISEÑO/PENDIENTE, no implementado en este commit. **Objetivo:** aumentar el costo de ingeniería inversa y reducir el abuso de la API preservando funciones legítimas y compatibilidad.

> **Seguimiento 2026-10-30 (checkpoint posterior):** R0 **INICIADA, NO CERRADA**. Consultar `docs/RASP_R0_BASELINE_2026_10_30.md`: inventario del código revisado, nuevas pruebas host del guard nativo (con casos benignos de ADB/Termux/Shizuku/VPN) y corrección de instalación Node en el workflow V2. Sin compilación Android, despliegue VPS ni cambio del código de detección. Falta CI actualizado y validación E2E HPKE en dispositivo físico. R1–R6 siguen pendientes.\n\n## 0. Instrucción para el próximo chat

Leer **este documento** y **docs/HPKE_VPS_DEPLOYMENT_SAFETY_RUNBOOK_2026_10_30.md**, examinar el estado real de la rama y verificar si el usuario ya confirmó el descifrado E2E de la Build 37 después de reactivar HPKE. **No asumir que el mero HTTP 200 de /health/live equivale a descifrado.** El usuario solicitó documentar hoy; no se autorizó implementar RASP nuevo, iniciar builds o desplegar VPS en este turno.

Después, proponer/ejecutar por fases pequeñas y probables las defensas pendientes. Antes de cada cambio, auditar código y detectar si existe ya una implementación para no duplicarla. Nunca cambiar claves HPKE, keystore original, versionName/versionCode, políticas de producción ni main por cuenta propia. Usar conector GitHub de **gokussj092**. No saturar GitHub Actions.

## 1. Contexto consolidado de arquitectura y pruebas

- Proyecto: **SP-DECODE** Android Cloud (paquete com.ghostdeveloper.spdecode), Next.js + API, worker Python y Redis en VPS. Dominio API público https://api.spdecode.xyz.
- Repositorio Goku: **gokussj092/NSKSDKLDLDLDMDNDNNDNDNDNDNDNDNDNDNDNDMDM**.
- 2026-10-30: PR #108 fusionó **security/hpke-native-cpp-migration** en main; merge SHA **ffcfb8887174eeba09c9dbd90e493a51b100ef90**. Se creó rama nueva **feat/post-native-security** desde ese SHA.
- Android fuente: **versionName 1.1.24, versionCode 35**. Artefactos APK/AAB firmados de prueba **1.1.24 build 37** en Actions run **41156789776** (override sólo del runner). No suponer publicación a Play.
- Pruebas independientes previas: interoperabilidad C++/Node **41154662597** y Android R8/ABIs **41154662634**, ambas success. El PR general mostró **checks heredados pendientes/fallidos**, no atribuir green global. Pruebas de dispositivo físico, Play Integrity real y RASP sin falsos positivos **pendientes**.
- Después de spdecode update all main, la APK arrojó “servidor fuera de servicio” por **CLOUD_V2_HPKE_ENABLED=false** y keyring ausente en entorno del contenedor, aunque Node y el worker estaban saludables. La clave privada persistía fuera del repo, KID público **896f195624217d42**, idéntico al pin X25519 incluido en C++. El usuario corrigió el entorno: **HPKE=true, KID compatible, HPKE_ONLY=false**. No hay aún en este registro confirmación explícita de descifrado real posterior. Ver runbook.
- Dependencias de VPS actualizadas/verificadas por usuario: **Next 16.4.3**, **React/React DOM 19.3.1**, **msgpack 1.2.4**, **requests 2.33.1**. **CairoSVG 2.9.1** actualizado en manifiesto de análisis APK, no worker de producción.

### Qué existe en código (no duplicar)

| Capa existente | Ruta / situación real |
| --- | --- |
| Biblioteca nativa | android/app/src/main/cpp/CMakeLists.txt produce **libv7q3.so**, exports reducidos a JNI_OnLoad |
| HPKE V2 | spdecode_hpke.cpp y spdecode_transport.cpp: X25519/HKDF/AES-256-GCM, request/reply autenticadas, pin público |
| Solicitudes y sesión | spdecode_security.cpp, spdecode_session.cpp: PoP ECDSA, nonce, expiración, invalidación bearer, validaciones nativas |
| Keystore | spdecode_keystore.cpp, spdecode_keystore_policy.cpp, adaptador CloudKeystorePlatform.kt: claves no exportables en AndroidKeyStore |
| Play | CloudDecodeClient.kt usa SDK oficial; backend verifica el verdict y políticas, también hardware attestation |
| Catálogo | spdecode_catalog.cpp: P-256 efímero nativo, handle opaco/one-shot, HKDF/AES-GCM |
| Integridad local | ReleaseIntegrity.kt y capa nativa comprueban firma y condiciones básicas |
| RASP inicial | spdecode_runtime_guard.cpp inspecciona **/proc/self/status TracerPid** y **/proc/self/maps** de su propio proceso buscando marcadores seleccionados Frida-Gadget/Xposed/Substrate; está acoplado al chequeo de integridad de release |
| Exclusión de motores | Cloud release usa prepareCloudOnlySources; no incorpora los secretos/motores offline históricos; mantener auditoría APK |
| Infraestructura | cloud/web/lib/v2-transport.mjs, v2-hpke.mjs, cloud/compose.yaml, cloud/infra/vps/spdecodectl |

**Limitaciones actuales:** un atacante con control del proceso puede evadir señales locales y observar datos en el momento de mostrarse; Kotlin/JNI/Keystore/SDK Play deben conservar tareas de plataforma. Frida no equivale sólo a una cadena de biblioteca cargada. El código native puede ser desensamblado. El cambio de nombre de la biblioteca o XOR del pin público **no son cifrado de secretos ni seguridad criptográfica**.

## 2. Modelo de amenazas y fronteras

**Activos protegidos:** confidencialidad de material de servidores y respuestas; propiedad intelectual del protocolo/cliente; privacidad de archivos de usuarios; claves de sesión no exportables; integridad de solicitudes, instalación legítima, disponibilidad del worker/API y confianza de descarga.

**Amenazas prioritarias:** APK modificada o re-firmada; hooking del proceso; Frida server/gadget/inyección, Xposed/LSPosed; depuración y volcados del proceso; alteración de JNI/PLT/GOT y librerías en memoria; automatización abusiva de endpoints; replay/MITM; overlays o control de pantalla con lectura de información; bypass de verificaciones locales.

**No es evidencia por sí sola de ataque:** modo desarrollador/ADB habilitado, cable USB, root, emulador, VPN, aplicación Termux instalada o ejecutándose, Shizuku instalada, servicios de accesibilidad legítimos, herramientas de screen recording o perfil de trabajo. El motor debe basarse en señales **correlacionadas y de alta confianza**, no prohibir herramientas genéricas.

**Controles autoritativos:** servidor rechaza token/veredicto Play, firma/PoP, sesión, límites y key attestation inválidos. La defensa nativa agrega fricción y señales. Nunca convertir un resultado manipulable del cliente en autorización suficiente.

## 3. Fases recomendadas de implementación

### Fase R0 — Inventario y línea base (PR de documentación/tests)

1. Inventariar todos los puentes JNI, flags release/debug/QA, claves y autorizaciones, cache y pantallas sensibles.
2. Documentar flujo de arranque, reanudación, operación sensible y cierre, y qué verificaciones se disparan; medir tiempo CPU/RAM y latencia en móviles reales.
3. Reconciliar tests globales fallidos en el merge de PR #108: rebaseline explícito de UI/UX, contratos JNI/cambio de lib, tests Node con @hpke/core instalado. Arreglar tests **sin rebajar reglas por conveniencia**.
4. Preparar fixtures de APK original, variante re-firmada de laboratorio, entornos simulados de hooks, depuración real y errores de Play; no usar credenciales reales.
5. Trazabilidad por requisito: ID del control, amenaza, señal, severidad, respuesta, pruebas, coste, compatibilidad, estado y evidencia CI.

**Salida:** matriz de riesgos y pruebas que pasan en baseline sin nuevos bloqueos. No cambios de API ni nuevas librerías todavía.

### Fase R1 — Integridad y antimanipulación (primera prioridad funcional)

- Verificación del **certificado de firma de la app distribuida** contra el esperado para el canal: diferenciar certificado **Google Play App Signing** del **upload key**; no asumir que el upload signer es el certificado que verá el usuario de Play.
- Play Integrity server-side: appIntegrity, deviceIntegrity, licensing/accountDetails cuando aplica, nonce/requestHash unido a **solicitud exacta**, antireplay y caducidad; política por canal Play interno/QA firmada. Ninguna excepción global para sideload.
- Integridad de **libv7q3.so**, tablas JNI críticas y código ejecutable: estrategias de hash de segmentos o comparación de secciones relevantes, teniendo en cuenta ASLR, relocation, JIT y diferentes ABIs. No comparar ingenuamente bytes que el loader modifica. Prevenir que el verificador y su expected hash sean triviales de modificar sin usar esto como única barrera.
- Reducir exports/strings y revisar símbolos JNI; activar y auditar **PIE, RELRO, stack protector, fortify, CFI cuando soporte toolchain/ABI**, sin introducir fallos Android 24–36. Mantener código y manifest coherentes.
- Separar política de integridad de UI: autenticidad se decide en backend, local RASP aplica a **operaciones sensibles**, no se confía en un booleano Kotlin.
- Integridad en arranque y **antes de cada solicitud de alto valor**, con invalidación segura de sesión ante evidencia fuerte.

**Gate:** tampered/re-signed APK rechazada por servidor o control local; APK auténtica de Play y QA autorizada pasan en dispositivos físicos. No bloquear por detectar solo que “desarrollador” está habilitado.

### Fase R2 — Anti-debug y anti-hooking continuo, Frida/Xposed

- Extender spdecode_runtime_guard.cpp desde su base actual: verificación acotada de **TracerPid**, debugger adjunto al proceso, librerías ejecutables de la propia app y desviaciones en funciones/JNI de seguridad. Contrastar varios indicadores para disminuir falsos positivos.
- Frida: distinguir marcadores de Gadget/agente en **memoria del propio proceso**, trampolines/hooks en puntos críticos y modificaciones comprobables del flujo. Nombres de procesos/puertos/strings aislados son señales frágiles y fácilmente evadibles.
- Xposed/LSPosed/Substrate: comprobar cambios verificables en la propia app y sus hooks relevantes, no bloquear automáticamente por paquete instalado en el dispositivo.
- Monitoreo **event-driven** al abrir app, al volver a foreground y antes de operaciones sensibles; intervalos acotados únicamente si se justifica. No crear servicio permanente de espionaje ni lectores agresivos de /proc del sistema.
- Asegurar que JNI, crypto e integridad no causen crash si el kernel restringe /proc/self/*, la lectura falla o el fabricante cambia el formato; estado “no evaluado” separado de “ataque confirmado”.
- Política de respuesta: riesgo alto → cancelar la operación sensible, invalidar sólo la sesión afectada y mensaje genérico; riesgo medio → verificación adicional o aviso; bajo/desconocido → telemetría agregada y continuidad. Nunca volcar nombres de módulos, mapas, tokens ni memoria a logs.

**Gate:** ensayos instrumentados con y sin Frida/hooks controlados, perfiles Android reales sin debugger, medición de p95 y prueba de recuperación tras abandonar entorno de pruebas. Política de QA temporal y diferenciada.

### Fase R3 — Anti-dump y protección de material en memoria

- Objetivo realista: **reducir ventanas y valor de los volcados**, no prometer que sea imposible extraer un resultado que el cliente necesita mostrar.
- Minimizar secretos y operaciones propietarias en APK: trabajadores, claves de proveedores y decodificadores privados continúan sólo en VPS; no incrustar claves privadas en C++ ni DEX.
- Revisar buffers de C++ (HPKE, catálogos, sesión): tiempo de vida, límites, escritura fuera de rango, ownership, zeroization comprobable, RAII y claves no exportables en AndroidKeyStore.
- Evitar persistencia de descifrados y secretos por defecto; proteger historial/caché AES-GCM con claves del Keystore, exclusión de backups según diseño, purge de datos temporales y permisos de archivo.
- Reducir fugas via logs, crash reports, analytics, clipboard, previews, capturas y notificaciones; **FLAG_SECURE** opcional y limitado a pantallas de contenido privado, evaluando usabilidad y soporte.
- Auditar dumps de Java heap y strings transitorios de UI/JNI: el resultado presentado en pantalla existe momentáneamente en memoria y es susceptible de captura si el SO está comprometido; no prometer invisibilidad.
- Evaluar binarios por stack hardening, símbolos exportados y bibliotecas cargadas; no instalar defensas que deshabiliten sistemáticamente crash reporting seguro o accesibilidad.

**Gate:** APK/AAB sin llaves privadas, secretos ni decodificadores internos; sin texto de perfiles en logs; límites/zeroization con pruebas reproducibles; tasa de fallos y memoria aceptable.

### Fase R4 — Entorno, ADB, Shizuku, Termux y captura/control externos

**Regla:** detección de presencia **no equivale a interferencia**. Respetar las restricciones Android 11+ de visibilidad de paquetes; no solicitar QUERY_ALL_PACKAGES, Usage Access, Accessibility, permisos de shell, root o enumeración global sólo para vigilar otras apps.

| Señal solicitada | Posible observación legítima | Evaluación y política |
| --- | --- | --- |
| ADB / USB debugging | Ajuste ADB habilitado, no prueba de conexión real ni de debugger adjunto | Baja confianza. Registrar sólo si necesario; debugger/tracer **adjunto a SP-DECODE** sí es señal directa |
| Shizuku activa | Servicio/paquete Shizuku en otro proceso no es visible de forma universal; app puede no tener permiso de inspección | No afirmar “Shizuku activo” sin API pública/consentimiento/permisos justificados y evidencia; preferir indicios reales de hooking/control que afecten la propia app |
| Termux activo | Android moderno no permite conocer de forma fiable todos los procesos en ejecución de otras apps | No forzar bloqueo por Termux instalado/en foreground; sólo evidencia de manipulación del proceso propio/abuso de API |
| Frida server externo | Proceso o puerto externo puede ocultarse; la mera existencia no confirma manipulación | Priorizar Frida Gadget/hook o memoria ejecutable anómala en proceso propio |
| Captura, overlay y control | Veredicto **appAccessRiskVerdict** de Play Integrity para KNOWN/UNKNOWN_CAPTURING, CONTROLLING, OVERLAYS | Evaluar server-side y por acción sensible; excluir accesibilidad legítima según reglas Play; no bloquear globalmente toda la app |
| Root/Magisk/emuladores | Entornos de pruebas, OEM, variantes de Android | Correlacionar con Play Integrity y evidencia de abuso; no asumir mala intención automáticamente |
| Apps VPN/proxy | Parte legítima del público de SP-DECODE | **Nunca bloquear por el mero uso de VPN**; TLS/HPKE y Play siguen controlando solicitudes |

Android Play Integrity proporciona veredictos sobre captura/control/overlays y Play Protect, cuando está habilitado y es evaluable. Un verdict vacío/no evaluado no es un resultado limpio. Se requiere opt-in de API y política de compatibilidad; el backend debe decidir sin exponer detalles sensibles del entorno del usuario.

**Gate:** prueba de usuarios con ADB activado y Termux/Shizuku instalados **sin manipulación de SP-DECODE**: deben poder usar la app legítima según política de distribución. Simulación de captura/control verdadero en pantallas sensibles produce advertencia/reto/denegación limitada si la política así lo requiere.

### Fase R5 — Riesgo compuesto y decisiones del servidor

- Protocolo de señales RASP acotado, firmado/PoP y sujeto a antireplay, **nunca un valor libre del cliente que autoriza por sí solo**.
- Modelo de decisión: nivel alto con señales independientes y confiables (firma inválida, attestation Play fallida, prueba de hook en el propio proceso) → rechazo de acciones sensibles. Señal ambigua (ADB habilitado/paquete instalado) → nada o reto proporcional.
- Controles de tasa y coste por cuenta/sesión/IP, scopes de operaciones, expiración corta, validación uniforme, auditoría segura sin guardar nombres de apps, puertos, mapas o datos personales.
- Posibilidad de **kill-switch server-side** para el nuevo *detector de RASP* en caso de falsos positivos; NO para desactivar HPKE obligatorio, proof, integridad del servidor, firma y protección de sesión.
- Observabilidad con counters por código y build, distribución p95 y tasa falsos positivos; los logs de debug tienen retención limitada y no contienen contenido descifrado.
- Policy por versión de cliente y canal: Play interno/cerrado, QA temporizado, producción. Evaluación de impacto antes de endurecer “deny”.

**Gate:** una APK con RASP falseado no puede forzar acceso del servidor; el backend autentica independientemente. Pruebas de bloqueo/replay, rate limits y rollback.

### Fase R6 — QA integral, beta y promoción

- CI por ABI **arm64-v8a, armeabi-v7a, x86_64, x86** según soporte de proyecto; build R8; JNI signatures, tamaño APK/AAB e idiomas completos; auditoría de secrets/exports.
- Dispositivos reales Android 24–36, al menos dos fabricantes, instalación Play interna y APK sideload; distinguir Google Play App Signing de upload signer.
- Comparativas sin/with detector: **cero falsos positivos en matriz de prueba acordada** como gate inicial, tolerancia de latencia/batería fijada según línea base y recuperación normal al desaparecer señal peligrosa.
- E2E de descifrado HPKE, catálogos P-256, offline/no red, token Play y hardware TEE/StrongBox, historial cifrado, reinicios y rotación de claves mediante procedimiento seguro.
- Verificar que las alertas de Dependabot/CI heredadas se evalúan de nuevo por revisión actual, sin asumir cierre automático.
- No publicar a Google Play ni a producción sin aprobación explícita; no cambiar versionCode ni firma antes de comprobar el código más alto realmente subido a Play.
- No saturar Actions: primero contratos locales/unitarios, después una sola corrida host y una release de prueba por checkpoint; evitar múltiples workflows paralelos redundantes.

## 4. Arquitectura objetivo (no implementada)

Estructura sugerida, sujeta a auditoría y sin añadir archivos innecesarios:

| Módulo / dominio | Rol |
| --- | --- |
| spdecode_runtime_guard.cpp | Orquestación bounded de detección **del proceso propio**, señales anti-hook/debug, estado de riesgo |
| spdecode_transport.cpp | JNI, canal HTTPS+HPKE, acceso a decisión RASP antes de acciones sensibles |
| spdecode_security.cpp | Pruebas PoP y validaciones nativas ya presentes, nunca reemplazar Play/KeyStore |
| spdecode_keystore*.cpp / CloudKeystorePlatform.kt | Claves privadas no exportables; respetar APIs de Android |
| ReleaseIntegrity.kt | Adaptador pequeño; no mover claves privadas o tokens del SDK oficial a C++ |
| CloudDecodeClient.kt | Flujo Kotlin con SDK Play y UX, rutas de rechazo tipado; sin endpoints ni secretos crudos |
| cloud/web/lib/v2-transport.mjs | Aplicar decisión servidor y verificar Play/PoP, manteniendo la política HPKE |
| docs + tests | Especificaciones, matrices, evidencias y rollback |

Usar C++ para protocolo y verificaciones propias cuando mejore seguridad; **no trasladar AndroidKeyStore, Play Integrity SDK o UI a C++ de forma artificial**. Ofuscación, XOR y nombre ELF sólo retrasan análisis; no sustituyen criptografía o control de servidor.

## 5. Reglas de privacidad, seguridad operativa y compatibilidad

- Sólo observar el estado propio del proceso y veredictos oficiales disponibles; nada de leer datos de terceros o ejecutar comandos en apps externas.
- Nunca invocar root, shell/ADB, Shizuku, Termux, permisos de accesibilidad o escaneo de paquetes para espiar. La app puede ser usada por desarrolladores que legítimamente tienen esas herramientas.
- No bloquear todas las funciones por una heurística que pueda producir falsos positivos; adoptar política gradual, mensajes localizados y mecanismos de remediación, sin revelar secretos/algoritmos de detección.
- No guardar contenido de archivos VPN, tokens de Play, privadas HPKE, mapas de memoria, directorios de usuarios ni lista de apps instaladas en métricas.
- Conservar compatibilidad de IDs/AAD de AndroidKeyStore, cachés y datos cifrados: renombrar rompe descifrado de registros sin migración.
- No crear loops de reintento de Play Integrity, anti-debug o red. Controlar recursos y energía.
- Si RASP falla en un móvil legítimo, detectar regresión en staging y detener rollout. La prioridad es seguridad **y** disponibilidad.

## 6. Entregables obligatorios por fase

1. Documentación del cambio exacto con threat model y estado implementado/no implementado.
2. Código limitado a módulos afectados, tests unitarios, negativos y criterios de falsos positivos.
3. Evidencias de CI por SHA, sin forzar builds firmados en cada commit.
4. Validación Android física separada de compilación y un plan claro de reversión.
5. Evaluación de seguridad del servidor y de la compatibilidad del pin HPKE, versión y servicios; no repetir el incidente del runbook.
6. PR hacia main **solo al estar listo**, nunca auto-merge de un cambio RASP aún sin aprobación.

## 7. Orden de continuación sugerido para el siguiente chat

**Primer objetivo:** confirmar con el usuario si ya descifra después de recuperar HPKE y fijar el baseline operativo; luego **R0 (inventario / pruebas / fixes CI)**, después **R1 (anti-tamper + verificación Play)**, **R2 (anti-debug/Frida)**, **R3 (anti-dump)**, **R4 (ADB/Shizuku/Termux/captura)** y **R5/R6 (servidor + pruebas y despliegue)**.

Evitar comenzar con bloqueos agresivos de Shizuku o Termux: técnicamente no hay una API fiable/universal de Android para espiar su ejecución y se penalizaría a usuarios legítimos. Implementar primero controles criptográficos y detección verificable de manipulación de SP-DECODE.

## 8. Referencias oficiales y antecedentes

- OWASP MASVS-RESILIENCE: https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/
- OWASP MASTG RASP: https://mas.owasp.org/MASTG/knowledge/android/MASVS-RESILIENCE/MASTG-KNOW-0118/
- OWASP runtime code integrity: https://mas.owasp.org/MASWE-0058/
- Google Play Integrity: https://developer.android.com/google/play/integrity/overview
- Veredictos de app access risk: https://developer.android.com/google/play/integrity/verdicts
- Android Secure the Environment: https://developer.android.com/security/fraud-prevention/environment
- docs/NATIVE_HPKE_CPP_MIGRATION.md
- docs/SECURITY_CXX_BOUNDARY_AND_DEPENDENCIES_2026_10_30.md
- docs/V2_HPKE_TRANSPORT.md
- docs/HPKE_VPS_DEPLOYMENT_SAFETY_RUNBOOK_2026_10_30.md

**Advertencia:** este archivo es una hoja de ruta deliberada. NINGUNA fase R0–R6 se considera ejecutada por redactar este documento. Sólo el RASP inicial limitado del apartado 1 existía previamente en la rama fusionada.
