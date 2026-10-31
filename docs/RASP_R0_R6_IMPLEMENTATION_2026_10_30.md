# SP-DECODE — Implementación R0–R6 y gates de aceptación

Fecha de trabajo: 2026-10-30 (America/Tijuana). Rama: `feat/post-native-security`.
Base auditada: `cd8619b5a7d1312af035eb3c9191ce0d1e7310f4`.

El usuario autorizó implementar todas las fases R0–R6 en este turno, superando la restricción histórica de no iniciar R1. Se conserva la prohibición de fusionar main, cambiar versiones/claves o desplegar producción. **Código implementado no equivale a aceptación de producción.** La ausencia de un Android físico conectado y de acceso al VPS de staging impide registrar sus pruebas como aprobadas.

## Estado por fase

| Fase | Implementación realizada | Aceptación pendiente |
| --- | --- | --- |
| R0 | Baseline reproducido; JNI, firma, R8/NPVS y HPKE preservados; runner único host/release/Compose; comparación de la batería Node contra el SHA base | Play/HPKE real, métricas físicas y ensayo del operador completo sobre staging representativo |
| R1 | Todos los firmantes ACTUALES deben estar autorizados; no basta un firmante histórico o uno entre varios. Comparación de segmentos ELF RX con el mismo archivo/inodo/dispositivo mapeado; ASLR y offsets APK contemplados; hardening ELF auditado por ABI; branch protection ARM64 | Play App Signing y QA reales; modificaciones previas a la carga y reemplazo de verificadores no quedan resueltos por el chequeo local; CFI opcional pendiente de matriz específica |
| R2 | Evidencia separada de observación; TracerPid/JDWP, marcadores ejecutables y cambios de código. Arranque/foreground por eventos y comprobación nativa antes de acciones sensibles; sin servicios/timers de vigilancia | Frida/Xposed reales y falsos positivos en OEM/ART; no se promete detectar toda sustitución de métodos JNI/GOT/PLT |
| R3 | RAII de buffers/claves HPKE y P-256 ante excepciones; limpieza de salida AEAD fallida; expiración oportunista de contextos HPKE; listas NPVS retienen metadatos públicos y cargan material sólo al seleccionarlo; pantalla privada opcional | Medición de heap/RAM y fallos en dispositivos; los Strings JVM, identidades NPVS exportables y resultados visibles siguen teniendo ventanas de exposición |
| R4 | No se enumeran paquetes/procesos ajenos ni se piden permisos invasivos. ADB/Termux/Shizuku/VPN no son señales de bloqueo; veredicto Play captura/control separado de overlays y no evaluado | Opt-in de app access risk en Play Console y matriz real de accesibilidad, perfiles de trabajo y captura |
| R5 | Reporte versionado incluido en metadata HPKE; PoP y action hash siguen ligados al mismo ciphertext. Backend evalúa tras autorización independiente, elimina `_rasp` antes de worker, aplica política por versión y revoca sólo sesión afectada; contadores agregados con TTL | Calibración y aprobación de `enforce`; un cliente comprometido puede mentir sobre señales y no se transforma un reporte limpio en autenticación |
| R6 | CI consolidado host/R8/ABIs/locales/ELF, pruebas de manipulación de DSO real, interoperabilidad crypto, Docker/Compose aislado, smoke instrumentado Android y validador de evidencia de promoción | Ejecutar instrumentación física, beta Play, consumo/latencia y restauración real. **No cerrada ni lista para producción** |

## Evidencia local reproducida

- 25 descriptores JNI Kotlin/C++ coinciden, más puente Android Keystore preservado.
- 31 pruebas Python de R0/R8/NPVS, actualización HPKE, UI/firmas, modificación de ELF real y validador de evidencia: PASS.
- 26 pruebas Node HPKE/V2/RASP: PASS. Incluyen bootstrap/sesión/operación usando HPKE-only real, respuesta autenticada, reporte alterado, replay, revocación selectiva y kill-switch que no rescata sesiones revocadas.
- Interoperabilidad C++ Mbed TLS 3.6.7 ↔ Node: HPKE RFC9180 PASS y catálogo P-256 PASS. Archivo oficial comprobado con el SHA256 existente del proyecto; no se cambiaron dependencias/keys de producción.
- Sintaxis C++ JNI comprobada con cabeceras JDK oficiales, `-DNDEBUG -O2 -Wall -Wextra -Werror`.
- DSO de laboratorio: original → MATCH; W+X → CHANGED; bytes RX alterados → CHANGED; restauración → MATCH; archivo eliminado → UNKNOWN. No se ejecuta la función con bytes alterados ni se toca otro proceso.
- Batería Node amplia en el entorno local, antes de añadir el último test HPKE-only: base **404 tests, 346 pass, 56 fail, 2 skip**; candidata **411 tests, 353 pass, 56 fail, 2 skip**. Mismos nombres de fallos; ninguno nuevo. Son fallos heredados de catálogo/proveedores/fixtures; no se desactivaron ni se declara verde global. Los tests nuevos dirigidos sí pasan. Investigar la deuda antes de promoción.
- Docker y Android SDK/dispositivo no están disponibles localmente. Las tareas respectivas se prepararon en CI; registrar su resultado observado abajo. La mera existencia del workflow no es evidencia de ejecución.

## Fronteras y comportamiento

`ReleaseIntegrity` verifica autenticidad de paquete/certificados y flag debuggable de release. Las señales de runtime ya no provocan `finishAndRemoveTask` por un nombre de módulo. `MainActivity.onResume` solicita observación en IO; el acceso sensible vuelve a comprobar desde JNI bajo política autenticada. No hay escáner global de herramientas.

`spdecode_code_integrity.cpp` localiza su DSO por dirección, recorre sólo PT_LOAD ejecutables no escribibles y compara bloques de 4096 bytes con el archivo mapeado en `/proc/self/maps`, verificando inodo/dispositivo. Límite: 2 MiB de mapas y 32 MiB de código. Soporta librería extraída y mapeo directo de APK mediante offsets del mapa. Fallos de lectura/referencia se distinguen de cambios confirmados. JIT/otros módulos/datos relocados no se comparan. No es autenticación criptográfica del archivo: la firma APK/Play/attestation sigue siendo la frontera autoritativa.

El reporte sólo contiene `v`, `signals`, `evaluated` y `elapsedUs`, nunca mapas, nombres de aplicaciones, tokens o contenido VPN. Bits: 1 trazado, 2 marcador de módulo, 4 código modificado, 8 debugger Java. La máscara `evaluated` indica qué observaciones se hicieron; 0 no significa dispositivo limpio. Un marcador de biblioteca aislado es advisory, no bloqueo.

Los reportes viajan dentro del JSON que se cifra una sola vez. Su ciphertext exacto mantiene PoP y Standard Integrity. El backend valida primero sesión, PoP, replay, coste e integridad de acción; sólo después evalúa y retira `_rasp`. Un reporte falsificado no sustituye Play/hardware/certificados/versión/nonce. No se envían señales por una cabecera sin autenticar.

## Política y reversión

Variables nuevas, propagadas en Compose sin modificar el VPS:

| Variable | Default | Efecto |
| --- | --- | --- |
| `CLOUD_RASP_MODE` | `observe` | `off`, `observe`, `enforce`; sólo controla RASP adicional |
| `CLOUD_RASP_MIN_VERSION_CODE` | `38` | Umbral de aplicación de la nueva política; código fuente sigue 1.1.24/b35 |
| `CLOUD_RASP_ACCESS_MODE` | `observe` | Política complementaria del veredicto Play sobre captura/control |

No activar enforce por defecto con clientes antiguos b35/b37, que no enviaban este reporte. En una prueba controlada de esta rama b35 se puede configurar explícitamente el mínimo 35. La promoción futura debe coordinar una versión nueva, fuera de este turno. Modos/umbrales inválidos fallan configuración; exigir access-risk necesita Play y action Integrity disponibles.

Enforce: evidencia directa alta o evaluación incompleta cancela la operación sensible; los nombres aislados de módulos son advisory. Se revoca sólo el jti de la sesión implicada en el servidor. El modo local se recibe en respuesta HPKE autenticada de sesión; la bootstrap/renegociación permanece disponible para recuperar la política del servidor. Off no desactiva HPKE, firma, Play, hardware, proof, caducidad ni límites. Las variables preexistentes de integridad conservan sus decisiones independientes.

`KNOWN/UNKNOWN_CAPTURING` y `CONTROLLING` pueden limitar una acción al activar explícitamente la política; overlays aislados son advisory. Ausente/vacío/desconocido no equivale a evaluación limpia. No se conoce de manera universal si Shizuku/Termux están activos, ni se afirma detectarlo.

Contadores: `spsec:rasp:<día>:<build-acotada>:<estado|bucket-latencia>`, TTL 8 días, sin identificadores de usuario/dispositivo. Los buckets permiten una distribución aproximada; no son una medición física p95 certificada. Un fallo de métricas no cambia la decisión de autorización.

## Memoria y compatibilidad NPVS

NPVS v1/v5/v6 sigue en worker. Las identidades se guardan con AES-GCM/Android Keystore en noBackupFilesDir. Las listas y pickers ya no conservan cada JSONObject privado descifrado: los Entry contienen metadatos y una lectura explícita de material. El formato de disco, consentimiento, exportación del usuario, contraseña y credenciales de destinatario no cambian. El material elegido y Strings visibles necesitan memoria JVM transitoria, que no puede borrarse con garantías de C++.

Los nuevos guard RAII cubren salida excepcional de HKDF/HPKE, claves derivadas, constructor RNG/AEAD y buffers AEAD fallidos. Los contextos HPKE son one-shot, tienen límite 64 y expiran a 300 s al acceder a la tabla; `finally` de Kotlin descarta los normales. El plazo contempla 60 s de preparación Play + 30 s de token + 10 s conexión + 165 s del catálogo pesado, evitando cortar una respuesta NUR válida. No hay hilo permanente que prometa borrado instantáneo durante inactividad. Los datos necesarios para mostrar/exportar siguen siendo observables con control del proceso/SO.

La opción de Ajustes **Pantalla privada** aplica FLAG_SECURE, persiste la elección y permite desactivarla para soporte/capturas. Default desactivado; textos en los 14 idiomas existentes. No añade permisos; el manifest conserva allowBackup=false.

## CI y pruebas restantes

El workflow existente `post-native-r0-host.yml` se amplió, con un solo disparador de cambio de ese archivo en la rama. Host pasa antes de R8 y Compose. No firma, sube a Play, publica artefactos ni despliega VPS. R8 audita idiomas, empaquetado cloud y hardening de las cuatro ABIs.

Compose construye una imagen de laboratorio sin puertos públicos y genera claves sintéticas efímeras. Ejecuta las funciones REALES de pre/postflight del operador contra contenedores recreados: persistencia, falta de keyring, cambio de KID, downgrade OFF y restauración. **No sustituye el update/rollback completo del operador con volúmenes, Nginx, worker, backups y Play de un VPS representativo.**

`scripts/ci/rasp_release_gate.py evidence.json --commit <SHA>` rechaza evidencia ausente/stale. Exige fabricantes, APIs frontera, canales, falsos positivos cero, p95 con presupuesto declarado, CPU/RAM/batería, pruebas de recuperación y staging. APIs por debajo del mínimo del servidor verifican denegación de política sin crash, sin fingir soporte de descifrado. Una matriz completa registrada manualmente aún requiere revisar sus referencias originales.

No hay evidencia física adjunta a este checkpoint. R0/R6 permanecen con gates abiertos. Las pruebas Android incluidas deben ejecutarse en la matriz real; su fuente no acredita ejecución.

### Primera ejecución remota de esta implementación

Run `41167255787`, SHA `65206a327a770c2d6121baa255d92a89c12ceb2c`: host completo SUCCESS. R8 detectó en arm64 una deducción de tipos distinta entre `Elf64_Xword` y `uintptr_t` en el comparador de código. Se corrigió con conversión explícita tras el límite de tamaño; el DSO host volvió a superar manipulación/restauración. No promover ese primer SHA. Se añadió además un test del presupuesto de tiempo Play+NUR y se ajustó la expiración HPKE a 300 s. Los textos de pantalla privada cubren los 14 idiomas. La siguiente ejecución debe validar el checkpoint corregido.
