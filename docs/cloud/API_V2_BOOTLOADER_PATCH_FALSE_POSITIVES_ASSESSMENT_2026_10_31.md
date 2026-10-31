# SP-DECODE — Diagnóstico y hoja de ruta: bootloader, parches, Play Integrity y falsos positivos (API V2)

**Fecha:** 2026-10-31  
**Proyecto:** SP-DECODE / Ghost Nexora Studio  
**Rama auditada:** `feat/cloud-selector-private-card-notification-chime`  
**Alcance:** diagnóstico, compatibilidad y plan de mejoras; **sin modificaciones de código ni despliegue**.  
**Prioridad:** alta — bloqueos de descarga del catálogo en instalaciones Android 1.1.25, incluidas algunas entregadas por Google Play.

## 1. Resumen ejecutivo

**Hallazgo principal:** La aplicación y el backend pueden funcionar perfectamente para un equipo y rechazar otro con el mismo APK o AAB. La descarga de catálogo de API V2 depende de una **sesión autenticada**, y dicha sesión está condicionada por **Key Attestation**, requisitos de firma/versión, política de bootloader, frescura de parches, **Play Integrity** (cuando esté exigido), prueba criptográfica de posesión de clave (PoP), y HPKE. No hay evidencia que permita atribuir todos los incidentes a un fallo del catálogo.

En pruebas del VPS se obtuvieron respuestas HTTP 200 para consulta de versión, catálogo, cifrado y 49/49 iconos; la API V2 estaba configurada y operativa. La atestación reportó primero 37 eventos `OS_PATCH_OUTDATED` y 16 `VERIFIED_BOOT`; después de reconstruir el servicio volvió a registrar eventos `OS_PATCH_OUTDATED`. **Esos recuentos son eventos, no usuarios únicos, y no se correlacionaron con el usuario que informó parche de julio de 2026.** Los límites HPKE observados estaban lejos del umbral de IP.

**La elección “4 años” afecta únicamente a las fechas de parches; NO desactiva Verified Boot, no modifica Play Integrity y NO garantiza acceso de equipos con bootloader desbloqueado.** Ambos interruptores de compatibilidad están implementados pero deben configurarse por separado. La política flexible tiene expiración automática de 1/6/24/48 horas, luego vuelve al perfil estricto. Desactivar el requisito de Verified Boot **aumenta el riesgo**, y no garantiza que una cadena de atestación inválida supere el verificador.

**No debemos equiparar** bootloader desbloqueado, ROM personalizada, root, ADB, Shizuku ni Termux. Son condiciones distintas. No existen evidencias confiables de root extraíbles solamente de `deviceLocked` y `verifiedBootState`; el código actual tampoco incorpora un “detector de root” concluyente en esa etapa.

## 2. Auditoría del flujo real

### 2.1 Android 1.1.25

Ruta principal:
- `android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt` → `session()` pide desafío y, cuando corresponde, solicita certificados de hardware con `CloudRequestProof.attest(...)`.
- `CloudRequestProof.kt` → `CloudNativeTransport.attestHardwareKey()`.
- `android/app/src/main/cpp/spdecode_keystore.cpp` → genera una clave Android Keystore ligada al desafío, lee la cadena, exige 2–8 certificados; gestiona StrongBox/TEE y devuelve la cadena. Este componente **no transmite por sí mismo una bandera “root=true”** ni una fecha de parche declarada manualmente por el usuario.
- El cliente envía la cadena en la operación 2 de V2 junto al desafío y los datos de sesión. **Los metadatos de estado de arranque y parches se obtienen del certificado verificado por el servidor, no de campos de UI editables.**
- La operación 10 descarga el catálogo y la operación 11 sus iconos, pero requieren sesión; fallar en operación 2 puede terminar presentado al usuario como “vuelve a intentarlo más tarde”.

**Resultado de auditoría estática:** los nombres de campos y el flujo de certificados concuerdan entre Android y el servidor. Esto **no constituye una reproducción instrumentada** de todos los teléfonos ni descarta errores de proveedor Keystore, ROM, StrongBox, conectividad o versiones de servicios de Google.

### 2.2 API V2 / servicios

- `cloud/web/lib/v2-transport.mjs`: operaciones 1/2 de desafío y sesión, aceptación de firma de clave y comprobación de hardware; las operaciones posteriores necesitan sesión válida.
- `cloud/web/lib/device-security.mjs`: consulta política vigente al verificar una nueva clave y la remite **por enlace privado autenticado** al servicio `key-attestation`. **Android no puede elegir la relajación.**
- `cloud/attestation/src/main/kotlin/Server.kt`: valida cadena, raíz de confianza de Google, revocación, desafío, clave, nivel TEE/StrongBox, identidad/versión/firma de SP-DECODE y, de forma independiente, los interruptores de parche y Verified Boot.
- `cloud/web/lib/v2-device-admission-policy.mjs`: 12, 18, 24, 36 o 48 meses; `enforcePatch`, `enforceBoot`; excepción temporal máxima 48 h; persistencia con revisión y retorno automático a estricto al expirar.
- `cloud/web/lib/v2-play-policy.mjs` y `cloud/web/lib/c3-integrity.mjs`: política **separada** de Google Play Integrity.
- `cloud/web/lib/rasp-policy.mjs`: RASP propio, observación/enforcement condicionado a versión; los nombres de herramientas de desarrollador presentes en el móvil **no son por sí mismos una señal del protocolo**.

### 2.3 Por qué “4 años” puede seguir fallando

| Situación | Resultado esperado actual | Interpretación |
| --- | --- | --- |
| `patchMonths=48`, `enforcePatch=true`, `enforceBoot=true` y bootloader desbloqueado | `VERIFIED_BOOT` | La edad del parche no cambia el requisito de arranque. |
| `patchMonths=48` y parche atestado de más de 48 meses | `OS_PATCH_OUTDATED` o `VENDOR_BOOT_PATCH_OUTDATED` | La ventana sigue teniendo límite. |
| `enforceBoot=false`, cadena no válida o raíz de Google incorrecta | Rechazo de cadena / restricciones previas | El interruptor no desactiva la validación criptográfica. |
| Perfil temporal caducado | Reaparece política de 12 meses y boot estricto | Leer `expiresAt` y `relaxed` antes de la prueba. |
| Dispositivo con certificado no reconocido o app Play/AAB con firmante no incluido | `APP_ID_MISMATCH` | Comprobar allowlist de digests sin publicar firmas o claves. |
| Play Integrity activado y bootloader desbloqueado (sobre todo Android 13+) | Puede fallar `MEETS_DEVICE_INTEGRITY` / `MEETS_STRONG_INTEGRITY` | El interruptor de Verified Boot **propio** no modifica el veredicto de Google. |
| Usuario reporta parche de julio de 2026, rechazo global `OS_PATCH_OUTDATED` | **No atribuible sin correlación** | Puede ser otro usuario o un dato atestado distinto. |

**Precisión:** El fichero `cloud/attestation/src/main/kotlin/Server.kt` exige fechas OS y, si existen, fechas vendor y boot, dentro de una misma ventana. Si el sistema muestra un parche nuevo pero el proveedor/arranque lleva años sin actualizarse, la causa puede ser `VENDOR_BOOT_PATCH_OUTDATED` sin que el sistema OS esté desactualizado. El código registra `OS_PATCH_OUTDATED` **solo** cuando falla específicamente `osPatchLevel`; no se debe atribuir ese código a vendor/boot. Las fechas atestadas deben inspeccionarse por categoría en pruebas controladas, **sin almacenar cadenas ni certificados**.

## 3. Semántica de Verified Boot: no confundir señal con root

La documentación AOSP de `RootOfTrust` distingue:
- `Verified` (habitualmente GREEN): cadena de arranque verificada con la raíz del fabricante.
- `SelfSigned` (YELLOW): verificado con raíz configurada por usuario; distinto de “falló” o “root detectado”.
- `Unverified` (ORANGE): bootloader desbloqueado / sin cadena completa verificable.
- `Failed` (RED): falló la verificación y no hay garantías de integridad de otras partes del estado.
- `deviceLocked` distingue estado de bloqueo del bootloader.

El código actual devuelve la categoría conjunta `VERIFIED_BOOT` cuando `!deviceLocked || verifiedBootState != VERIFIED`. **Mejora propuesta:** separarlas en códigos agregados distintos para no etiquetar falsamente como root a un usuario con bootloader abierto.

Shizuku, Termux, ADB y herramientas similares **no prueban que una app esté manipulada**. Root y bootloader desbloqueado están relacionados en algunos escenarios, pero no son equivalentes. Su presencia no debe determinar por sí sola el acceso al catálogo.

## 4. Google Play: dos niveles de admisión independientes

### Nivel A — Google Key Attestation (VPS)

Activo durante el acceso beta actual, incluso sin Play tokens: cadena Google, hardware, identidad/firma, desafío. El panel puede reducir temporalmente solo límites de parche y Verified Boot, pero **no** la cadena ni la identidad.

### Nivel B — Google Play Integrity (cuando `integrityRequired=true`)

En `cloud/web/lib/c3-integrity.mjs` se exige, entre otros valores, `PLAY_RECOGNIZED`, `LICENSED`, `MEETS_DEVICE_INTEGRITY` y por defecto `MEETS_STRONG_INTEGRITY`. Cuando esta capa vuelva a estar activa:
- En Android 13+, `MEETS_DEVICE_INTEGRITY` está asociado a bootloader bloqueado y sistema certificado.
- `MEETS_STRONG_INTEGRITY` exige adicionalmente actualización reciente de particiones relevantes.
- El veredicto opcional `MEETS_BASIC_INTEGRITY` puede admitir ciertos dispositivos desbloqueados, **pero el código actual no lo acepta como reemplazo de DEVICE o STRONG**. Cambiar esto es una **decisión futura de producto y seguridad**, no un ajuste ya existente del panel.
- Una instalación desde Play y otra desde Telegram pueden tener **firmas de distribución diferentes**; la lista de certificados de app aceptados por el VPS debe verificarse en un entorno seguro, sin publicar los digests completos.
- `PLAY_RECOGNIZED` y `LICENSED` dependen de cómo se instaló y reconoce la app; no son equivalentes a estar en una versión “reciente” por sí sola.

Conclusión: que Play entregue un AAB correcto **no implica** que el dispositivo supere la política de admisión del backend. El mensaje “no descarga el catálogo” puede tener el mismo síntoma aunque el rechazo se haya producido durante login/atestación.

## 5. Hoja de ruta para reducir falsos diagnósticos sin debilitar todo V2

### P0 — Observabilidad de fallos de admisión (antes de seguir relajando)

1. Conservar recuentos agregados de errores de atestación, pero separar `BOOTLOADER_UNLOCKED`, `BOOT_STATE_SELF_SIGNED`, `BOOT_STATE_UNVERIFIED`, `BOOT_STATE_FAILED` y `BOOT_STATE_UNKNOWN` en vez de una sola categoría `VERIFIED_BOOT`. No derivar `ROOT_DETECTED` de estas categorías.
2. Distinguir `OS_PATCH_OUTDATED`, `VENDOR_PATCH_OUTDATED` y `BOOT_PATCH_OUTDATED`; y `OS_PATCH_MISSING`. Nunca publicar valores de certificados en logs.
3. Para una sesión rechazada, permitir correlación **efímera y aleatoria** con el código de diagnóstico mostrado al usuario, sin IP, IMEI, serial, certificados, clave pública, texto ni configuración VPN; caducidad corta y sin identificador permanente.
4. En panel separar métricas por canal de distribución (Play / Telegram), `versionCode`, categoría Android SDK y etapa: `CHALLENGE`, `KEYSTORE`, `ATTESTATION`, `PLAY_TOKEN`, `HPKE`, `CATALOG`, `ICON`, `CACHE`. **Cualquier canal derivado de un dato declarado por el cliente se considera no confiable** hasta ser validado.
5. Crear mensaje Android que diferencie “dispositivo no compatible con política de seguridad” de “servicio temporalmente no disponible”. No mostrar datos de la atestación ni el detalle de raíz/firma a clientes potencialmente hostiles.
6. Auditar si existen restricciones de RASP, SDK mínimo, versión mínima, StrongBox, tokens Play o límites de sesión; son controles adicionales fuera de los dos interruptores.

### P1 — Política por *grado de confianza*, no “todo o nada”

**Recomendación de diseño futuro** (no implementada):
- **Nivel estricto:** certificado Google, app oficial, boot verificado, parches frescos, PoP, HPKE; para funciones sensibles.
- **Nivel compatible supervisado:** certificado Google y firma de app verificados, PoP y HPKE; admitir temporalmente bootloader desbloqueado o parches antiguos solo si la cadena sigue siendo válida. Sesiones cortas, throttling más conservador y mayor observación.
- **Nivel no verificable:** no afirmar que el dispositivo es “seguro” y no conceder acceso a decodificación privilegiada. Ofrecer recuperación, diagnóstico o información pública sin exponer claves ni operaciones sensibles.

No basar la admisión en una simple bandera enviada por Android. Si se desarrolla un acceso de *solo catálogo*, la autorización debe mantenerse del lado del servidor con ámbitos de token distintos; nunca reutilizar el mismo token privilegiado para los dos niveles.

### P2 — Ajustes de antigüedad sin falsos bloqueos

Evaluar usar `osPatchLevel` como referencia primaria (recomendación AOSP) y mantener vendor/boot como señales de riesgo separadas en lugar de bloquear por cualquiera de ellas automáticamente. Diferenciar **ausente** de **antiguo**; nunca interpretar fecha ausente como fecha válida. Considerar margen de fábrica cuando una ROM tenga osPatch reciente pero vendor antiguo, únicamente con certificado y firma válidos.

No establecer “4 años para todos” como norma de producción sin medir exposición de vulnerabilidades conocidas. Preferible probar cohortes graduales con umbrales escalonados, caducidad y rollback.

### P3 — Política explícita para bootloader desbloqueado

No existe un detector perfecto de root sin falsos positivos. Para usuarios que desbloquearon por personalización:
- Permitir un **modo de compatibilidad voluntario y limitado** para tareas de menor riesgo, reconociendo la pérdida de garantías de Verified Boot.
- Conservar cadena de Google/validación de la app, cifrado HPKE, PoP y límites.
- No bloquear solo por presencia de ADB, Termux, Shizuku o nombre de herramientas.
- Mantener `Failed`/RED y errores criptográficos como mayor severidad. Un equipo con bootloader abierto puede fallar antes de leer el estado, por ausencia o incompatibilidad de su atestación; ningún interruptor promete admitirlo.

### P4 — Play Integrity y el plan de salida de beta

Antes de activar nuevamente Play Integrity en producción, decidir formalmente si se exigirá `DEVICE` y `STRONG` para todas las funciones o si habrá una ruta de menor privilegio compatible con dispositivos personalizados. Registrar las consecuencias en Android 13+. No comunicar a los usuarios que los interruptores del panel resolverán Play Integrity cuando esa capa esté obligatoria.

## 6. Matriz de pruebas reproducible

| Caso | Estado | Prueba | Resultado esperado |
| --- | --- | --- | --- |
| A | Android oficial, boot bloqueado, parches recientes, Play | Sesión + catálogo + 49 iconos | Correcto con perfil estricto. |
| B | Android oficial, boot bloqueado, parches de 18–36 meses | Estricto y luego 24/36 | Solo falla por antigüedad si así lo confirma el certificado; el cambio reduce los rechazos esperados. |
| C | Bootloader desbloqueado, **sin root**, app legítima | Estricto / `enforceBoot=false` temporal | Detectar categoría exacta. Aceptar solo si cadena, hardware y firma siguen válidos. |
| D | Bootloader desbloqueado + ROM personalizada | Como C, más test de Key Attestation | Puede fallar raíz, cadena, disponibilidad del Keystore o Play Integrity; no prometer compatibilidad. |
| E | Certificado o firma APK no reconocidos | Todas las políticas de compatibilidad | Debe seguir rechazándose. |
| F | Parche OS reciente + vendor/boot antiguos | Comparar cada dato | Mostrar cuál componente incumple; evaluar política por nivel. |
| G | Google Play AAB | Sesión cuando Play token obligatorio | Verificar `PLAY_RECOGNIZED`, `LICENSED`, firmas aceptadas y DEVICE/STRONG. |
| H | Telegram APK firmada | Sesión con beta V2 aún vigente | Confirmar atestación y firma admitidas; no asumir la misma firma que Play. |
| I | Excepción expirada | Nueva sesión tras TTL | Volver al perfil estricto **sin reinicio de Docker**. |
| J | Root/hooking real, emulador, cadena falsa | Sesión | Mantener rechazo de cadena, PoP o identidad; no crear bypass genérico. |

**Método sugerido:** comenzar con 12 meses + ambas verificaciones; probar 24, 36, 48 meses con boot exigido; solo después, si hay categoría de boot, desactivar temporalmente `enforceBoot` para una cohorte de prueba, conservar `enforcePatch` y observar. Cambiar **un factor por vez**. Comparar nuevas sesiones concedidas, rechazos por código, éxito de descarga, latencia y abusos. Registrar fecha de inicio y de expiración del perfil.

## 7. Criterios de aceptación de futuras correcciones

- [ ] La app distingue errores de autenticación, Keystore, atestación, Play Integrity, catálogo e iconos.
- [ ] La política del panel y el verificador aplican exactamente el mismo plazo y configuración.
- [ ] Los equipos con bootloader desbloqueado, sin root, no se registran como `ROOT_DETECTED` únicamente por boot.
- [ ] Un certificado de prueba con OS Patch válido y vendor antiguo produce un código distinto de `OS_PATCH_OUTDATED`.
- [ ] La firma Play y la firma Telegram se aceptan **solo** si fueron autorizadas explícitamente; una firma desconocida se rechaza.
- [ ] Con Play Integrity obligatorio, los requisitos DEVICE/STRONG se documentan como barreras independientes del panel.
- [ ] Dos perfiles (estricto y compatible) no comparten privilegios inadvertidamente.
- [ ] Todas las excepciones se auditan, caducan y vuelven a estricto.
- [ ] Sin persistencia de IP, cadenas completas, seriales, tokens, claves, contenido descifrado ni configuraciones VPN en logs.
- [ ] Regresión validada con pruebas instrumentadas Android, unitarias Kotlin/Node y casos reales representativos.
- [ ] Sin modificación de API V1 ni ejecución de GitHub Actions sin permiso explícito.

## 8. Fuentes oficiales

- AOSP — Key and ID attestation, RootOfTrust, OS/vendor/boot patch levels: https://source.android.com/docs/security/features/keystore/attestation
- AOSP — Keymaster version binding y actualizaciones de particiones: https://source.android.com/docs/security/features/keystore/version-binding
- Android Developers — Play Integrity verdicts y diferencias BASIC/DEVICE/STRONG: https://developer.android.com/google/play/integrity/verdicts

## 9. Conclusión para la siguiente etapa

**No atribuir los rechazos generalizados a un fallo del catálogo.** Su generación y los 49 iconos superaron las pruebas internas, mientras varias peticiones de atestación fueron rechazadas. El siguiente trabajo no es “desactivar toda la seguridad”: es **diagnóstico por etapa, separación de señales de arranque/patch, políticas de riesgo por función y manejo correcto de las diferencias entre Play y APK externa**.

**Estado de esta documentación:** revisión estática de código GitHub y síntomas aportados desde VPS, complementada con documentación oficial. **No se aplicaron cambios en Android, panel, verificador ni VPS como parte de esta revisión.** No hay todavía correlación individual de los rechazos ni pruebas instrumentadas de los dispositivos afectados.
