# SP-DECODE Online — Unity LevelPlay, Unity Ads, AdMob y Google UMP

**Fecha:** 2026-11-11  
**Estado:** cuenta y panel configurados, anuncio todavía **NO verificado en dispositivo**.  
**Alcance:** Android **Online**. La edición Offline y el analizador APK permanecen fuera de esta publicación.  
**Versión de pruebas:** `versionName=1.1.27`, `versionCode=42`. No subir versiones hasta aprobar QA.

## 1. Sistemas y avances

| Sistema | Avance comprobado | Pendiente |
| --- | --- | --- |
| Unity LevelPlay (ironSource) | SP-DECODE registrada; cuenta ironSource activa; dispositivo Android de pruebas registrado | Validación de entrega en dispositivo |
| Unity Ads | Unity ID creada; organización Ghost Nexora Studio; proyecto SP-DECODE; red vinculada en LevelPlay | Probar **carga y visualización** reales y de prueba |
| Mediación | Grupo `All Countries` con ironSource y Unity Ads en bidding | Diagnosticar si hay inventario / errores de carga |
| Google AdMob | App Android SP-DECODE y unidad intersticial creadas | No se usa la ad unit de AdMob dentro de LevelPlay por ahora |
| Google UMP | Mensaje de normativas europeas publicado; opciones Consent, Do not consent y Manage options | Comprobar flujo real y estado `canRequestAds()` |
| app-ads.txt | 163 entradas publicadas en `cloud/web/public/app-ads.txt`; Unity Cloud confirma **actualizado** | Revisar periódicamente si cambian vendedores |
| Android | Dependencias de LevelPlay 9.7.0, adaptador Unity 5.16.0 y UMP 3.2.0 presentes bajo `-PspdecodeUnityAds=true` | QA de callbacks, ready, no-fill, consent, cierre y retorno |
| Firma Android | Firma persistente recuperada e instalada en GitHub/VPS; CI firmó APK | Verificar actualización con la APK que ya tienen los usuarios |
| GitHub Actions | QA aislado `ci/unity-ads-online-qa`: run exitoso **43003667124**, artefacto firmado generado | QA en dispositivo antes de promoción a producción |

## 2. Identificadores (públicos de SDK, no secretos)

- **LevelPlay App Key:** `29755d275`.
- **LevelPlay Interstitial Ad Unit ID:** `ouy4i00ulql2cxj3`.
- **Unity Ads Android Game ID:** `800433738`.
- **Unity Ads Interstitial Placement:** `BP_Interstitial_Android` (confirmar texto exacto desde el botón copiar de Unity; en algunas capturas aparece truncado).
- **Google AdMob App ID / UMP:** `ca-app-pub-6771239583897519~8354694124`.
- **Google AdMob Interstitial Unit (no usada por LevelPlay):** `ca-app-pub-6771239583897519/1146947081`.
- **Organization ID mostrado en Unity Cloud:** `4674284877087` (no confundir con proyecto ni asumir que siempre equivale a Organization Core ID).
- **Unity Cloud Project ID:** `0b9847df-f50f-4af4-b427-a4591b7b7466`.
- **Dominio:** `https://spdecode.xyz/app-ads.txt`.

**No incluir** API keys de servidor, contraseñas, Secret Keys, Google OAuth client secret, contenido de keystore ni tokens de pago en el repositorio o APK. Los identificadores anteriores son públicos o de configuración cliente.

## 3. Historial técnico de CI

1. Se generó el workflow firmado aislado `.github/workflows/android-unity-ads-online-qa.yml` desde el código de `feat/nuevas-integraciones`.
2. La primera ejecución **42998721753** compiló y firmó, pero falló la auditoría `cloud_c5_apk_audit.py` porque el SDK de publicidad empaquetó archivos OMID/HTML/JS que no estaban en la lista de recursos permitidos.
3. La auditoría se ajustó **solo en la rama de QA**, admitiendo nueve rutas concretas del SDK de publicidad cuando se llama con `--unity-ads`; se mantiene el rechazo de otros recursos no identificados, motores de descifrado locales y material confidencial.
4. La segunda ejecución **43003667124** terminó **success** y publicó `SP-DECODE-UNITY-ADS-ONLINE-1.1.27-b42-QA-SIGNED`.
5. La compilación no reemplazó la APK pública, no modificó VPS ni `main`; la numeración se mantuvo en `1.1.27 (42)`.

Workflow: https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/43003667124

## 4. Problema abierto: cero anuncios en dispositivo

**Observación del desarrollador:** múltiples descifrados guardados sin visualizar ningún intersticial.

**No concluir que se debe al límite diario.** En el código previo de `UnityInterstitialHost.kt`, se permitían como máximo 3 anuncios por día, con 10 minutos de intervalo, pero **esos límites se aplican después de cargar un anuncio**. Si `isAdReady()==false`, UMP todavía no permite solicitar anuncios, el SDK no se inicializa o el servidor devuelve no-fill, aumentar el límite no hará aparecer anuncios.

### Hallazgos de revisión de fuente

- La app inicializa anuncios desde `MainActivity.onResume` o tras aceptar los términos propios de SP-DECODE.
- UMP debe obtener estado actualizado antes de llamar a `LevelPlay.init`; `canRequestAds()` es obligatorio y no implica consentimiento forzado.
- El anuncio es un intersticial oportunista tras **un resultado descifrado y guardado**; si no hay anuncio preparado, se entrega el resultado sin bloquear.
- Los callbacks de `onInitFailed`, `onAdLoadFailed` y `onAdDisplayFailed` en la compilación anterior no ofrecían diagnóstico visible, por lo que no se puede establecer todavía causa exacta.
- Otra causa posible es que el dispositivo esté habilitado como prueba en el panel, pero el formato/red no esté entregando inventario. El estado de una instancia en el panel no prueba que haya un anuncio cargado en el teléfono.

### Plan de corrección y QA

1. Añadir **diagnóstico seguro** en Logcat: UMP actualizado / no habilitado; init OK/fail; load start/loaded/fail; show attempt/display/skip/fail; **sin** datos de descifrado, nombres de archivo, IDs de usuario, cookies ni secretos.
2. Activar **Integration Test Suite** únicamente en una compilación especial de QA para probar ironSource y Unity Ads por separado y registrar motivo de falla.
3. Habilitar recarga/reintento prudente (sin bucles de requests) tras fallos de load.
4. Subir gradualmente el límite local a **12 anuncios/día** con **mínimo 4 minutos** entre visualizaciones *solo después* de comprobar fill, sin anuncios invasivos ni impedir resultados.
5. Mantener el tope de LevelPlay definido en panel (al tomar capturas: 8 impresiones/hora, intervalo 4 minutos); el servidor puede imponer límites adicionales.
6. No agregar Banners o Rewarded solo para resolver fallos del Interstitial. Rewarded requiere una recompensa transparente y opt-in; Banner implica UI y permisos que deben diseñarse antes.

## 4.1. Parche preparado en rama aislada (todavía NO promovido)

En `ci/unity-ads-online-qa` se modificó `UnityInterstitialHost.kt` y se añadió una prueba contractual:

- `MAX_DAILY_ADS=12` y `MIN_INTERVAL_MS=240_000L`.
- Si `onAdLoadFailed` ocurre, el siguiente intento elegible solicita una nueva carga tras **45 segundos**; no se generan bucles automáticos ni se bloquea el resultado.
- `onInitFailed` permite volver a intentar inicializar en una reanudación posterior.
- Diagnósticos `SPDECODE_ADS` de UMP, init, load, show y skip. Solo estados, sin datos ni identificadores de usuarios.
- Prueba de compilación firmada: run **43012363138** completado **SUCCESS**; artefacto **SP-DECODE-UNITY-ADS-ONLINE-1.1.27-b42-QA-RETRY-DIAGNOSTICS-SIGNED** (APK 1.1.27/b42, 12,048,908 bytes, SHA-256 `8244469746b17b41f059b3e51bb56c4adb34a3aab2869ac0fe802f1bdb97d9fc`). **Compilación y auditorías aprobadas; entrega real de anuncios no verificada todavía en dispositivo**.
- Esta rama QA se mantiene separada de producción; **no** modificar `versionName` ni `versionCode` durante pruebas.

## 5. Cómo diagnosticar en dispositivo

- Abrir **Unity LevelPlay → Setup/Settings → Test devices** y confirmar que la sesión de prueba para SP-DECODE utiliza el Advertising ID correcto. Activar anuncios de prueba para cada red/ad unit; Unity puede restablecer esta selección al cabo de una hora.
- Usar **LevelPlay Integration Test Suite** en una APK QA: verificar SDK, Unity adapter, `Ad Units`, `Load ad`, `Show ad` y razón exacta de cualquier error.
- Si el **anuncio de prueba aparece** pero el real no: sospechar inventario/country/capping/estado de publicación, no funcionamiento del SDK.
- Si el **anuncio de prueba no aparece**: comprobar conectividad, App Key, Ad Unit ID, consent UMP, inicialización y adapter.
- Recopilar solo estados de diagnóstico (no contenido del descifrado). Ejemplo local, con ADB: `adb logcat -s SPDECODE_ADS:D *:S` para inspección en el equipo de pruebas.
- Verificar que no se muestre anuncio antes de consentir cuando se requiera, y que el rechazo no bloquee la función principal.

## 6. Reglas de publicación

- Hasta que se verifique en dispositivo: **NO PUBLICAR** ni anunciar como versión monetizada funcional.
- Mantener `versionName=1.1.27` y `versionCode=42` durante QA, según solicitud expresa.
- Antes de distribuir como actualización a usuarios existentes, decidir y aprobar incremento de versionCode, y confirmar que firma/canal son compatibles.
- APK Online externa: sin actualizaciones Play automáticas; APK Offline separada; analizador APK en «Próximamente».

## 7. Referencias

- Unity: https://docs.unity.com/en-us/grow/levelplay/sdk/android/integration-test-suite
- Unity: https://docs.unity.com/en-us/grow/levelplay/sdk/android/troubleshoot-no-ads-displaying
- Unity: https://docs.unity.com/en-us/grow/levelplay/sdk/android/interstitial-integration
- Google UMP: https://developers.google.com/admob/android/privacy

## 8. Observación QA en dispositivo: 2 intersticiales / ~15 descifrados (2026-11-11)

**Evidencia reportada por el probador:** En la APK QA con corrección de foco (run [43062469936](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/43062469936)), se presentaron **2 anuncios** tras aproximadamente **15 operaciones de descifrado**. Las restantes operaciones mostraron un aviso similar a `Anuncios QA: sin anuncio, error 503`; el código no se ha confirmado mediante captura o Logcat.

**Conclusiones sustentadas:**

- La ruta Android → consentimiento/LevelPlay → anuncio listo → pantalla completa **funciona al menos en dos ocasiones**. El fallo ya no es «cero anuncios» en todos los casos.
- Este mensaje, **si** comienza por `Anuncios QA: sin anuncio, error ...`, toma el número del callback `LevelPlayAdError.errorCode` en `UnityInterstitialHost.kt`; no prueba por sí mismo un HTTP 503 de `api.spdecode.xyz`.
- `503` no figura en la tabla pública actual de errores Android de LevelPlay; no asignar automáticamente «no fill». Las definiciones documentadas incluyen 509 (no ads to show), 510 (server response failed), 524 (placement pace/cap), 526 (ad-unit session cap).
- El modo de prueba deshabilita los límites **locales** de 12/día y 4 minutos, pero **no** los límites configurados en el panel LevelPlay ni garantiza inventario de cada red.
- `requestLoadWhenReady()` solicita otro anuncio tras cerrar el anterior; ante error, bloquea nuevos intentos hasta 45 segundos y solo vuelve a cargar cuando ocurre otro evento elegible. Repetir 15 descifrados rápidamente no garantiza 15 anuncios preparados.

**Acción de diagnóstico siguiente:**

1. Confirmar texto **exacto** y captura del aviso, especialmente si dice `503` u otro código.
2. Hacer dos pruebas separadas: **Integration Test Suite** (red por red, con inventario de prueba), y 3–4 descifrados espaciados al menos 4 minutos para evaluar las restricciones de LevelPlay sin recurrir a decenas de solicitudes consecutivas.
3. Registrar en QA de forma segura `onAdLoadFailed` con **código y mensaje normalizado** del SDK, `onAdLoaded`, `onAdDisplayed`, `onAdClosed`, sin incluir datos del archivo ni datos del usuario.
4. Revisar `All Countries` y límites de intersticial en el dashboard de LevelPlay. Aumentar cuotas solo cuando se confirme que el problema es un límite, y no un error de red o disponibilidad.
5. Mantener versión `1.1.27 (42)`, APK de QA y firma persistente. **No publicar todavía.**

Fuentes de referencia: [Errores Android LevelPlay](https://docs.unity.com/grow/levelplay/sdk/android/advanced-settings), [Intersticial Android](https://docs.unity.com/en-us/grow/levelplay/sdk/android/interstitial-integration).

## 9. Diagnóstico confirmado: error 509 en secuencias rápidas (2026-11-11)

El desarrollador confirmó expresamente que el error indicado por la APK QA era **509**, no 503. En aproximadamente 15 descifrados rápidos se mostraron 2 anuncios; una nueva prueba también produjo **2 intersticiales**, y los demás intentos inmediatos mostraron 509.

- **Definición oficial LevelPlay Android:** código **509**, `Show Fail: No ads to show`, aplicable a intersticiales y rewarded. Referencia: https://docs.unity.com/grow/levelplay/sdk/android/advanced-settings
- **Conclusión probada:** el SDK tiene al menos dos impresiones funcionales. El problema de foco anterior no bloquea toda la publicidad.
- **Hipótesis, no diagnóstico cerrado:** una nueva solicitud de anuncio puede no haber terminado de cargar cuando comienza otro descifrado; también puede faltar inventario de alguna red o aplicarse restricciones de servidor. El 509 no identifica inequívocamente cuál de esas causas se produjo.
- **Código actual:** `onAdClosed` llama a `requestLoadWhenReady()`; se usa `isAdReady()` antes de presentar; la APK de QA conserva una ventana para recuperar el foco y no bloquea el resultado de descifrado. Los fallos de carga aplican una pausa local de 45 s antes de intentar otra carga. La prueba anula la frecuencia local, pero no puede anular controles de LevelPlay.
- **Siguiente prueba recomendada:** realizar 3 descifrados espaciados 3–5 minutos, verificar `onAdLoaded`, `onAdLoadFailed` y la mediación por red desde Integration Test Suite. Mantener ads de prueba. Evitar solicitar un intersticial con cada operación rápida en producción.
- **Sin cambios nuevos en código, versión, firma o VPS:** `1.1.27 (42)` sigue en QA hasta decisión de publicación.

## 10. QA catálogos: JSON íntegro en Inicio + intersticial (2026-11-11)

**Petición funcional:** aplicar a las solicitudes de resultados de catálogo VPN el mismo comportamiento publicitario de la prueba de archivos; navegar a Inicio con el JSON visible, sin el aviso `resultado demasiado largo / exportar desde historial`.

**Implementación provisional en la rama `ci/unity-ads-online-qa` (no promovida a producción):**

- Flujos cubiertos: `decodeNurServers()` y `decodeServerVpnProvider(id)` después de una respuesta de descifrado correcta. Los refrescos de la lista de apps/catálogos de metadatos no son resultados de JSON y no activan publicidad.
- En el transformador de `android/app/build.gradle.kts`, `presentDecodedRecord` distingue `nurservers` y `vpnservers`: establece `result=entry`, `tab=0` y `showLargeResultWarning=false` para catálogos; se mantiene el control previo para otros archivos o textos excepcionalmente grandes.
- `CompleteResultCard` usa `LargeResultViewer` / `NativeResultEngine` y `ContinuousJsonView`, que muestra el contenido indexado con scroll continuo. La vista contiene el JSON completo y mantiene la exportación directa desde Inicio.
- Los dos flujos de catálogo llaman `onlineAds?.onSavedResult(...)` con la misma unidad de LevelPlay y manejo de foco/carga del modo `spdecodeAdsEveryFileQa`; siempre después de completar el resultado. No se alteran UMP ni los límites que impone el servidor de LevelPlay.
- La APK de pruebas conserva **1.1.27 (42)** y la firma persistente. Código del cambio: `4bd6952fba6da44d37888ae1a369e11827d82193`. Workflow de QA: [43106942212](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/43106942212).
- **Estado del workflow:** ejecución **43106942212** terminada en **SUCCESS**, APK de QA firmada de **12,048,903 bytes** con SHA-256 `b49e18e7ecf1c8c4535a02f981188d7615ab362ec4a89568c9f7aff8b202fa12` (ZIP GitHub `sha256:a73800a9ed4967825fb990f21642308614ecb1f72a733ec2513a937397bd47b8`). **Resultado en un teléfono aún no verificado**; comprobar memoria/rendimiento con catálogos grandes e impresiones 509 si se repiten operaciones demasiado rápido.

**Casos de aceptación en móvil:** 1) catálogo NUR con JSON completo en Inicio; 2) proveedor VPN con JSON en Inicio y scroll; 3) exportación del JSON sin pasar al historial; 4) intersticial si el SDK lo tiene cargado; 5) ante error 509 o falta de inventario, el resultado se entrega igualmente; 6) no aparece el aviso de longitud para estos catálogos.

## 11. Cierre de QA confirmado y preparación de producción (2026-11-11)

**Confirmación del desarrollador:** la APK QA de la ejecución [43106942212](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/43106942212) funciona correctamente tanto para descifrado de **archivos** como para descarga/descifrado de **catálogos NUR/Server VPN**. Los catálogos regresan a Inicio con JSON visible, sin el aviso antiguo que obligaba a exportar desde el historial. Se han visto intersticiales en ambos flujos. Las ejecuciones rápidas pueden mostrar código **509** (LevelPlay sin anuncio listo), que nunca debe bloquear el resultado.

### Acciones obligatorias antes de producir

1. **Promover los cambios probados desde `ci/unity-ads-online-qa` hacia `feat/nuevas-integraciones`**, conservando el parche de visor JSON y recuperación del foco. La rama de integración aún tiene la implementación publicitaria anterior y no basta con compilarla sin cambios.
2. **Apagar el modo diagnóstico:** no pasar `-PspdecodeAdsEveryFileQa=true` en la compilación real. `SPDECODE_ADS_EVERY_FILE_QA=false` es el valor predeterminado; en ese modo `showQaFeedback()` retorna antes de llamar a `Toast.makeText()`. De ser posible, separar por completo código diagnóstico del artefacto público mediante source sets. Los registros técnicos no deben contener contenido de resultados, contraseñas, nombres de archivo ni identificadores privados.
3. **Restaurar límites locales para uso real:** 12 impresiones diarias y 4 minutos mínimos desde la última visualización, además de los límites del dashboard LevelPlay. QA actual deshabilita solo esos límites locales.
4. **Decidir disparadores de producción:** después de guardar archivo o catálogo con éxito, si el anuncio está listo. Nunca interrumpir una descarga, bloquear la visualización del JSON ni imponer un anuncio por cada operación inmediata. Sin anuncio o con código 509, continuar silenciosamente.
5. **Verificación de privacidad y publicación:** UMP actualizado antes de pedir anuncios; respetar opciones de privacidad; probar aceptación/rechazo; revisar Play Console Data safety y declaraciones de anuncios, política de privacidad, ads.txt y SDKs terceros.
6. **Verificación de firma y distribución:** mantener firma persistente, comprobar actualización sobre APK anterior y APK externa versus AAB Play. **No** usar el mismo `versionCode=42` para una actualización de Play si ya fue publicado ese número: el incremento requiere aprobación explícita.
7. **QA smoke antes de publicación:** casos NUR, Server VPN, .hc, .ehi, sin anuncios, 509, sin foco, JSON largo, exportación, importación cancelada, UMP revocado y reinicio de actividad.
8. **Producción aún no publicada:** esta nota no confirma que el código probando esté fusionado, desplegado ni autorizado para lanzamiento.

### Fases de monetización

- **Fase A (inmediata):** estabilizar Interstitial y medir sesiones, solicitudes, fill, impresiones y retención. Preparar binario release sin Toast de QA.
- **Fase B (opcional):** Banner adaptativo mediante una unidad publicitaria propia, en espacio fijo de pantallas adecuadas, sin ocupar el área del JSON ni superponer controles. Crear Ad Unit y confirmar oferta de redes antes de implementarlo.
- **Fase C (al habilitar tienda/créditos):** Rewarded **opt-in**: premio claro, verificación de finalización (callback/SSV cuando esté disponible), concesión idempotente en servidor y protección antifraude. No prometer créditos hasta estar implementada la economía y conciliación.
- **Fase D (para mejorar el fill):** revisar la incorporación real de la red AdMob como demanda adicional en LevelPlay. Tener App ID y UMP configurados no significa que AdMob ya participe en mediación; requiere alta de red, unidades, adaptador y validación del dashboard.

**Documentación oficial:** https://docs.unity.com/grow/levelplay/platform/settings/capping-pacing ; https://docs.unity.com/en-us/grow/levelplay/sdk/android/banner-integration ; https://docs.unity.com/en-us/grow/levelplay/sdk/android/rewarded-ads-integration
