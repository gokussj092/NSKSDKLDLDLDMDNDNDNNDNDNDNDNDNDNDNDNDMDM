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
