# SP-DECODE Online — chat nativo y estado de anuncios (2026-11-13)

Rama: `ci/unity-ads-online-qa`.

## Chat: diagnóstico y cambio
La captura del usuario mostraba **dos barras de navegación**: una global
`NativeCommerceScreens.kt` con SP-DECODE/Soporte técnico y otra del contacto
en `CommerceSupportPage.kt`. El soporte y el reporte ahora poseen una sola
barra propia. La lista de chats puede regresar a la cuenta; en una conversación,
la flecha y Back del sistema primero regresan a la lista. En la creación también
se conserva la ruta de vuelta. Cuando el bloqueo local de cuenta está activo,
el contenedor mantiene su encabezado hasta desbloquear. No se alteraron API,
mensajes, autorefresco, permisos de personal ni historial.

Se actualizó la paleta AMOLED a azul petróleo + cian suave, chips de estado,
separadores de fecha, burbujas adaptadas al ancho del texto, compositor y aviso
de conversación cerrada, con cadenas del sistema de localización existente.
Validar visualmente en dispositivo físico, tipografía grande y RTL.

## Estado publicitario confirmado por código, no por suposición
- SDK Online: Unity LevelPlay `9.7.0`, adaptador Unity Ads `5.16.0`, UMP
  `3.2.0`, activados con `-PspdecodeUnityAds=true`.
- Workflow QA firmado ya inyecta IDs **públicos** de Unity:
  App Key `29755d275`, interstitial `ouy4i00ulql2cxj3`.
  UMP usa AdMob App ID `ca-app-pub-6771239583897519~8354694124`.
- El correo **«Buenas noticias: se ha aprobado tu cuenta»** (11 de noviembre)
  acredita aprobación **de la cuenta AdMob**, no la revisión/publicación de la
  aplicación ni el fill de anuncios de Unity/AdMob.
- El correo **«Instrucciones de implementación de AdMob»** contiene el
  AdMob App ID anterior y el **AdMob interstitial unit**
  `ca-app-pub-6771239583897519/1146947081`. Este último **NO** es el
  LevelPlay Ad Unit; no se conectó directamente ni se insertó como reemplazo
  de Unity. El correo no solicita expresamente `app-ads.txt`.
- `cloud/web/public/app-ads.txt` ya contenía la lista autorizada de
  Unity (`unity.com, 162529223, DIRECT, 96cabb5fbdde37a7`).
  Se añadió la línea estándar del editor AdMob validado por correo
  (`google.com, pub-6771239583897519, DIRECT, f08c47fec0942fa0`),
  sin borrar entradas existentes. El commit no despliega automáticamente
  ese archivo: verificar después `https://spdecode.xyz/app-ads.txt`
  y que el dominio concuerde con la ficha de Google Play.
- No se modifican `UnityInterstitialHost.kt`, el ritmo de anuncios ni los
  IDs de Unity/UMP de la APK QA. El modo `spdecodeAdsEveryFileQa` es
  explícitamente **QA** y no debe considerarse verificación de producción.

## Pasos que restan para usar anuncios reales
1. Confirmar en el panel LevelPlay la app Android y su estado de aprobación,
   red Unity Ads mediada, unidad intersticial, fill real y restricciones para
   APK externa a Google Play. Los IDs en código no prueban esos estados.
2. Confirmar que el CMP de Google UMP está publicado para el AdMob App ID y
   que se respetan preferencias por región; probar aceptar/rechazar y
   recuperación del formulario en dispositivo.
3. Confirmar URLs de sitio de desarrollador en ficha y dashboards, publicar
   `app-ads.txt` con deploy verificado y revisar el rastreo.
4. Preparar una **release**, no la compilación de cada archivo QA; mantener
   firmante persistente, Android API/consentimiento, anuncios no bloqueantes,
   certificados y revisión de políticas de red/canal de distribución.
5. Verificar anuncios reales en dispositivos de usuarios autorizados **sin**
   generar tráfico inválido de desarrollador; revisar estados de aprobación,
   errores de fill y políticas. Desactivar test/QA solo al lanzar una release
   autorizada, sin intentar simular impresiones reales como prueba.

Notas: App ID AdMob y publisher ID son identificadores públicos, no
contraseñas. No archivar mensajes privados ni tokens de Gmail/Unity.
