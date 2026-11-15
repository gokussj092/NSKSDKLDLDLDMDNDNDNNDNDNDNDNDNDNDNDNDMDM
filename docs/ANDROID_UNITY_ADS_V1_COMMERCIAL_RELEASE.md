# SP-DECODE Online 1.1.27 — Unity Ads y API comercial v1

## Contrato de esta entrega

- **Online**: Unity LevelPlay SDK 9.7.0 + adaptador Unity Ads 5.16.0 (intersticial).
- **Offline**: ninguna compilación ni publicación; continúa pendiente su sistema de licencia.
- **Analizador de APK en edición Online distribuida**: pestaña **Próximamente**.
  Las clases de upload y worker originales se excluyen del código compilado Cloud release
  y se sustituyen por un cliente sin peticiones de red. QA explícito conserva el motor de
  pruebas con `SPDECODE_CLOUD_QA_BUILD=true`. La edición comercial no vende créditos
  ni concede licencias Offline hasta que haya entrega validada.
- **API comercial v1**: `POST /api/commercial/v1/decode`.
  Usa Bearer `spd_api_...`, IP pública autorizada, cuotas y entitlement activo.
  Exige `SPDECODE_COMMERCIAL_API_ENABLED=true` y `CLOUD_TRUST_PROXY=true`.
  La API histórica pública `/api/v1/*` permanece bloqueada (HTTP 410
  `V1_API_DISABLED`). **NO reactivar** el endpoint v1 obsoleto.
- No se habilitan automáticamente `SPDECODE_ANALYSIS_CREDITS_READY` o
  `SPDECODE_OFFLINE_LICENSE_READY` ni `SPDECODE_PAYMENTS_LIVE`.

## Consentimiento y frecuencia de anuncios

La integración de la APK con Unity se construye solo con
`-PspdecodeUnityAds=true`. Google User Messaging Platform (UMP) actualiza el
estado de consentimiento, presenta el formulario CMP cuando es requerido y
solo entonces se llama a Unity LevelPlay si `canRequestAds()` es verdadero.

La opción de privacidad de anuncios está en Ajustes cuando la compilación la incluye.
El estado GDPR se toma de UMP y nunca se declara consentimiento afirmativo sin
confirmación. Se establece CCPA do-not-sell por defecto. Error de carga, consentimiento
o visualización **no bloquea el descifrado ni la consulta del resultado**.

Los intersticiales solo se intentan después de guardar un resultado completo.
Límites: máximo 3/día y al menos 10 minutos entre anuncios. Las peticiones no
incluyen el archivo, nombres, payloads, credenciales, email, ni claves API.

## Activación de Unity en el VPS

1. En el panel Unity LevelPlay crear/configurar aplicación Android, App Key,
   y un **Interstitial Ad Unit ID** con el adaptador Unity Ads.
2. Configurar el CMP/Google UMP con el ID de aplicación AdMob público
   (forma `ca-app-pub-...~...`) y publicar los mensajes de privacidad.
   Si el CMP no está configurado, el SDK debe seguir sin mostrar anuncios.
3. Guardar los tres IDs públicos en `/etc/spdecode/unity-ads.env`:

```bash
umask 077
cat > /etc/spdecode/unity-ads.env <<'EOF'
SPDECODE_UNITY_APP_KEY='APP_KEY_REAL'
SPDECODE_UNITY_INTERSTITIAL_ID='AD_UNIT_REAL'
SPDECODE_UNITY_UMP_APP_ID='ca-app-pub-ID_REAL'
EOF
chmod 600 /etc/spdecode/unity-ads.env
```

**Los ejemplos anteriores NO son identificadores reales.** Antes de publicar
sustituirlos por los proporcionados por el panel; no poner claves privadas,
contraseñas o archivos de firma en este fichero. El script del VPS rechaza
publicar Online sin el fichero e IDs completos y pasa
`-PspdecodeUnityAds=true` a Gradle. La keystore persistente sigue en
`/etc/spdecode/keys/upload-key.p12` y `/etc/spdecode/signing.env`.

## Validaciones antes de distribuir

- CI release verde en el commit EXACTO y artefacto firmado presente (el
  comando `spdecode android public-build online --ci-run ID` lo exige).
- Verificar compilación de variante Unity/UMP con IDs reales, consentimiento
  aceptado/rechazado y fuera/dentro del EEE, carga y cierre de anuncios de prueba.
- Comparar certificado SHA-256 con la firma de APK anterior, incrementar
  versionCode respecto de la última app realmente distribuida y verificar R8.
- Revisar Play Data Safety, privacidad, uso del Advertising ID y reglas CMP.
- Asegurar que no se puede subir APK desde la app pública, que créditos y
  licencias Offline no estén activos, y que la API comercial v1 conserva
  autenticación, cuota e IP. El VPS no se actualiza automáticamente por este commit.

Pruebas de contrato del código fuente:
`python3 -m unittest tests.test_android_unity_release_contract -v`.

Documentación oficial:
https://docs.unity.com/en-us/grow/levelplay/sdk/android/sdk-integration
https://developers.google.com/admob/android/privacy
