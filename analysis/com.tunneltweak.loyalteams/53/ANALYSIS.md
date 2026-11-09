# Tunneltweak — build 53 / 6.2.3

Se adquirió y verificó la identidad del paquete com.tunneltweak.loyalteams:
versionCode 53, versionName 6.2.3. Los hashes de distribución, base APK y
certificado extraído están en generated/identity.json. Se cotejó SHA-1 del
certificado con la distribución previa; esto no sustituye una comprobación
criptográfica completa de firma APK.

## Causa del fallo

La solicitud de SP-DECODE llevaba x-app-version: 51. El servidor respondió HTTP
426 con status update_required, minVersionCode 53 y latestVersionName 6.2.3.

ServerConfigManager.fetchFromUrl conserva la fuente fija
https://tunneltweak.com/api/servers, GET, User-Agent TunnelTweak/1.0 (Android),
ngrok-skip-browser-warning true, x-cfg-keyed 1 y obtiene x-app-version del
versionCode real de la aplicación. La corrección utiliza 53, el build del APK
adquirido; no un valor inventado ni un intento de eludir autenticación.

La ruta pública volvió a HTTP 200 sin clave de suscripción. No se intentaron
cuentas privadas, suscripciones premium ni tokens de integridad simulados.

## Cifrado

SecureConfigEncryption mantiene el método ya integrado: PBKDF2-HMAC-SHA256,
10000 iteraciones, clave 256 bits, salt16, nonce12, AES-GCM con tag128 sin AAD.
La constante pública del cliente y los lectores de perfiles se conservan.
No fue necesario reemplazar las primitivas criptográficas.

La salida conserva el sobre, announcement y todos los campos de data. El
catálogo real completo coincidió con el oráculo Java/JCA existente y con el
worker aislado. Los archivos TTPBE1, CBC/XOR y las rutas históricas conservan sus
pruebas; no se certifica una nueva exportación real de teléfono.

## Herramientas reutilizadas

- Descargador APKPure de analysis/com.tunneldoom.http/432/tools/acquire.py:
  sin cambios, mediante wrapper por aplicación e identidad Androguard 4.1.3.
- Instalador y JAR verificados JADX 1.5.6 de scripts/apk_analysis/decompile.py;
  CLI auto con salida privada. Hubo errores de descompilación ajenos a las
  clases revisadas; no se declara descompilación completa de toda la app.
- tests/golden/tunneltweak_oracle.java y tunneltweak_vectors.json: sin cambios.
  El nuevo verify.py aplica ese mismo oráculo al catálogo real completo.
- Los hashes de las herramientas reutilizadas están en dependencies.lock.json.
  No se copian binarios, fuentes descompiladas del proveedor ni catálogos a Git.

Se conservan scripts propios de adquisición, inspección, solicitud y verificación
en tools/. No se ejecutó código del APK. La firma APK completa, el despliegue VPS
y una exportación real independiente del teléfono quedan fuera de lo validado.

