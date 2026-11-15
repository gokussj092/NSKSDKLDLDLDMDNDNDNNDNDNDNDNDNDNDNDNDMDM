# Litron Pro 11.0 / build11

## Identidad y alcance

El propietario aportó Litron Pro_11.0.apks para continuar la integración del catálogo en el servidor. AXML confirma com.litron.udp, versionName11.0/versionCode11. APKS22493144bytes, SHA-256 a0b2e01fa614273d471f8897921bd9576dc3bdaa3d25e2ad597c818f267d467b; base25928872bytes, SHA-25683425c38c72a04e0875374cc50706e3eb5ff518104e7edaa1e5f753e675484e1. El certificado extraído tiene huella51633c1390d1ff21a71a1a256f5a81027c929d36385eafdb234a16697b6b607b; no equivale a verificar criptográficamente toda la firma APK. Splits y hashes en generated/identity.json. No se ejecutaron APK/DEX/SO.

## Método observado

Se reutilizó JADX1.5.6 completo con la receta compartida registrada. Salió3 y reportó6078 errores globales; no se afirma reconstrucción completa de la aplicación. Las clases y rutas revisadas se conservan por nombre y SHA-256 en generated/recipe.json: util/ConfigUpdate.java, util/ConfigUtil.java, util/AESCrypt.java, MainActivity.java y adapter/ServerDialog.java bajo com/skyproject/udp.

ConfigUpdate realiza GET de la fuente pública fija https://godtechprime.github.io/litroproadfix.txt mediante HttpURLConnection, sin token ni cuenta; no establece un User-Agent especial. Nuestro cliente se identifica SP-DECODE/1.0 y obtuvo200. Sin redirecciones aceptadas ni sustitución por el endpoint de Litron base. ConfigUtil abre assets/config/config.json o la copia actualizada Config.json mediante AESCrypt.m3311 con el input público de formato godtech25. SHA-256 se aplica directamente a los bytes UTF-8; no usa el paso hexadecimal mayúsculo ni el portador Unicode del método base.

AESCrypt usa Base64, AES256/CBC/PKCS7 y IV16 ceros. MainActivity y ServerDialog abren nueve campos de cada servidor con un segundo input público, ocho espacios ASCII: ServerHost, Username, Password, Payload, ProxyIP, SNI, ChaveKey, NameServer y DNS. Json y los demás datos se preservan; no se intenta descifrar cadenas arbitrarias que parezcan Base64. Campos vacíos permanecen vacíos. CBC carece de autenticación: igualdad con otro lector no demuestra autenticidad criptográfica ni integridad ante manipulación.

## Verificación real y adaptación

El sondeo público real devolvió31768bytes/HTTP200 y el catálogo2.6.7:51 servidores. Se comprobaron el JSON entero y206 campos internos con un oráculo propio Java/JCA, el lector Python y el worker aislado real; coincidencia completa tanto en structuredJson como rawText, isPartial=false. El asset incluido15384bytes contiene versión1.0.0,26 servidores/104 campos, con la misma comparación. Hashes, conteos y límites en RESULTS.md y generated/. No se publican ciphertext ni JSON reales, credenciales, APK ni fuentes decompiladas.

El registro litron-pro-vpn tiene fuente e icono propios y respeta los controles del operador, mantenimiento, TLS/DNS/IP pública y límites existentes. El lector exige JSON válido completo, claves únicas, UTF-8 válido y valores finitos, y falla en bloque ante campos corruptos. Los fixtures de9 campos, Unicode y protocolos futuros son ficticios: no sustituyen las pruebas reales. No se certifican archivos/texto/exportadores de teléfono ni conexión VPN. No hubo compilación Android, merge main o despliegue VPS.
