# Evidencia TunnelDOOM 4.2.4

Análisis autorizado del APKS aportado, 26-oct-2026. Base del trabajo:
PR102 HEAD `d7d2f696c349851842c901d691a46dc465f42c8d`.

| Artefacto | SHA256 |
| --- | --- |
| APKS | `7dd96e37fc45552e99c5623ce80055ca0b6422918844f75c4ff4bde0065745c5` |
| base.apk | `7f5de13617e2bc5baadcb997b483bf8152bc9ae39d39ca2862eb14cfface3672` |
| classes3.dex | `2c14ab0d36ad945c805e00287b006802c138903661b2c0a4118a97b96c0ef0d9` |
| res/raw/noobdev.txt | `e662093ebcd6523e4065166fc4732b0d2021fa36baf810c4b67197ecbb0438b4` |
| PNG launcher | `ce33bc4ef6b663f43af31dc72bc32d6d7981fd4cb33bc0d89bc9b1b699187980` |

JADX 1.5.6 fijado por checksum: DEX3 termina parcialmente con **8 errores**.
No se afirma recuperación de todo el código. Las rutas relevantes se revisaron
en fuente y mediante `dex_method.py`:

- `StringCrypter.processString`: **52 instrucciones**; XOR SHA256(test_key),
  salt hexadecimal de 32 caracteres, UTF-8. No hay JNI en este camino.
- `SocketClayMainActivity.j1`: **343 instrucciones**; obtiene 13 campos,
  llama Y0 → callable → w1 → Utils.decrypt → NoobCrypt/NoobPass. Los puertos,
  Bhttp y flags se leen directamente. Los 13 campos de la muestra se abren.
- `ConfigParser.decodeInput`: **21 instrucciones**; GCM y DES heredado.
- `ConfigUpdateco.doInBackground`: dos overloads, **43 instrucciones** en
  total; GET fijo `https://control.tunneldoom.space/config.json`.

`ConfigUtil` consume `R.raw.noobdev=0x7f110001`, recurso de 1212 bytes,
o la caché privada `Zs.png`. No se sustituye este loader por la implementación
histórica `SkProtect.getJSONConfig`, que apunta a otro asset.

`NoobPass.star` contiene ASCII/control, XOR por `QXWR` y reversa Java:
24 caracteres ASCII → SHA256. `NoobCrypt` utiliza CBC con 16 ceros y PKCS7.
La referencia JDK independiente está en `tests/golden/tunneldoom_oracle.java`;
la paridad compara el texto exterior íntegro y todos los campos, no muestras
de primeros registros. El documento real mantiene Version3 y 1 servidor.

No copiar al repositorio la tabla de cuentas de `GoogleFeedbackUtils`,
tokens, claves API ajenas, fuentes JADX, binarios o resultados reales.
Las sustituciones de cuenta ocurren después de descifrar; conservar aliases
del documento, sin reemplazarlos por cuentas del APK. El asset real no los usa.

Parser SKS presente; escaneo de invocaciones en los tres DEX no encuentra
llamadas externas a `convertDataToFile`/`convertInputAndSave`. La llamada de
MainActivity a ConfigParser es `isValidadeExpirou` (fecha), no importación.
Por ello se documenta contrato legado y vectores JCA, no export real actual.

El módulo V2Ray comparte/importa enlaces estándar. No se encontró prefijo
TunnelDOOM ni descarga individual por ID. El POST `ABS /api/verify_token`
es servicio autenticado de cuentas y no se consulta ni integra como catálogo.

El actualizador no pudo alcanzarse desde el proxy de este entorno:
HTTP503/envoy, fallo de conexión upstream. Repetido con UA Dalvik y agente
predeterminado. No se atribuye el fallo al servidor original sin evidencia.
Sin contenido remoto real no se registra un broker público operativo.

Icono: manifiesto `android:icon=0x7f080174`, archivo exacto
`split_config.xhdpi.apk!/res/drawable-xhdpi-v4/ic_launcher.png`, 1000×1000,
16328 bytes. Extraído sin rasterizar, redimensionar ni inventar otra marca.
