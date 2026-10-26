# Evidencia actual: TunnelDOOM 4.2.7 / 4.3.0

Actualización autorizada del 26-oct-2026 sobre `e5f2c50c`, PR102.
Se descargaron y analizaron los XAPK, sin instalar ni modificar la app:

| Versión | XAPK SHA256 | base.apk SHA256 |
| --- | --- | --- |
| 4.2.7 (427) | `e9aa33e2407783246c50c5896ada23f9963994338e1526da5988c0775e8d326b` | `b753a8015d6a8409d2a7b0492b1ba71c5ef18d3e0a8ac7b3100ef72d3a5ad438` |
| 4.3.0 (430) | `930e45d6356203abb8d2181b234f888a2d6499c36764a09774f2712ea62a4661` | `c576d424dd85028dbd092312f37baa0cdbfd112eed67bdf1e9bf05f2816ece97` |

El nombre/código reales coinciden con esas versiones y el paquete es
`com.tunneldoom.http`. Certificado DER SHA256 en los tres builds:
`12704504f5711f22d78ee436f38baeb90557c2fa72c4dfb281c766f59800461d`.
Esto compara el certificado con el adjunto original del usuario, no sustituye
una auditoría de publicación ni un análisis de malware.

Fuentes observadas de descarga: APKPure `/download/4.2.7` y `/download`;
ambas páginas proporcionaron el link directo XAPK y SHA256 del archivo.
La consulta indexada web presentaba versiones atrasadas: la comprobación de
versiones se hizo sobre los bytes descargados, no sobre el snippet.

`ConfigUpdateco.doInBackground` de430 contiene el GET literal
`https://panel.tunneldoom.space/config.json` (43 instrucciones sumando sus
dos overloads). Sin cabeceras nativas de firma/tiempo. La427 apuntaba a
`panel.proeducativa.com/panel_v2/api_servidores.php` con `SecurityHelper`
y `libapp_security.so`; no se reproduce esa firma ni se usa esa API.
El endpoint proporcionado por el usuario HTTP7676 es distinto y no devolvió
respuesta desde aquí. No se integra una receta GCM sin muestra real.

Los helpers StringCrypter, NoobPass, NoobCrypt, ConfigUtil y ConfigParser de
430 son idénticos a424 al retirar comentarios de procedencia de JADX.
El recurso noobdev es byte a byte igual en424/427/430: plantilla Version3,
1 entrada vacía, no un catálogo real. El recurso original de launcher430
`config.hdpi.apk!/res/drawable-hdpi-v4/ic_launcher.png` es byte a byte igual
al PNG ya registrado, SHA256 `ce33bc4ef6b663f43af31dc72bc32d6d7981fd4cb33bc0d89bc9b1b699187980`.

La descarga430 devolvió HTTP200, 662936 bytes, SHA256
`62a83ca9e60d692f707476e3cc56300cd64ab965d562f2ff1fc6f6b92a123f2d`.
Se obtuvo **Version473 /387 servidores /5031 campos cifrados**; JSON completo
renderizado435343 bytes. Texto exterior y todos los campos iguales al oracle
JCA independiente y al worker aislado. Una segunda descarga CLI produjo el
mismo documento completo. No hay aliases de cuenta del mapa estático en los
387 registros; no se copiaron cuentas del APK al código.

El broker público usa origen/ruta fijos y rechazo de redirects, controles
persistentes y validación del resultado entero. El egress Node nativo falla
en este entorno; pruebas DNS/IP/TLS, sesión y JSON del gateway con mocks,
respuesta real obtenida por Python/HTTPS. No se afirma despliegue/VPS probado.

Sigue pendiente una exportación SKS real y ruta UI de import/export del
build nuevo. Las primitivas reutilizadas no certifican un archivo inexistente.
La extracción JADX es parcial:427 terminó con8 errores; en430 se verificaron
las rutas relevantes con DEX. No se afirma recuperación de todo el código.

## Evidencia histórica de la 4.2.4

### Análisis inicial TunnelDOOM 4.2.4

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
