# TunnelDOOM VPN 4.2.4 / 4.2.7 / 4.3.0

Paquete `com.tunneldoom.http`. PR **#102**, rama
`feat/ha-tunnel-plus-1-7-1-decoders`. Backend Python/Cloud; sin cambios de UI.

## Estado actual, 26-oct-2026

Se descargaron **4.2.7 (427)** y **4.3.0 (430)** de APKPure. Se comprobaron
nombre/código de versión dentro de los APK y el mismo certificado SHA256 de
la 4.2.4 aportada. Los lectores de catálogo y sus primitivas son iguales;
la dirección del actualizador cambió. No se usó una variante de Telegram.

| Entrada | Estado |
| --- | --- |
| Catálogo incluido `res/raw/noobdev.txt` | Version 3, una plantilla `prueba`, sin parámetros de conexión; el mismo recurso en los tres builds |
| Catálogo remoto de build 430 | **Version 473, 387 servidores, 5031 campos cifrados**. JSON completo igual a JCA, CLI y worker aislado |
| `.sks` | Parser legado incluido: GCM/DES canónico Fenix; pendiente exportación real y ruta UI activa del build nuevo |
| Texto propietario / Cloud individual por ID | No identificados; los enlaces V2Ray estándar usan los lectores existentes |

## Fuentes distintas por versión

- **424:** `https://control.tunneldoom.space/config.json`, inaccesible aquí.
- **427:** `https://panel.proeducativa.com/panel_v2/api_servidores.php`;
  `SecurityHelper` prepara cabeceras de firma/tiempo mediante una librería
  nativa. No se integra ese flujo: la fuente actual de 430 es pública.
- **430:** `https://panel.tunneldoom.space/config.json`, **GET público 200
  validado**, sin token, firma, ID de usuario o cuenta. Esta es la única
  fuente registrada en el broker y en el CLI actuales.
- El URL `http://secure.tunneldoom.space:7676/servers` y la receta GCM
  aportados por el usuario son otro protocolo: no se obtuvo una respuesta
  real y no se mezcla esa receta con el catálogo actual.

No confundir el contador del catálogo proveedor **473** con la versión de
metadatos SP-DECODE **56**. La versión 470 indicada por el usuario ya fue
superada en la respuesta observada; no se afirma haber descargado 470.

## Lectores

`ConfigUtil.getJSONConfig` lee la caché `Zs.png` o `R.raw.noobdev`, luego
`Utils.decryptFile` → `StringCrypter.processString('d')`: Base64, XOR con
SHA256 de la constante de compilación, UTF-8, retiro de 32 caracteres de salt
hexadecimal. No usa como fuente el loader histórico de `SkProtect`.

`SocketClayMainActivity.j1` abre 13 campos con `NoobCrypt`: AES256-CBC, IV0,
PKCS7, clave SHA256 de `NoobPass.getKey`. Se preservan nombres, banderas,
países, puertos, flags, desconocidos y vacíos, sin recortar ni filtrar
servidores deshabilitados. Un campo corrupto falla todo el documento.

Las sustituciones de algunos aliases de cuenta de `GoogleFeedbackUtils`
son lógica posterior de conexión: se conservan los valores originales ya
descifrados, sin copiar al código las cuentas del APK. Ninguno de los 387
registros de la respuesta real utiliza esos aliases. Tampoco se consulta
el servicio autenticado de cuentas/tokens ABS.

El XOR y CBC no tienen autenticación propia; validar padding/JSON no agrega
integridad al formato. Entrada/salida 8 MiB, profundidad 64 y 200000 nodos.
No se ejecutan conexiones o instrucciones presentes en los resultados.

## Uso

Python >=3.10 y PyCryptodome. Para catálogo basta copiar `codec.py` y
`server_catalog_decoder.py` juntos; no necesita APK, SO ni root.

```sh
python -m pip install -r requirements.txt
python server_catalog_decoder.py -o /privado/nuevo-catalogo.json
python server_catalog_decoder.py /privado/catalogo.enc -o /privado/copia.json
python server_catalog_decoder.py - < /privado/catalogo.enc
python file_decoder.py /privado/perfil.sks > /privado/perfil.json
```

Sin entrada, descarga exclusivamente la fuente fija build 430, sin URLs de
usuario ni redirecciones. `-o` crea un archivo 0600 sin sobrescribir.
`run(data: bytes) -> str` permanece offline, registrado como `tunneldoom-vpn`.

## Cloud y compatibilidad

Fuente HTTPS fija con DNS/IP públicos fijados al socket TLS, sin redirecciones,
tamaño/tiempo acotados; validación de identidad del worker y JSON íntegro en
el gateway. Ficha con PNG original y control individual persistente del panel.
Activar/desactivar conserva los switches anteriores y actualiza la metadata.
La disponibilidad final depende del interruptor global y del administrador.

Catálogo mínimo **56 / 49 fichas**; C0 **240**, C8 **254**, sin extensiones nuevas.
El nombre público de `.sks` refleja el contrato legado hasta 4.3.0. Su
`offlineSupported` histórico pertenece a SocksIP; no certifica archivos
TunnelDOOM en el APK offline. No se inventan `.doom`, JSON genérico ni prefijos.

No hay contraseña personal/HWID criptográficos en los lectores. Los flags de
protección/login/fecha se conservan en XML. El fallback de SocksIP `d/v` y
el parser Fenix GCM/DES siguen intactos. Falta exportación SKS real y pruebas
Android/Termux físicos. Sin fusión, despliegue ni publicación APK/novedades.

Ver `ANALYSIS.md`, `TESTING.md`, `manifest.json` y
`scripts/apk_analysis/tunneldoom_verify.py`. Binarios/catálogos/credenciales
reales permanecen fuera de Git.
