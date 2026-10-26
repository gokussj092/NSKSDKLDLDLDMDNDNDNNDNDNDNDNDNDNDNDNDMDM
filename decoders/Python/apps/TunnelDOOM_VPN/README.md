# TunnelDOOM VPN 4.2.4 (424)

Paquete `com.tunneldoom.http`. Integración en la rama del **PR #102**,
`feat/ha-tunnel-plus-1-7-1-decoders`. Backend Python/Cloud; sin cambios de UI.

| Entrada | Estado |
| --- | --- |
| Catálogo incluido `res/raw/noobdev.txt` | JSON completo verificado: Version `3`, 1 servidor, 13 campos cifrados no vacíos |
| Actualizador HTTPS fijo | Identificado en DEX; respuesta real no obtenida desde este entorno. Ficha con icono original, descarga pública desactivada |
| `.sks` | Contrato del parser incluido confirmado; GCM y DES reutilizan HTTP FenixVPN. Sin exportación real independiente de este build |
| Texto | No se identificó un formato cifrado propietario de TunnelDOOM. El subsistema V2Ray utiliza enlaces estándar ya existentes |
| Importación Cloud por ID | No identificada; el GET de actualización es un catálogo, no un enlace individual |

## Catálogo

`ConfigUtil.getJSONConfig` lee la caché `Zs.png` o `R.raw.noobdev`, y llama
`Utils.decryptFile` → `StringCrypter.processString('d')`:
Base64, XOR con SHA256 de la constante de compilación, UTF-8, retiro de 32
caracteres de salt hexadecimal. No usa las rutas heredadas de SkProtect como
fuente activa. No confundir los JSON de assets con el recurso consumido.

`SocketClayMainActivity.j1` descifra 13 campos mediante `NoobCrypt`: clave
SHA256 de `NoobPass.getKey`, AES-256-CBC, IV cero, PKCS7. `codec.py` conserva
nombre, bandera, país, puertos, flags, metadatos y campos desconocidos sin
renombrarlos; vacíos opcionales permanecen vacíos. Un campo conocido corrupto
falla el documento entero. No se devuelve una salida parcial como completa.

La app aplica después `GoogleFeedbackUtils.mapUser/mapPass`, sustituciones de
algunos aliases por cuentas codificadas en el APK. Esto es lógica de conexión,
no otra capa de cifrado: el lector conserva los valores originales ya
descifrados. **No copia ese listado de credenciales al repositorio ni consulta
el servicio de tokens/cuentas ABS.** La muestra incluida no utiliza esos aliases.

El sobre XOR y CBC no tiene autenticación: validar JSON/padding no agrega una
garantía criptográfica ausente en el formato. Límites: entrada/salida 8 MiB,
profundidad 64 y 200000 nodos. No interpreta conexiones ni ejecuta contenido.

## Uso

Python >=3.10, PyCryptodome. Para catálogo basta copiar `codec.py` y
`server_catalog_decoder.py` juntos; no necesita APK, SO ni root.

```sh
python -m pip install -r requirements.txt
python server_catalog_decoder.py /privado/noobdev.txt -o /privado/catalogo.json
python server_catalog_decoder.py - < /privado/catalogo.enc
python server_catalog_decoder.py -o /privado/catalogo-remoto.json
python file_decoder.py /privado/perfil.sks > /privado/perfil.json
```

Sin entrada, el CLI hace exclusivamente GET a
`https://control.tunneldoom.space/config.json`, URL literal del actualizador,
sin URLs de usuario ni redirecciones. El archivo `-o` se crea con modo 0600 y
no se sobrescribe. El CLI no certifica disponibilidad del endpoint.
`run(data: bytes) -> str` permanece completamente offline y está registrado
en el worker de catálogos con ID `tunneldoom-vpn`.

## Archivos y cliente

`ConfigParser.FILE_EXTENSAO=sks`, `encodeInput/decodeInput`, `SecurityConfig`
y `CipherServiceImpl` confirman PBKDF2-HMAC-SHA256/1000/salt32/AES128-GCM,
nonce12/tag16, sin AAD, y el fallback histórico DES-ECB/PKCS5. Los parámetros
son iguales al lector canónico Fenix: `file_decoder.py` lo reutiliza y requiere
la carpeta hermana `HTTP_FenixVPN`. El router `.sks` sigue distinguiendo el
JSON `d/v` histórico SocksIP antes de entrar a GCM/DES. No se duplica motor.

No hay contraseña personal/HWID como entrada criptográfica de estos lectores;
flags de protección/login/fecha están dentro del XML y se conservan. No se
ha demostrado una ruta UI de exportación/importación SKS activa en build424:
las invocaciones externas a ConfigParser encontradas solo comprueban fecha.
La coincidencia del parser no certifica una exportación que no se proporcionó.

Se actualiza únicamente el nombre público de `.sks`; `offlineSupported`
continúa describiendo la ruta SocksIP histórica y **no** certifica que el APK
actual decodifique offline archivos propios de TunnelDOOM.
C0 **240**, C8 **254**, catálogo mínimo **55**, **49 fichas**.
No se añaden `.doom`, `.tdoom`, JSON genérico ni prefijos inventados.

## Remoto pendiente

Tres GET desde este entorno recibieron HTTP503 del proxy/envoy con
`upstream connect error ... remote connection failure`; la consulta web
tampoco obtuvo el recurso. **No se afirma que el origen esté caído** ni que
se haya abierto un catálogo remoto. El CLI fijo se comprobó con mocks.

La ficha pública conserva el PNG exacto de launcher y `remote:null`.
`server-vpn-provider.mjs` y los controles administrativos no permiten invocar
este ID remoto aun cuando el interruptor global esté activo. Para habilitarlo:
obtener una respuesta real, comparar todo el JSON con JCA y worker, registrar
el broker fijo DNS/TLS, añadir su control individual y elevar la versión.

Ver `ANALYSIS.md`, `TESTING.md`, `manifest.json` y
`scripts/apk_analysis/tunneldoom_verify.py`. Sin fusión, VPS, APK o novedades.
