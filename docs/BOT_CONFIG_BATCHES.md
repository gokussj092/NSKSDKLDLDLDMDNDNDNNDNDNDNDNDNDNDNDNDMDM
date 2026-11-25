# SP-DECODE — lotes de motores de archivos y protocolos

## Objetivo y alcance

Migrar los métodos del archivo original `66.py` autorizado por el usuario
**sin copiar el bot monolítico**, creando un archivo Python por motor/familia,
con importaciones aisladas, registro por extensión y reutilización desde los
enlaces de texto. Esta fase es **solo para el bot de Telegram**. No portar a
Android, no modificar `android/` o `decoders.json`, y no publicar un APK.

Se conservaron las 118 extensiones previamente registradas (61 históricas,
41 nuevas Ultra/Sandok y 16 RENZ/7NET). Esta fase incorpora **27 sufijos
adicionales**, hasta **145** en el bot.

## Lote de archivos — 13 motores / 27 extensiones

| Archivo Python | Extensiones | Técnica desde 66.py |
|---|---|---|
| `sentinel.py` | `.st` | STCF, XOR/inversión, HMAC-SHA256 y AES-GCM |
| `itv.py` | `.itv` | Clave/nonce del contenedor, AES-GCM y entradas XML |
| `eut.py` | `.eut` | AES-CBC y descifrado anidado `cipher:iv` |
| `v2box_export.py` | `.v2box` | `v2box_export`, AES-GCM y dos opciones de claves |
| `slipnet.py` | `.slipnet` | AES-GCM con/sin byte marcador, 33 campos estructurados |
| `juanscript.py` | `.juanscript`, `.juan`, `.mobi` | SHA256 checksum, PBKDF2, AES-GCM, gzip |
| `wyrlite.py` | `.wyrl`, `.wyrlite`, `.wyrvpnlite` | ChaCha20-Poly1305 y AES-GCM, perfiles alternativos |
| `wyrvpn.py` | `.wyr` | AES-GCM y campos protegidos dentro de JSON |
| `intvpn.py` | `.int` | AES-GCM y cadenas `djAx` anidadas |
| `fthp.py` | `.fthp`, `.ftp` | PBKDF2 + AES-GCM, ambas contraseñas históricas |
| `ar_pro.py` | `.ar`, `.msy` | AES-CBC exterior, AES-CFB para campos |
| `ec.py` | `.ec` | XXTEA puro compatible con el algoritmo original |
| `xor_family.py` | `.apnalite`, `.apnatnl`, `.bdnet`, `.hxt`, `.fnf`, `.4ulite`, `.omanova`, `.ursa`, `.hsome` | XOR hexadecimal y transformación recursiva de campos |

Las extensiones se declaran una sola vez en
`decoders/Python/config_batch_registry.py`, y el bot las incorpora desde
`spdecode/registry.py` sin duplicar motores.

## Lote de texto — reutiliza los mismos módulos

`spdecode/handlers/config_batch_texts.py` registra los protocolos antes del
handler genérico de textos. Respeta la autorización central existente. Se
admiten:

- `falcontunnel://import/` (Base64URL y JSON, `falcon_links.py`)
- `npvt-ssh://`, `dns://`, `npvs1:` (`npvt_links.py`)
- `slipnet-enc://`, `slipnet://`
- `wyrlite://`, `wyrvpnlite://`, `wyrl://`, `wyrvpn://`
- `intvpn://`, `juanscript://`, `mobi://`
- `eut-settings://`
- `httptweak://` usando el decodificador de archivos ya existente
- `apnalite://`, `apnatnl://`, `bdnet://`, `hxt://`, `fnf://`,
  `4ulite://`, `omanova://`, `ursa://`, `hsome://`,
  `hamaratnl://` usando un único motor XOR
- `happ://crypt/`, `happ://crypt2/`, `happ://crypt3/`,
  `happ://crypt4/` usando RSA PKCS#1 v1.5 (ver aviso de claves)

Los protocolos `ihome://`, `actunnel://` y `gcpvpn://` ya se
incorporaron con el motor RENZ. No se crea un handler duplicado.

## Advertencias y límites

**HAPP:** el archivo original contenía claves RSA privadas completas.
Para evitar publicarlas en un repositorio se omitieron intencionadamente.
El administrador puede aportar un JSON de claves PEM en la variable de
entorno `SPDECODE_HAPP_KEYS_JSON`, con claves `crypt`, `crypt2`,
`crypt3` y `crypt4`. Nunca registrar la variable en logs, commits,
documentación o archivos descargables. Si no se configura, los enlaces HAPP
no son descifrables. El motor tampoco descarga URLs devueltas por RSA.

**V2Box protegido:** el bot solicita la contraseña con una respuesta al
documento o enlace original, en el mismo chat y tema. Responde al aviso
del bot. La solicitud caduca en 3 minutos, admite 3 intentos y queda
vinculada a la persona que envió el original. Se conserva en memoria
mientras está pendiente.

**ITV:** la implementación extraída de `66.py` usa AES-GCM pero *no
comprueba etiqueta de autenticación* (el diseño del original no define su
separación en el contenedor). Por ello, una salida plausible no certifica
integridad. Hacer prueba con muestras auténticas antes de marcar ITV como
certificado para producción.

**Otros perfiles:** AES-CBC, AES-CFB y XOR no son cifrados autenticados.
No afirmar integridad criptográfica a partir de que el JSON se haya podido
parsear. Algunos modos históricos toleran datos parcialmente corruptos.

El inventario Android **sigue separado**. No se declara equivalencia Kotlin
ni soporte Android para ninguno de los formatos nuevos.

## Verificación

```sh
python -m unittest tests.test_config_batch_modules -v
python -m unittest tests.test_config_batch_crypto_a -v
python -m unittest tests.test_config_batch_crypto_b -v
python -m unittest discover -s tests -v
```

La validación automática usa muestras cifradas sintéticas reproducibles
con datos ficticios. Para certificar compatibilidad con cada aplicación
actualizada se necesitan **exportaciones reales y autorizadas** y comparar
campos descifrados con los de la aplicación exportadora.
