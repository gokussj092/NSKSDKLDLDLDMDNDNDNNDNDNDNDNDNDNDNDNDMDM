# TurboMX VPN 143.1.26

Paquete `turbo.mx.anuncios`, build 168. Proveedor Cloud `turbomx-vpn` con dos
catálogos oficiales, control administrativo e icono PNG original. Python 3.10+
y PyCryptodome 3.23.0; no necesita APK, Android ni bibliotecas nativas al ejecutar.

```bash
python server_catalog_decoder.py --all > catalogos.json
python server_catalog_decoder.py --download > servidores.json
python server_catalog_decoder.py --users > usuarios.json
python server_catalog_decoder.py copia.sv5c > catalogo.json
python server_catalog_decoder.py --stdin < copia.sv5c > catalogo.json
```

Sin argumentos descarga ambos catálogos. `run(data: bytes) -> str` trabaja
offline; el sobre dual devuelve `{provider, complete:true, catalogs:{servers,
users}}`. Stdout contiene el JSON completo; errores sanitizados van a stderr,
código 1. Dos fuentes fijas recuperadas de `t1x.dJLu5d6z$zlWUw`:

- Servidores: `https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/turbomx/servr_turbomx_sv5c`
- Usuarios: `https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/turbomx/user_turbomx_sv5c`

La descarga exige HTTPS, respuesta no vacía, máximo 8 MiB y ninguna redirección.
El broker mantiene DNS/IP públicos fijados a TLS y no recibe URLs del cliente.

SV5C v2, **release 143**, firma Ed25519 y registros XChaCha20-Poly1305 con claves
HMAC-SHA256 y AAD ligados a release, propósito, índice, tamaño y metadatos.
Se reutiliza la primitiva de SuperFlash con **firma, clave y contexto propios**
confirmados en el SO de este APK. SuperFlash conserva release 157 y sus valores
predeterminados; ambos lectores rechazan catálogos de la otra aplicación.
`Configs`, `Servers`, `AESED` y los recursos confirman los mismos 27 campos
opacos de servidores y seis de usuarios: Base64 URL-safe, IV incluido,
AES-256-CBC/PKCS7, propiedad `SSH_UDP` rellenada con ceros y rotación Java 21
(inversa de ROT5 en ASCII). Nombre, bandera e información también se abren.

Se verifica la firma y **cada registro**, conservando todos los metadatos,
campos, valores vacíos, tipos, entradas duplicadas y opciones `xhttp_*` en claro.
Los metadatos visibles solos no producen éxito. Límites nativos: 4096 registros,
512 KiB de metadatos y 512 KiB por registro; no se filtra por país o protocolo.

Descarga real autorizada del **2026-10-22**: **268 servidores, versión 18**, y
**una entrada de usuarios, versión 3**. Assets: **240 servidores / una entrada**,
ambos versión 3. Los cuatro documentos completos coinciden con KDF/AAD nativos
originales de TurboMX, libsodium y JDK; CLI HTTPS `--all` y worker aislado también.
Los recuentos son observaciones, no límites ni garantía de conectividad VPN.

Al copiar fuera del repositorio, conservar `../SuperFlash_VPN/codec.py`,
`../HTTP_FenixVPN/codec.py` y `../HTTP_FenixVPN/field_names.json`. Las herramientas
ELF/JNI y ARM64 permanecen en `scripts/apk_analysis/`; referencias compartidas y
vectores TurboMX sintéticos en `tests/golden/`. PNG raster original de
`res/mipmap-xxxhdpi/ic_launcher.png`, sin convertir ni reconstruir el adaptativo.

Integración de catálogo de esta versión; no se registra un formato de perfil
exportado sin muestra validada. APK, SO y cuentas reales permanecen fuera de Git.
Ver [TESTING.md](TESTING.md) y [manifest.json](manifest.json).
