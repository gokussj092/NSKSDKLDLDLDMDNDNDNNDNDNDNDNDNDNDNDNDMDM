# SuperFlash VPN 184.0.1

Paquete `speicers.diablo.vpn`, build 184. Catálogos completos de servidores y
usuarios registrados como `superflash-vpn` en el PR #96, con dos fuentes HTTPS
fijas, control administrativo e icono PNG original. Python 3.10+ y PyCryptodome
3.23.0; el lector no necesita APK, Android, emulador ni SO al ejecutar.

```bash
python server_catalog_decoder.py --all > catalogos.json
python server_catalog_decoder.py --download > servidores.json
python server_catalog_decoder.py --users > usuarios.json
python server_catalog_decoder.py copia.sv5c > catalogo.json
python server_catalog_decoder.py --stdin < copia.sv5c > catalogo.json
```

Sin argumentos descarga ambos catálogos. `run(data: bytes) -> str` es offline.
Una copia devuelve su JSON completo; el sobre dual devuelve
`{provider, complete:true, catalogs:{servers, users}}`. Errores sanitizados van
a stderr y finalizan con código 1. Cada fuente y el transporte dual tienen un
límite de 8 MiB; se rechazan redirecciones, HTML y descargas vacías. El broker
Cloud aplica sus controles existentes de DNS/IP/TLS y solo admite estas fuentes:

- Servidores: `https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/supervpn/servr_superflash_sv5c`
- Usuarios: `https://raw.githubusercontent.com/apksdemons/apks2/refs/heads/main/supervpn/user_superflash_sv5c`

Formato recuperado de `Configs.openEnvelope/openRecord`, `x.h7.q.r/s` y
`libspeigoshield.so`: SV5C versión 2, release 157, cabecera de 20 bytes y firma
Ed25519 de 64 bytes. Se verifica la firma sobre el SHA-256 de dominio, contenido
y sufijo; cada registro lleva índice, tamaño, nonce de 24 bytes y XChaCha20-
Poly1305. Claves HMAC-SHA256 y AAD incluyen propósito, índice, release y hash de
los metadatos. Se autentican **todos** los registros antes de devolver éxito.
Los límites de 4096 registros, 512 KiB de metadatos y 512 KiB por registro vienen
del lector nativo; los recuentos observados no se usan como límites.

Los 27 nombres opacos de campos de servidores y seis de usuarios coinciden con
Fenix; se reutilizan únicamente su inventario y validadores, sin cambiar su
motor. `AESED` usa Base64 URL-safe, IV de 16 bytes, AES-256-CBC/PKCS7 y la
propiedad `SSH_UDP` de `assets/LICENSE` rellenada con ceros. `Servers.decoder`
aplica rotación Java de 21, equivalente al inverso ASCII de ROT5. Nombre,
bandera e información de servidor también se descifran. Los campos `xhttp_*`
observados son texto plano y se conservan. Al copiar fuera del repositorio,
mantener `../HTTP_FenixVPN/codec.py` y `../HTTP_FenixVPN/field_names.json`.

Se conservan todos los registros, nombres opacos, tipos, valores vacíos,
duplicados de lista, metadatos desconocidos y opciones por protocolo. Se unen
los metadatos de presentación con el registro autenticado y se rechazan copias
en conflicto. Leer solo los metadatos visibles nunca cuenta como descifrado.
No se fabrica una sesión Android ni se necesita consultar una API de claves.

Descarga real autorizada del **2026-10-22**: **268 servidores, versión 27**, y
**una entrada de usuarios, versión 5**. Ambos documentos completos y los dos
assets SV5C coinciden con una referencia independiente que usa KDF/AAD nativos
originales, libsodium y JDK. CLI `--all` HTTPS y worker aislado coinciden.
PNG original de 192×192 de `res/mipmap-xxxhdpi/ic_launcher.png`, sin conversión;
es el recurso raster existente de la familia del icono adaptativo.

Las herramientas reutilizables `elf_inspect.py` y `arm64_function.py` están en
`scripts/apk_analysis/`. Oracles y vectores sintéticos están en `tests/golden/`;
APK, SO, descargas y datos de usuarios se mantienen fuera de Git. Integración
de catálogo SV5C de esta versión; no certifica un formato de perfil exportado.
Ver [TESTING.md](TESTING.md) y [manifest.json](manifest.json).

La primitiva interna `decode_sv5c` también se reutiliza por TurboMX con otro
release, firma, clave y contexto fijos. `decode_catalog` de SuperFlash conserva
los valores originales y rechaza catálogos TurboMX. No se mezclan materiales
ni se prueban claves de otros proveedores cuando falla la autenticación.
