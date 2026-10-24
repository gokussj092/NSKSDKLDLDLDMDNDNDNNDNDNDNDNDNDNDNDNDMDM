# MegaTunnel 1.17.1

Paquete `xyz.tekidoer.mega.tunnel`, build **17**. Integración de catálogo en el
PR #96, rama `feat/austroplus-vpn-13-0-1-decoders`.

Descarga HTTPS real autorizada: **10 servidores y 124 ajustes (Tweaks)**,
versión **0.2**. Se procesan **297 campos, 210 no vacíos**, conservando también
registros con campos ausentes. Todo el documento descifrado coincide con JDK
independiente, CLI real y worker aislado. Los recuentos no limitan el catálogo.

## Uso

Python >=3.10 y `pip install -r requirements.txt`. Conservar `codec.py` y los
archivos `codec.py`/`field_names.json` de la carpeta hermana `HTTP_FenixVPN`,
que aportan Base64, validación y renderizado compartidos.

```bash
python server_catalog_decoder.py > catalogo.json
python server_catalog_decoder.py --download > catalogo.json
python server_catalog_decoder.py copia_cifrada.txt > copia.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt > copia.json
```

`run(data: bytes) -> str` y archivo/stdin funcionan offline. El modo predeterminado
y `--download` consultan la fuente fija original `G2.updater`:
`https://raw.githubusercontent.com/SpkHexX/HexX/refs/heads/main/MegaTunnel.js`.
Se verifica HTTPS; no se aceptan URLs del cliente ni redirecciones.

## Formato recuperado

- `G2.confpass`, `XW.m`, `AbstractC2562yx.a`: Base64 de nonce12+ciphertext+tag16,
  AES-256-GCM sin AAD. La clave es la constante de build UTF-8 truncada/rellenada
  con ceros a 32 bytes. Primero se verifica el tag y después se interpreta JSON.
- `MainActivity.W4` y `PW.a/b`: los campos especificados usan Base64 y XOR
  repetido con los seis bytes de `PW.DEFAULT_KEY`. Se abren ocho campos de
  servidor y cinco de ajustes, enumerados en `manifest.json`. No se aplica la
  doble Base64 del importador de archivos, que es una ruta diferente.
- Se mantienen puertos, banderas, booleanos, números, textos, `version`, `reset`,
  avisos, metadatos publicitarios y cualquier campo desconocido en su tipo y
  estructura originales. No se filtra por país/modo, rellena con defaults,
  sustituye placeholders o deduplica. `ovpn_cert` permanece como texto original.
  Un tag, campo o registro inválido falla sin devolver éxito parcial.

Los `long[]` ofuscados por `C1682lA` se resolvieron siguiendo `java.util.Random`
y la reconstrucción little-endian del APK. No se ejecuta código de anuncios,
telemetría o VPN durante el descifrado.

Proveedor `megatunnel`, control administrativo, worker e icono PNG original
incluidos. Catálogo público mínimo **23**, con **25 fichas**. Se conservan los
192×192 píxeles y bytes exactos de `res/mipmap-xxxhdpi-v4/ic_launcher.png`.
No se identificó una fuente remota separada de usuarios; las credenciales
incluidas en los servidores se conservan dentro de sus registros.

Entrada/salida del lector: 8 MiB; worker/HTTP conservan sus límites generales.
Ver `TESTING.md`: comprobaciones puntuales, sin suites completas ni despliegue
VPS. Esta entrega integra el catálogo, no registra `.meg` ni certifica perfiles
exportados. APK, capturas reales y resultados privados quedan fuera de Git.
