# Hex Tunnel / HexVPN 1.7.3-Rev — archivos `.hexcm`

Paquete analizado: `com.hex.tunnel.jotchuast`, build 73. Este lector corresponde
a las seis exportaciones autorizadas proporcionadas por el propietario. El
análisis histórico de `com.hex.custom.jotchuast` 10.6.1 se conserva por separado
en `../Hex_Custom/`; no se declara comprobada esa versión antigua.

## Uso

```bash
python decoders/Python/apps/Hex_Tunnel/file_decoder.py configuracion.hexcm
python decoders/Python/apps/Hex_Tunnel/file_decoder.py configuracion.hexcm --raw
python decoders/Python/apps/Hex_Tunnel/file_decoder.py --stdin < configuracion.hexcm
```

Python 3 y PyCryptodome. Es un lector autónomo: no requiere APK, VM, Android,
conexión a Internet, contraseña externa ni un ID de dispositivo en runtime.
`run(data: bytes) -> str` devuelve aplicación, extensión, método, verificación
de firma y el JSON completo bajo `config`. `--raw` devuelve solo ese documento.
No se eliminan ni alteran campos de servidor, metadatos, bloqueos o firma.
Un archivo no válido termina con código 1 y sin contenido parcial en stdout.

## Formato comprobado

- Base64 exterior de `salt[16] || nonce[12] || ciphertext || tag[16]`.
- PBKDF2-HMAC-SHA256, 100 000 iteraciones, 32 bytes, usando `AppConfig.keydev()`.
- AES-256-GCM autenticado. Las seis muestras reales usan esta variante simple.
- Variante doble recuperada: plaintext AES → Base64 →
  `nonce[12] || ChaCha20-Poly1305 ciphertext || tag[16]` → JSON firmado.
  Verificada con referencia JCA y vectores sintéticos, no atribuida a las
  muestras reales simples.
- Firma: SHA-256 de los bytes JSON sin la propiedad raíz `signature`,
  concatenados con la constante de la aplicación. Se conservan lexemas y
  orden del exportador para evitar diferencias de serialización Android/Python.

Se exige un documento `version: 1`, un objeto `server` no vacío, metadatos
`blocked` booleanos y firma válida. Se rechazan duplicados, números no finitos,
estructuras excesivas, tags corruptos, truncamientos y versiones desconocidas.

El ID de las muestras se encuentra en `meta.blockIdValue` o
`meta.loginByIdValue`. La compañía/país se representan mediante `blockCompany`,
`company` y `countryIso`. En estas muestras son metadatos posteriores al
descifrado: el ID no es una entrada de la KDF. La salida los preserva completos.

## Integración

- Motor Cloud: `_C8_FILE_ENGINES` en `cloud/workers/python/engine.py`.
- Bot: ruta exacta `hexcm` en `spdecode/registry.py`.
- Inventario público generado: `cloud/web/content/file-formats.json`.
- Versión fuente del catálogo: **61**, mediante el contrato monotónico existente.
- Nuevo total de rutas de archivo Cloud: **256**; C0 permanece en **240**.
- `offlineSupported: false`, `cloudSupported: true`, `credentialFields: []`.

Solo se incorpora un formato de archivo. No se inventa un catálogo de servidores,
una URL ni una ficha Server VPN. El listado de proveedores conserva 58 entradas.
El soporte Android es la ruta Cloud obtenida mediante el catálogo remoto; este
cambio no incorpora un motor offline en el APK.

## Evidencia y límites

Los seis archivos reales se abrieron completos y conservaron sus 26 campos de
servidor; se compararon íntegramente con una implementación independiente JCA.
Las cuatro muestras adicionales abarcan ID, compañía, ambos e inicio por ID.
No se incluyen documentos, IDs ni credenciales reales en el repositorio.

Las copias recifradas sin esas restricciones se probaron criptográficamente
en privado. **La importación Android y la conexión real siguen pendientes**;
no se habilita ni certifica Unlocked en el producto con esta incorporación.
No se han desplegado servicios, publicado APK ni modificado novedades.

Pruebas reproducibles: [TESTING.md](TESTING.md). Recuperación del APK exacto:
`scripts/apk_analysis/hex_tunnel_recover.py`, con hashes de XAPK y bibliotecas
fijados; requiere las herramientas de análisis existentes y genera material
privado. El lector de producción no depende de esas herramientas.
