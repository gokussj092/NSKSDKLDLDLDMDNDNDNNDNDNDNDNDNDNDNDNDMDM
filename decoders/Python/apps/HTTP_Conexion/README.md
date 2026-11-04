# HTTP Conexión — catálogo Cloud

Paquete `com.doriaxvpn.unlimited`, muestra1.2.9/build129. El catálogo vigente
observado es **107 /244 servidores /5325 campos GCM**, íntegro e igual a JCA,
CLI y worker aislado. Las dos constantes del formato están incorporadas en
`codec.py`; no requiere `.env`, archivos de claves ni credenciales HTTP nuevas.

```sh
python decoders/Python/apps/HTTP_Conexion/server_catalog_decoder.py catalogo.enc > catalogo.json
python decoders/Python/apps/HTTP_Conexion/server_catalog_decoder.py --stdin < catalogo.enc
python decoders/Python/apps/HTTP_Conexion/server_catalog_decoder.py > catalogo-remoto.json
```

`run(bytes)` es offline. Sin argumentos, CLI descarga el updater fijo **/new**,
comprobado mediante Firebase Remote Config real(template17). Conserva GET,
User-Agent original `HTTP-Conexion-VPN/3.0`, headers de caché y `nocache` dinámico.
El /Update antiguo todavía responde57/251, pero no es la fuente seleccionada
por esa configuración: no se usa como fallback de producción ni se sustituye
un fallo remoto por el asset1/7.

Sobre: glifos→Base64→AES256-CBC, clave SHA256(hexUTF8(password) en mayúsculas),
IV cero/PKCS7. Campos: Base64(nonce12+ciphertext+tag16), AES-GCM autenticado,
Base64 interior y rotación -1 en alfabeto34. Se admiten los saltos de línea
de Android Base64.DEFAULT. Un tag inválido falla; no devuelve ciphertext como
si estuviera descifrado. Se conservan metadatos, valores vacíos, tipos y claves
desconocidas. No se infiere soporte de archivos, texto o exportación.

Icono launcher PNG original618×613/449874bytes sin recodificar. Proveedor
`http-conexion`, controles y validación de documento completo conectados;
piso de catálogo67/63 fichas,256 formatos. Android no cambia.

El origen queda fijado al observado; si Firebase cambia URL/contraseña, requiere
revisión del método. No se permite que datos remotos elijan una URL arbitraria.
Node real aquí: REMOTE_NETWORK_DENIED; replay con bytes reales/HTTP simulado
aprobado. Falta comprobar Node en VPS y rollout del operador.

[Expediente y scripts](../../../../analysis/com.doriaxvpn.unlimited/129/MANIFEST.json),
[reproducción](../../../../analysis/com.doriaxvpn.unlimited/129/REPRODUCE.md),
[pruebas](TESTING.md).
