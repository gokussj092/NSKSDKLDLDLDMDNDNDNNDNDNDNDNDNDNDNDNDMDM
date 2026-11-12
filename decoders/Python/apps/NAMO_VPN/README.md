# NAMO VPN — catálogo Cloud

Muestra **3.5-namo / code35**, paquete `com.appxrayservice.namovpn`.
Descarga real original **22.3 /14 servidores /13 redes**, documento entero
contrastado con Java independiente, CLI y worker aislado.

La constante de descifrado de `MainDetail.b()` está **incorporada en codec.py**,
según lo solicitado por el propietario. Es una constante del formato, no una
credencial HTTP ni una cuenta VPN. Esta app no necesita `.env`, secretos de
Compose ni archivos de claves externos. `SOURCE` y el User-Agent original
`okhttp/5.3.2` están en el adaptador de descarga. Solo el backend los consume.

```sh
python decoders/Python/apps/NAMO_VPN/server_catalog_decoder.py catalogo.enc > catalogo.json
python decoders/Python/apps/NAMO_VPN/server_catalog_decoder.py --stdin < catalogo.enc
python decoders/Python/apps/NAMO_VPN/server_catalog_decoder.py > catalogo-remoto.json
```

`run(bytes)` es offline. Sin argumentos, CLI hace GET al updater fijo de la
APK; TLS normal, sin redirects, URL arbitraria ni autenticación adicional.
El sobre es Base64/XXTEA modificado(delta772515655), palabras little endian,
clave16bytes rellenada con ceros y longitud final. Después se decodifican una
vez los campos Base64/UTF-8 documentados por la APK: hosts, credenciales,
payloads, DNS y configuraciones. Se conserva el objeto entero sin renombrar
claves, convertir strings en objetos ni transformar campos desconocidos.
La revisión anterior solo abría el sobre; esa afirmación de descifrado completo
era incorrecta. Se corrigieron 87 valores internos del catálogo real 22.3.
Se reutilizan validadores JSON canónicos de BD_NET_VPN; no se modifica ese codec.
Runtime únicamente stdlib.

Proveedor `namo-vpn`, icono launcher PNG original192×192/25421bytes, ficha y
switch individual conectados. Piso de catálogo71/65 fichas;256 formatos.
No se añaden archivos/textos/exportadores. Android no se modifica ni compila.
Transporte Node real pendiente en VPS: el ejecutor devolvió
`REMOTE_NETWORK_DENIED`; el replay tiene HTTP simulado y bytes reales.

[Expediente y scripts](../../../../analysis/com.appxrayservice.namovpn/35/MANIFEST.json),
[reproducción](../../../../analysis/com.appxrayservice.namovpn/35/REPRODUCE.md),
[pruebas y límites](TESTING.md).
