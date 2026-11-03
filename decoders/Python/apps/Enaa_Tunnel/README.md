# Enaa Tunnel Enna-1.07 (7)

Paquete `com.enaa.tunnel`, original vigente comprobado el 2026-11-01.
Catálogo **4.26, 45 servidores /515 redes**, descarga real HTTP200.
Fuente fija `https://strongteam.co/api/wolftunnellite/enaav1.txt`, GET con
**User-Agent: Enaa Tunnel**. No API key, cuenta ni secreto de backend adicionales.
La llamada nativa `AndroidLibXrayLite.CU` confirma URL, método y cabecera.
No confundir esa fuente con Wolf Custom aunque compartan proveedor.

```sh
python -m pip install -r decoders/Python/apps/Enaa_Tunnel/requirements.txt
python decoders/Python/apps/Enaa_Tunnel/server_catalog_decoder.py --download
python decoders/Python/apps/Enaa_Tunnel/server_catalog_decoder.py catalogo.enc
python decoders/Python/apps/Enaa_Tunnel/server_catalog_decoder.py --stdin < catalogo.enc
python decoders/Python/apps/Enaa_Tunnel/file_decoder.py perfil.enaa
```

Scripts independientes sin APK/Android/SO al ejecutarse; conservar la carpeta
hermana HTTP_FenixVPN por sus validadores/render. `run(bytes)` es offline.
La CLI descarga solo el origen fijo, valida TLS, tamaño, HTTP200, identidad de
codificación y rechaza HTML/redirecciones. No sustituye fallos por el asset.
El broker conserva DNS público fijado, TLS, cuotas, sesión y switch individual.

## Método y campos

`libgojni.so`, paquete `github.com/2dust/AndroidLibXrayLite`: Argon2id v19,
**t=3, m=8192 KiB, p=1, salida32**, contraseña de formato WolfTunnelLitePASS.
Base64 de **salt16 + nonce12 + AES256-GCM(ciphertext/tag16)**, con salt como AAD.
El algoritmo de MM Tunnel usa otros parámetros y contraseñas; no se reutiliza.
`EO/DO` abre el catálogo incluido y campos. `Encrypt/decrypt` añade/retira
una letra ASCII en el índice3 del Base64 para el catálogo remoto/exportaciones.
Elegir el sobre por su estructura; no reintentar otra clave tras fallar el tag.
No aplicar la letra extra a los campos internos.

Raíz: DefOVPNUser, DefOVPNPass, HysteriaUser, HysteriaOBFS, DefaultOVPNCert.
Servidores: ServerIPHost, OVPNUser, OVPNPass, UDP_obfs, UDP_user,
CustomCertificate, SlowDNSHost, SlowDNSKey, V2rayUUID, V2rayPath, H2pass,
TrojanPass. Redes: Payload, CustomProxy, SNI, V2rayConfig, BugDNS,
V2rayAddress, V2rayHost, V2raySNI. Consumidores Hometab.Companion.a y
HomeFragment confirman los contextos. URI e Info son texto y se conservan;
no se descifran propiedades desconocidas por parecer Base64.

Hometab admite texto directo en campos conocidos. El lector conserva ese texto,
nulos, tipos y desconocidos; si un sobre protegido tiene tag incorrecto, rechaza
el documento completo. Devuelve todas las filas/listas/credenciales almacenadas;
no selecciona servidores, reemplaza placeholders ni inicia VPN.

## Archivos y alcance

`NetworkAdapter.u` exporta el NetworkList por `Libv2ray.encrypt` con extensión
**.enaa**, MIME application/x-enaa; ConfigFileParser importa ese sobre, EO/DO
alternativo o JSON directo. No usa contraseña del usuario ni identidad del
terminal para derivar la clave. Los protocolos estándar de la base V2Ray no
constituyen un nuevo prefijo propietario de texto o un feed Cloud individual.

`.enaa` queda como ruta **C8 Cloud** adicional, 255 formatos efectivos; C0 sigue
congelado en240 y no se altera el inventario Android. No se recibió un perfil
.enaa exportado independientemente: paridad sintética con el método original,
sin certificación de writer/exportador ni prueba física Android.

Icono WebP original192×192 conservado y PNG con **píxeles RGBA idénticos**,
sin redimensionar ni redibujar. Ficha `enaa-tunnel`, control y worker integrados.
Fuente59 /56 fichas; sin despliegue ni fusión. Ver [TESTING](TESTING.md),
[manifest](manifest.json) y [continuidad](../../../../docs/cloud/ENAA_ZIG_TUNNEL_HANDOFF_2026_11_01.md).
