# APNA VPN 3.9 — catálogo de servidores

App: APNA VPN, Android package my.teamapna.tunnel, versión 3.9.

El catálogo embebido se encuentra en base.apk/assets/janu.json del APKS. Es Base64 estándar de XXTEA modificado, delta hexadecimal 9E5729B1, enteros little-endian y tamaño original al final. La clave de formato se recuperó de LBm en classes2.dex.

**Validación real:** Version=289, 19 Free_servers, 491 Payloads, 10 secciones y 210815 bytes de JSON UTF-8 completo. Premium_servers, Vip_servers y Private_servers están vacíos en esta versión. Se conservan todos los campos, listas y valores sin truncar. XXTEA no proporciona autenticación criptográfica, por lo que el lector solo valida estructura.

## Uso

    python decoders/Python/apps/APNA_VPN/server_catalog_decoder.py --apks 'APNA VPN_3.9.apks' --summary
    python decoders/Python/apps/APNA_VPN/server_catalog_decoder.py --apks 'APNA VPN_3.9.apks' --output /ruta/privada/catalogo.json
    python decoders/Python/apps/APNA_VPN/server_catalog_decoder.py --input janu.json --output /ruta/privada/catalogo.json
    python decoders/Python/apps/APNA_VPN/server_catalog_decoder.py --stdin < janu.json > /ruta/privada/catalogo.json

Python 3.10+ únicamente con biblioteca estándar. La función run(data: bytes) -> str entrega JSON completo; el worker privado registra el ID fijo apna-vpn. La opción --summary solo emite recuentos. El JSON completo puede contener usuarios, contraseñas, hosts y payloads: nunca publicarlo en CI, Git ni registros.

## Fuente y límites

Lprince/open/vpn/activities/a;.g lee filesDir/janu.json o assets/janu.json; LHZ.o realiza Base64; LBm.c/b descifra XXTEA y LBm.f/g recupera los bytes. Las cadenas se recuperaron de cinco bloques LSParanoid de Deobfuscator$APNAVPN$app. El script no necesita APK o bibliotecas nativas en producción.

**El catálogo remoto no está validado.** El APK contiene un enlace de actualización, pero no se confirmó que entregue catálogos de servidores. No añadir URL al broker, tarjeta pública habilitada ni publicarlo como operativo hasta validar un origen oficial, su icono y el JSON entero.

El trabajo se conserva en la rama feat/austroplus-vpn-13-0-1-decoders, PR #96, sin merge ni despliegue.
