# 24clan VPN Lite — catálogo

App: 24clan VPN Lite, paquete `net.tcodes.vpn`, versionCode 71, versionName 7.5.

## Método

- Descarga: `GET https://24clanvpn.com/updater/bf6d1060f2f2480eba5845c748c5b6`, sin cabeceras propias, sin parámetros, sin token ni autenticación.
- Descifrado: Base64 estándar → contenedor OpenSSL `Salted__` + salt de 8 bytes → EVP_BytesToKey/MD5 (1 iteración) con contraseña `mtscrypt` → AES-256-CBC-PKCS#7 → JSON UTF-8. Mismo cifrado que 24clan VPN Green 3.3; solo cambia el path del endpoint.

## Uso

```sh
pip install pycryptodome
python 24clan_VPN_Lite.py --url --summary
python 24clan_VPN_Lite.py --url -o catalogo.json
python 24clan_VPN_Lite.py respuesta_guardada.txt -o catalogo.json
```

Python 3.10+. `--output` guarda con modo 0600.

## Probado en vivo (2026-11-13)

El endpoint remoto responde HTTP 200 pero con solo 2 bytes (`AA`): el archivo está vaciado en el servidor desde marzo de 2026. No es un bloqueo de autenticación. El decodificador abre el catálogo integrado del APK (`assets/defconf`): v1.2, 14 servidores, 1505 tweaks. El endpoint del Green sigue activo (v1.5), así que el servidor está vivo.

## Pendiente

El catálogo remoto Lite no es recuperable hoy; el script funcionará sin cambios cuando el vendor republique el archivo en el mismo path.
