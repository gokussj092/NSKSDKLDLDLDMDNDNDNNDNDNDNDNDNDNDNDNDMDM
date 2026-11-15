# APNA Tunnel Lite — catálogo

App: APNA Tunnel Lite, paquete `com.apnatunnel.lite`, versionCode 51, versionName APNA.

## Método

- Descarga: `GET https://paperonboard.com/updater/<token>` (URL fija, sin parámetros ni autenticación).
- Cabeceras exactas de la app: `User-Agent: Dalvik/2.1.0` y `Accept-Encoding: identity`. Con un User-Agent genérico el servidor responde 403.
- Descifrado: quitar espacios/saltos de línea → Base64 estándar → XXTEA modificado (delta `0x9E5729B1`) → JSON UTF-8 completo. Mismo cifrado que APNA VPN 3.9; solo cambia el token de la URL.

## Uso

```sh
python APNA_Tunnel_Lite.py --summary
python APNA_Tunnel_Lite.py --output catalogo.json
python APNA_Tunnel_Lite.py --apks 'APNA_Tunnel_Lite.apks' --summary
```

Solo biblioteca estándar (Python 3.10+). `--output` guarda con modo 0600 y no sobrescribe.

## Probado en vivo (2026-11-13)

Catálogo remoto v850: 50 servidores libres, 644 payloads. Integrado del APK: v580, 44 libres, 623 payloads. El servidor corta la conexión a mitad del cuerpo con frecuencia; el script reintenta y reanuda por rangos con las mismas cabeceras.

## Pendiente

La petición HTTP exacta vive en un DEX secundario protegido (LIAPP) que no se pudo decompilar; su forma se infiere del linaje con APNA VPN 3.9 y del comportamiento 403/200 del servidor.
