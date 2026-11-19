# Dependencias — 1FTunnel 0.7.3 (build 129)

Versiones exactas en `dependencies.lock.json`.

| Herramienta | Versión | Uso en este expediente |
|---|---|---|
| Python | 3.12.3 | Todos los scripts (`tools/`, `tests/`). |
| PyCryptodome | 4.4.0 | Solo para sellar la fixture sintética (`make_fixture_v6.py`); la apertura del archivo real la hace el decodificador del repo. |
| androguard | 4.1.4 | Manifest de la APK 0.7.3 (package, versionCode) y comparación DEX (`dex_compare.py`). |
| unicorn | 2.1.4 | **Disponible pero no ejecutado**: el oráculo de la KDF fija el hash de la `.so` 0.6.99 y direcciones fijas; la autenticación GCM del archivo real 0.7.3 con la clave 0.7.1 es prueba más fuerte. |
| UnZip | 6.00 | Extracción de la APK. |
| GNU binutils (strings) | 2.42 | Conjunto de strings de la `.so` nativa (comparación de etiquetas KDF). |
| Repo SP-DECODE | head remoto `3e4a02c0` (`ci/unity-ads-online-qa`) | Decodificadores `1FTunnel.py` / `codec.py` / `file_decoder.py` y cableado del servidor; verificado por clon HTTPS. |

## Dependencias del método (runtime del servidor)

El decodificador `1FTunnel.py` usa solo la biblioteca estándar de Python
(`base64`, `hashlib`, `hmac`, `json`, `struct`, `zlib`) más `Crypto.Cipher.AES`
(PyCryptodome) para AES-256-GCM. No hay dependencias nuevas respecto al
expediente 127.

## Sin red

Toda la verificación se hizo offline sobre archivos locales. No se llamó a
ningún endpoint del servidor en vivo.
