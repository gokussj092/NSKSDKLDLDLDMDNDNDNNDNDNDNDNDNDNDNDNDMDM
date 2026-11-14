# HX Tunnel VPN — archivos y catálogo

App: HX Tunnel VPN, paquete `com.hxtunnel.vpn`, versionCode 14, versionName Hx-Build14. APK verificado byte a byte contra el analizado en el repo (mismo SHA-256).

## Archivos `.hxt` (lo nuevo de este paquete)

- Formato: JSON → UTF-8 modificado JNI (CESU-8) → XOR repetido con clave de 12 bytes → hexadecimal (2 dígitos por byte). Sin salt, IV, MAC ni contraseña criptográfica.
- Importación a la inversa. Las protecciones (`tweak_password`, `tweak_expiry`, `hwid_lock`, `block_rooted`) se verifican DESPUÉS de descifrar, no derivan la clave.

## Uso

```sh
python HX_Tunnel_VPN_archivos.py configuracion.hxt -o perfil.json
python HX_Tunnel_VPN_archivos.py --text 'HEXADECIMAL_DEL_ARCHIVO' -o perfil.json
python HX_Tunnel_VPN.py --url -o catalogo.json
```

Solo biblioteca estándar (Python 3.10+).

## Probado (2026-11-13)

- Archivos: round-trip verificado con 8 perfiles cifrados con la propia ruta de exportación de la app (incl. Unicode, NUL, CRLF, perfiles largos) — todos descifran con igualdad exacta. No existe ningún `.hxt` real para probar contra una exportación del teléfono.
- Catálogo (método ya conocido, re-verificado en vivo): `GET https://ctxrelay.online/updater/e7aa9907021632c39b0e0573e11861` → Base64 → XXTEA modificado (delta `0x9E5729B1`, clave `Princie!`) → JSON. En vivo: v26.01, 24 libres, 708 payloads. La descarga se trunca a veces en esta red; reintentar. Integrado del APK: v23.100, 25 libres, 635 payloads.

## Pendiente

Falta un `.hxt` real del teléfono para validar el lector contra una exportación auténtica. La librería `libputils.so` no viene en el base.apk (vive en el split de ABI del .apks); su verificación byte a byte queda pendiente de ese split.
