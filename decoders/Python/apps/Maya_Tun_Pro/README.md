# MAYA TUN PRO — 43.0 (43)

Paquete `maya.tun.udp`, dev NOOB DEVEVELOPER, Play 23 jul 2026; proveedor
fijo `maya-tun-pro`, integrado en la nube siguiendo el patrón GCP/NetFlux
(broker HTTPS fijo, worker aislado, contrato de documento completo,
control administrativo individual). Python >=3.10 y
`cryptography>=42.0`. Reutiliza la clave y la ruta de archivos
existentes (`../../_noobcrypt.py`, `../../maya.py`); no necesita APK,
SO, Android ni cuenta en runtime.

## Métodos confirmados

| Entrada | Descifrado | Salida |
| --- | --- | --- |
| Catálogo, sobre exterior (modo 5) | Base64 → AES-256-XTS, tweak = primeros 16 B, clave de 64 B derivada del `.rodata` de `libovpn3.so` | JSON con `Version`, `Servers`, `Tweaks` |
| Campos de servidor y escalares (modo 0) | AES-256-GCM, Base64(nonce12 + ct + tag16), clave `maya` del repo | Nombres, hosts, banderas, puertos |
| Campos de Tweaks/payloads (modos 1/4) | AES-256-CBC, Base64(IV16 + ct), PKCS#7 o `\n` final, clave `maya` | Payloads, SNI, CustomProxy |
| Archivos `.maya` | Ruta C0 existente: `decoders/Python/maya.py` → `_noobcrypt.decrypt_profile` (Base64 → AES-CBC IV-prefijo → JSON; campos internos AES-GCM) | Perfil exportado |
| Enlaces `maya://` (modo 3) | ChaCha20-Poly1305, Base64(nonce12 + ct + tag16), misma clave `maya` → bytes `.maya` → ruta de archivo existente | Perfil exportado |

No se escribió un codec propio por campo ni se duplicó la lógica de
`maya.py`/`_noobcrypt.py`: la clave `maya` se importa de
`_noobcrypt.py` (byte-idéntica a la derivada por el código nativo
43.0) y los archivos `.maya` siguen su ruta C0 congelada
(`C0_FORMAT_MATRIX.csv` fila 80 → `decoders/Python/maya.py`). Este
módulo **no trae `file_decoder.py` a propósito**: un wrapper sería
código muerto — nada puede apuntar a él sin tocar la matriz congelada —
y el precedente `RMP_TUNNEL_PRO` envía módulos solo-catálogo igual.
El handler `maya://` vive en `codec.decode_text` y se cablea
explícitamente en `text_bridge.py`, como `netfluxvpn://` lo hace con
`file_decoder.decode_text`.

**Estos formatos no autentican criptográficamente el ciphertext del
sobre.** Padding, longitud y estructura validan el formato, no su
autenticidad. Si falla el sobre exterior o faltan `Servers`/`Tweaks`,
el lector rechaza el catálogo completo. HMAC de autenticación de
conexión: `NOT_OBSERVED` (ver dossier).

## Fuentes comprobadas

Única URL del updater de este build (valor de `DefUpdateURL` descifrado
del catálogo integrado):

`https://jezvpn.xyz/api/app?json=38FD5AC7020E09D8203F`

Lectura pública autorizada del 2026-11-22: **HTTP 200, 454,716 bytes,
SHA-256 `131869d6…4806`, Version 1.3.41, 27 servidores y 376 tweaks**;
2,449 campos Base64 internos, 0 sin descifrar. El catálogo no trae
marca libre/premium (`NoobLevel` no separa libre/premium: hay
servidores llamados PREMIUM en los tres niveles); el acceso se regula
en la app por tiempo/recompensas. CLI HTTPS real, CLI stdin y worker
aislado entregan el mismo documento completo con fixtures sintéticos;
el catálogo en vivo se descifra en ~1.2 s por el mismo codec (límite
del worker de catálogos: 120 s). No se guardan en Git catálogos reales,
valores descifrados ni credenciales.

Se preservan orden, metadatos, listas, valores vacíos, nulos y tipos
desconocidos. Los JSON internos permanecen como texto exacto. No se
eligen hosts, sustituyen marcadores ni inician conexiones VPN.

## Uso

```bash
python server_catalog_decoder.py --download
python server_catalog_decoder.py copia-catalogo.txt
python server_catalog_decoder.py --stdin < copia-catalogo.txt
```

Los lectores de catálogo exponen `run(data: bytes) -> str`; el texto
expone `codec.decode_text("maya://...") -> str | None`. No se aportó
una exportación real independiente; las rutas `.maya` y `maya://` se
comprueban con fixtures sintéticos. No se certifica un roundtrip de
exportador Android.

## Cloud

- Bridge privado, worker aislado, contrato de documento completo y
  control administrativo individual. Una URL HTTPS fija, DNS IPv4
  público validado, TLS y ninguna redirección; el cliente no puede
  elegir destinos.
- PNG del icono launcher del XAPK 43.0, remuestreado Lanczos 300×300 →
  512×512 (**216,321 bytes**; el original 300×300 es 47,275 bytes).
  Ver `manifest.json` → `icon.policy`: no son los bytes exactos del
  APK; pendiente de confirmación del owner.
- Catálogo mínimo **95**; conserva switches y versión persistente.
  La entrega deja código en el árbol, sin push ni despliegue.
- Dossier y pruebas: `analysis/maya.tun.udp/43/` y [pruebas](TESTING.md).
