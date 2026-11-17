# HexVPN 1.7.3-Rev — dependencias

## Herramientas propias

- `tools/HexVPN.py` (sonda de catálogo y self-test del lector):
  Python 3.10+, solo stdlib + `pycryptodome` (AES-GCM / ChaCha20-Poly1305).
  Requiere red solo para `--probe` (GET anónimo al RTDB de Firebase).
- `tests/test_live_json.py`: Python 3.10+, solo stdlib, sin red.

## Herramientas del repo (reutilizadas, no modificadas)

- `decoders/Python/apps/Hex_Tunnel/file_decoder.py`: Python 3 +
  `pycryptodome` (fijado en `requirements.txt` raíz).
- `tests/test_hex_tunnel.py`, `tests/golden/hexcm_vectors.json`:
  vectores dorados con contraste independiente JCA.
- `scripts/apk_analysis/hex_tunnel_recover.py`: pines SHA-256 de
  `libkovsec.so` y `libhexvpn.so` usados para la identidad del build.

## Dependencias del servidor (sin cambios)

- `requirements.txt` (raíz): `pycryptodome==3.23.0`,
  `argon2-cffi==25.1.0` (este último solo lo usa Hex Custom, no HexVPN).
- `cloud/web/package-lock.json`: dependencias Node del broker (sin cambios).
