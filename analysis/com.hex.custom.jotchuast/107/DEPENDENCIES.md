# Hex Custom 10.6.7 — dependencias

## Herramientas propias

- `decoders/Python/apps/Hex_Custom/Hex_Custom_10.6.7.py`: Python 3.10+,
  solo biblioteca estándar en el nivel superior (Argon2id, AES-256-GCM
  y XChaCha20-Poly1305 implementados en Python puro en el archivo).
  Con `argon2-cffi` + `PyCryptodome` instalados el descifrado tarda
  ~0,3 s; en stdlib puro el Argon2id con m=65536 KiB tarda minutos.
- `tools/verify_107.py`: Python 3.10+, solo stdlib + el decodificador;
  sin red, sin archivos reales.

## Herramientas del repo (reutilizadas, no modificadas salvo lo indicado)

- `decoders/Python/apps/Hex_Custom/Hex_Custom_archivos.py` (10.6.4):
  intacto; referencia de equivalencia de la rama con contraseña.
- `cloud/workers/python/hex_custom_bridge.py`: modificado para cargar
  el módulo nuevo por ruta (importlib); el contrato (contraseña por
  stdin, códigos de error) no cambia.
- `tests/test_hex_custom_recovery.py`: recuperación/oráculo del método.

## Dependencias del servidor (sin cambios)

- `requirements.txt` (raíz): `argon2-cffi==25.1.0`,
  `pycryptodome==3.23.0` (ya fijados; el worker ya los tenía).
- `cloud/web/package-lock.json`: dependencias Node del broker (sin cambios).
