# Hex Custom 10.6.7 — reproducir

Desde la raíz del repo. Sin red; los archivos reales de prueba NO están
en el repo (se verifican por ruta privada, ver RESULTS.md).

```bash
# 1. Self-test del decodificador nuevo (11/11)
python3 decoders/Python/apps/Hex_Custom/Hex_Custom_10.6.7.py --self-test

# 2. Verificación sintética reproducible (round-trip ambas ramas + negativos)
python3 analysis/com.hex.custom.jotchuast/107/tools/verify_107.py -v

# 3. Equivalencia 10.6.4: el decodificador nuevo abre la muestra 10.6.4
#    con JSON idéntico al decodificador viejo (ruta privada del archivo)
python3 - <<'EOF'
import importlib.util
from pathlib import Path
def load(p, name):
    spec = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
old = load('decoders/Python/apps/Hex_Custom/Hex_Custom_archivos.py', 'hc_old')
new = load('decoders/Python/apps/Hex_Custom/Hex_Custom_10.6.7.py', 'hc_new')
raw = Path('<ruta-privada>/NONE_BREAKER__0_0osx.hexcm').read_bytes()
# La contraseña del archivo de prueba se pasa por variable de entorno
# o argumento transitorio; nunca se escribe en el repo.
import os
pw = os.environ['HC_TEST_PASSWORD']
assert old.decode(raw, password=pw) == new.decode(raw, password=pw)
print('NONE_BREAKER: JSON identico entre 10.6.4 y 10.6.7')
EOF

# 4. Rama sin contraseña por el bridge del worker (archivo FastDNS real)
printf '' | python3 cloud/workers/python/hex_custom_bridge.py \
  <ruta-privada>/FastDNS_nube_HexCustom-BoKo2Q5gQR_1_r6pe.hexcm

# 5. Ruta completa del worker (engine.decode_file)
python3 -c "
import sys; sys.path.insert(0, '.')
from pathlib import Path
from cloud.workers.python.engine import decode_file
out = decode_file('hexcm', Path('<ruta-privada>/FastDNS_nube_HexCustom-BoKo2Q5gQR_1_r6pe.hexcm').read_bytes())
print(out['structuredJson']['server']['name'], 'partial:', out['isPartial'])
"

# 6. Suites Python del método
python3 -m unittest tests.test_hex_custom_recovery tests.test_hx_tunnel -v
```

Entorno: Python 3.10+ con `argon2-cffi==25.1.0` y
`pycryptodome==3.23.0` según `requirements.txt` (el decodificador
también funciona en stdlib puro, pero Argon2id tarda minutos).
Ningún comando escribe contraseñas, valores HWID ni claves en el repo.
