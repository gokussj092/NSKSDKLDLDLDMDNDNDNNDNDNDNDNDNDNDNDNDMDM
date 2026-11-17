# HexVPN 1.7.3-Rev — reproducir

Desde la raíz del repo. Sin red salvo el sondeo RTDB (solo lectura, GET anónimo).

```bash
# 1. Lector .hexcm (simple y doble) + vectores dorados
python3 -m unittest tests.test_hex_tunnel -v

# 2. Ruta completa del worker (engine.decode_file) con un vector dorado
python3 -c "
import sys, json; sys.path.insert(0, '.')
from pathlib import Path
from cloud.workers.python.engine import decode_file
V = json.loads(Path('tests/golden/hexcm_vectors.json').read_text())['documents']
valid = [c for c in V if not c.get('reject')][0]
out = decode_file('hexcm', valid['wire'].encode())
print(out['structuredJson']['config']['server']['name'], 'partial:', out['isPartial'])
"

# 3. Re-sondear el RTDB (re-escribe live.json; 27 GET anónimos)
python3 analysis/com.hex.tunnel.jotchuast/73/tools/HexVPN.py --probe \
  --out analysis/com.hex.tunnel.jotchuast/73/live.json
python3 -c "
import json
live = json.load(open('analysis/com.hex.tunnel.jotchuast/73/live.json'))
assert live['catalog']['status'] == 'NO_CATALOG'
assert live['servers'] == [] and len(live['probes']) == 27
assert all(p['http_status'] == 401 for p in live['probes'])
print('NO_CATALOG confirmado: 27/27 sondas 401, 0 servidores')
"

# 4. Validar el live.json guardado sin red (esquema + sin secretos)
python3 analysis/com.hex.tunnel.jotchuast/73/tests/test_live_json.py -v

# 5. Comprobar la entrada supplied y el icono
python3 -c "
import json
d = json.load(open('cloud/web/content/supplied-integrations.json'))
e = next(a for a in d['apps'] if a['id'] == 'hex-tunnel')
assert e['catalogState'] == 'FILE_ONLY' and e['requests'] == []
assert e['versionCode'] == 73 and e['icon'] == 'hexvpn.png'
print('supplied hex-tunnel OK, total apps:', len(d['apps']))
"
```

Entorno: Python 3.10+ con `pycryptodome` (worker) y `argon2-cffi`
instalados según `requirements.txt`; el lector `.hexcm` solo necesita
`pycryptodome`. Ningún comando escribe contraseñas ni valores HWID.
