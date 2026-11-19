# V2Box 6.2.3 (build 88) — REPRODUCE

Desde la raíz del repo, en la rama `ci/unity-ads-online-qa`:

```bash
# 1. Self-test del decodificador corregido (sin red, sintético)
python3 decoders/Python/apps/V2Box/V2Box_archivos.py --self-test
# esperado: 9/9 OK

# 2. Tests de regresión del AAD (sintéticos, sin red)
python3 -m unittest tests.test_v2box_aad -v
# esperado: 5/5 OK
python3 -m unittest tests.test_v2box_password -v
# esperado: 5/5 OK (worker bridge, sin cambios)

# 3. Archivo .v2box v2 real (ruta privada, fuera de Git; nunca
#    escribir sus valores en reportes, commits ni chat)
python3 decoders/Python/apps/V2Box/V2Box_archivos.py \
  ~/workspace/user/files/TheBestVIP_Free_MF____v_box__________0_cp2p.v2box
# esperado: status ok, version 2, kdf none, aad header-b64,
# 1 perfil; ANTES de la corrección daba TAG_MISMATCH.

# 4. Batería de hipótesis AAD/clave contra un archivo (solo
#    estructura/códigos, nunca valores descifrados)
python3 analysis/dev.hexasoftware.v2box/88/tools/verify_aad_candidates.py \
  ~/workspace/user/files/TheBestVIP_Free_MF____v_box__________0_cp2p.v2box

# 5. Vía del servidor (worker): mismo archivo por supplied_bridge
python3 -c "
from cloud.workers.python.supplied_bridge import file_decode
raw = open('~/workspace/user/files/TheBestVIP_Free_MF____v_box__________0_cp2p.v2box','rb').read()
doc = file_decode('v2box', raw, {})
print(doc['status'], doc['version'], doc['kdf'], doc['aad'], len(doc['configs']))"

# 6. Pausa VPN / M Light — re-corrida del catálogo en vivo
#    (petición exacta de la app; el resultado NO lleva las APIs)
python3 decoders/Python/apps/M_Light/M_Light.py --download -o /tmp/mlight.json
# esperado: v1.0.115, 117 servidores, SHA-256
# 7e61c89fc62cb9fd162df2aabd5260b608e262e2ba6f6ef3840d40dae4cc0cd1
python3 decoders/Python/apps/M_Light/M_Light.py --self-test
python3 decoders/Python/apps/M_Light/M_Light_archivos.py --self-test
# esperado: 5/5 y 6/6 OK
```

## Entorno

- Python 3.12.3. El decodificador operativo es stdlib puro.
- `pycryptodome` 4.5.0 solo para los tests del worker
  (`tests/test_v2box_password.py`); sin red.
- El APK local 6.2.3/88 usado para re-verificar la clave fija está
  fuera del repo (`~/workspace/catalogs/v2box/`); el APK no se sube
  a Git.

## Despliegue (lo hace Pedro en el VPS)

La corrección vive en `decoders/Python/apps/V2Box/
V2Box_archivos.py`, que corre en el `decoder-worker`: `update api`
NO basta (solo reconstruye web).

```bash
sudo spdecode backup
sudo spdecode update all <SHA_VALIDADO>
sudo spdecode status
sudo spdecode logs worker 2>&1 | tail -30
```

Después, en la app Online: importar el mismo archivo .v2box y
comprobar que abre (1 perfil). Si sigue dando error, revisar el log
del worker antes que el decodificador (ver incidente V2
`docs/cloud/INCIDENTE_V2_ANDROID_CLOUD_Y_CATALOGO_2026_11_18.md`).
