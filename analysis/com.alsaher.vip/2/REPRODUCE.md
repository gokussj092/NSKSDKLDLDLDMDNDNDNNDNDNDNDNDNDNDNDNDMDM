# Reproducción desde la raíz

Entorno observado: CPython3.12.14, Java17.0.20, Node24.22.1, Linuxx86_64.
JADX1.5.6 se instala/verifica con el script compartido y sus hashes fijados.
Usar un directorio privado fuera de Git; no ejecutar APK ni SO.

```bash
python -m venv /ruta/aislada/alsaher
/ruta/aislada/alsaher/bin/pip install -r analysis/com.alsaher.vip/2/requirements.lock.txt
PRIVATE_DIR=/ruta/privada/alsaher
/ruta/aislada/alsaher/bin/python analysis/com.alsaher.vip/2/tools/prepare.py "$PRIVATE_DIR" --download --inspect
python scripts/apk_analysis/decompile.py --install
python scripts/apk_analysis/decompile.py "$PRIVATE_DIR/inspected/dex/classes.dex" "$PRIVATE_DIR/jadx1"
python scripts/apk_analysis/decompile.py "$PRIVATE_DIR/inspected/dex/classes2.dex" "$PRIVATE_DIR/jadx2"
python scripts/apk_analysis/decompile.py "$PRIVATE_DIR/inspected/dex/classes3.dex" "$PRIVATE_DIR/jadx3"
```

Las tres decompilaciones terminaron exit3/14,16,8 errores respectivamente:
no usar set-e para descartar los resultados parciales conocidos. La adquisición
original se hizo con curl al mismo URL; prepare.py se ejecutó después sobre los
bytes presentes para inventario/extracción. Rechaza un SHA de APK diferente.
La muestra, DEX, fuentes y logs se mantienen privados, nunca en Git.

Revisar con rg FileUtils.showJson/_De/getPass, XxTea, checkUpdate y
OpenVPNClient. La constante y receta coinciden con el motor ZiG y el oráculo
Java canónico; no copiar valores de perfiles ni claves a fixtures.

```bash
/ruta/aislada/alsaher/bin/python analysis/com.alsaher.vip/2/tools/inspect_catalog.py "$PRIVATE_DIR/mtk.hs"
/ruta/aislada/alsaher/bin/python analysis/com.alsaher.vip/2/tools/verify.py "$PRIVATE_DIR/mtk.hs" "$PRIVATE_DIR/included"
/ruta/aislada/alsaher/bin/python analysis/com.alsaher.vip/2/tools/verify.py "$PRIVATE_DIR/mtk.hs" "$PRIVATE_DIR/remote" --download
```

El primer comando hace censo de ubicaciones sin imprimir datos. verify.py
usa Java independiente, compara todo el JSON y ejecuta CLI y worker aislado.
--download hace GET real mediante el módulo operativo con okhttp/4.12.0:
9.9.58/14/3/9; el incluido es9.9.9/4/4/1. Nunca sustituir uno por el otro.
JSON reales, salidas CLI/worker y respuestas cifradas quedan0600 fuera de Git.

```bash
/ruta/aislada/alsaher/bin/python analysis/com.alsaher.vip/2/tools/make_vectors.py
/ruta/aislada/alsaher/bin/python -m unittest discover -s tests -p test_alsaher_vip.py -v
node --test cloud/web/tests/alsaher-vip.test.mjs cloud/web/tests/halcon-r-net.test.mjs cloud/web/tests/server-vpn-provider.test.mjs cloud/web/tests/server-vpn-worker-contract.test.mjs
node analysis/com.alsaher.vip/2/tools/probe_node.mjs --real "$PRIVATE_DIR/node-real.enc"
node analysis/com.alsaher.vip/2/tools/probe_node.mjs --replay "$PRIVATE_DIR/remote/downloaded.enc" "$PRIVATE_DIR/remote/downloaded.worker.json"
```

9 Python/38 Node correctas; Node real dio REMOTE_NETWORK_DENIED del entorno.
Replay con bytes reales/HTTP simulado pasó. No afirmar por ello prueba Node/VPS.
No se esperan compilaciones Android: no hay cambios Android en esta integración.

El PNG público se copia byte a byte de inspected/icon.png (original res/HI.png),
sin renderizado/edición. Se verifica su SHA en el test Node.

Inventario de dependencias reproducido con herramienta canónica existente:

```bash
/ruta/aislada/alsaher/bin/python analysis/com.halcon.connect/1391/tools/dependency_inventory.py "$PRIVATE_DIR/dependencies.snapshot.json" --repo-root .
```

Comparar con dependencies.lock.json; no sobrescribirlo silenciosamente al
actualizar dependencias. Los hashes de las distribuciones pip no se retuvieron:
null/NEEDS_REVIEW, sin inventarlos. Los scripts/recetas y sus hashes sí se
registran. Herramientas no aprobadas para ejecución automática de Fase7.
