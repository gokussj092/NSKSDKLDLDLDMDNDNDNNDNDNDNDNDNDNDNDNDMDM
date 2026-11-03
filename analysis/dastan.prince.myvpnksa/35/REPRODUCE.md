# Reproducción desde la raíz del repositorio

Use rutas privadas fuera de Git para APK, JADX, catálogos y JSON. Se ejecutaron
CPython3.12.14, OpenJDK17.0.20 y Node24.22.1 en Linux x86_64. Consulte
DEPENDENCIES.md/lock para42 distribuciones instaladas, procedencia y límites
de hashes/licencias. No hace falta instalar paquetes npm. El codec usa stdlib.

```sh
python3.12 -m venv /ruta/privada/fnf-venv
/ruta/privada/fnf-venv/bin/pip install -r analysis/dastan.prince.myvpnksa/35/requirements.lock.txt
```

Los hashes de distribución PyPI no fueron retenidos: el lock fija versiones,
no certifica por sí solo la cadena de suministro. Las licencias transitivas
requieren revisión antes de autoejecución Fase7.

## Adquisición e inspección

La página consultada fue `https://apkpure.com/fnf-tunnel-bd/dastan.prince.myvpnksa/download`.
La descarga observada, fijada por SHA256, fue:

```sh
curl --fail --location --max-time 180 'https://d.apkpure.com/b/XAPK/dastan.prince.myvpnksa?versionCode=35&nc=arm64-v8a&sv=23' -o /ruta/privada/FNF-TUNNEL-BD-35.xapk
python analysis/dastan.prince.myvpnksa/35/tools/prepare.py /ruta/privada/FNF-TUNNEL-BD-35.xapk /ruta/privada/fnf
```

`prepare.py` exige hash `9bf63096a5443dcaa61a5b0135f2c46604f7bd1c86e1770e4f153a6d4ec3c6aa`,
no ejecuta contenidos y exige salida vacía. Crea `apks/`, `inspected/dex`,
`gremlin.json`, `server.psi`, `libputils.so`. El inspector inicial también se
ejecutó directamente sobre el base; mismo resultado.

```sh
python scripts/apk_analysis/decompile.py --install
python scripts/apk_analysis/decompile.py /ruta/privada/fnf/inspected/dex/classes.dex /ruta/privada/fnf/jadx1
python scripts/apk_analysis/decompile.py /ruta/privada/fnf/inspected/dex/classes2.dex /ruta/privada/fnf/jadx2
python scripts/apk_analysis/paranoid_strings.py /ruta/privada/fnf/jadx2/sources '/ruta/privada/fnf/jadx2/sources/org/lsposed/lsparanoid/Deobfuscator$MHRTUNNELVPN$app.java' /ruta/privada/fnf/resolved --inventory
readelf -Ws /ruta/privada/fnf/libputils.so
python scripts/apk_analysis/elf_inspect.py /ruta/privada/fnf/libputils.so --disassemble 0x1466d4 --size 548
python analysis/dastan.prince.myvpnksa/35/tools/recover.py /ruta/privada/fnf --download
```

Ejecute los dos JADX por separado aunque el primero termine3. Se observaron
18/9 errores; revisar las clases indicadas en ANALYSIS, sin asumir decompilación
perfecta. El JAR ya estaba en caché y se verificó su checksum; `--install` permite
reproducir su preparación en un entorno nuevo. Salida de strings:1496/58/2097.
`recover.py` fija la identidad, coteja código/constantes y hace GET público
original con TLS normal. Escribe solo en la ruta privada; imprime metadatos.
`tools/history/recover_v1_inner_xor.py` conserva el intento fallido, no es el
codec recomendado. No ejecutar firma/licencia, clases Android ni `server.psi`.

## Referencia independiente y runtime

```sh
python analysis/dastan.prince.myvpnksa/35/tools/verify.py /ruta/privada/fnf/verified /ruta/privada/fnf/gremlin.json /ruta/privada/fnf/remote.enc --download
python analysis/dastan.prince.myvpnksa/35/tools/make_vectors.py
python analysis/dastan.prince.myvpnksa/35/tools/run_checks.py /ruta/privada/fnf/checks
node analysis/dastan.prince.myvpnksa/35/tools/probe_node.mjs --real /ruta/privada/fnf/node.enc
node analysis/dastan.prince.myvpnksa/35/tools/probe_node.mjs --replay /ruta/privada/fnf/remote.enc /ruta/privada/fnf/verified/remote.worker.json
```

`verify.py` reutiliza `bd_net_verify.java_batch` y las referencias Java canónicas
`bd_net_oracle.java`/`apna_oracle.java`: solo modoC/sobre externo, **sin XOR**.
Compara el documento entero, no solo contadores, y guarda resultados privados.
Los scripts compartidos quedan sin cambios y se fijan por ruta/hash/commit en
MANIFEST/dependencies.lock. No hay una segunda copia divergente.

`run_checks.py` ejecuta unittest desde raíz y Node desde `cloud/web`, que es su
directorio de trabajo esperado. Requiere los iconos/fixtures/rutas originales
del repositorio completo; no sustituirlos por datos inventados. En este checkout
parcial se materializaron desde el commit base. Probe Node real: salida3,
`NETWORK_UNAVAILABLE/REMOTE_NETWORK_DENIED`; replay: HTTP simulado y bytes reales.
Se requiere repetir Node real en el VPS antes de afirmar transporte allí.

No guardar APK, decompilación o catálogos reales en Git. El commit contiene
solo icono de presentación, código propio, fixtures ficticios y evidencia
sanitizada. No se lanzó compilación Android, merge ni despliegue.
