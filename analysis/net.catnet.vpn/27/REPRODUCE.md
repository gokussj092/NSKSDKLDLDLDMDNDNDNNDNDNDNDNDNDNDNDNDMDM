# Reproducir desde la raíz del repositorio

CPython3.12.14, Node24.22.1, Java17.0.20; Linux x86_64. APK, decompilación,
catálogos, headers/UUID/sesiones y logs reales en directorio privado, nunca Git.
Mantener proxy/TLS heredados. No se necesita Android SDK ni compilar la app.

```sh
python3.12 -m venv /ruta/privada/venv
/ruta/privada/venv/bin/pip install -r analysis/net.catnet.vpn/27/requirements.lock.txt
curl --fail --location --max-time 40 'https://apkpure.com/catnet/net.catnet.vpn' -o /ruta/privada/catnet/apkpure-main.html
curl --fail --location --max-time 180 'https://d.apkpure.com/b/XAPK/net.catnet.vpn?version=latest' -o /ruta/privada/catnet/CATNET-latest.xapk
python analysis/net.catnet.vpn/27/tools/prepare.py /ruta/privada/catnet/CATNET-latest.xapk /ruta/privada/catnet/unpacked
python scripts/apk_analysis/decompile.py --install
python scripts/apk_analysis/decompile.py /ruta/privada/catnet/unpacked/inspected/dex/classes.dex /ruta/privada/catnet/jadx1
python analysis/net.catnet.vpn/27/tools/scan.py /ruta/privada/catnet/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libapp.so /ruta/privada/catnet/app-strings.json
python analysis/net.catnet.vpn/27/tools/dex_trace.py /ruta/privada/catnet/unpacked/inspected/dex/classes.dex /ruta/privada/catnet/api-dex.json
python analysis/net.catnet.vpn/27/tools/source_evidence.py /ruta/privada/catnet
python analysis/net.catnet.vpn/27/tools/signature.py /ruta/privada/catnet/unpacked/apks/net.catnet.vpn.apk /ruta/privada/catnet/signature.json
python analysis/net.catnet.vpn/27/tools/extract_icon.py /ruta/privada/catnet/unpacked/apks/net.catnet.vpn.apk /ruta/privada/catnet/icon.png
python analysis/net.catnet.vpn/27/tools/probe.py /ruta/privada/catnet/remote
python analysis/net.catnet.vpn/27/tools/verify.py /ruta/privada/catnet/remote/servers.json /ruta/privada/catnet/verified --download
python analysis/net.catnet.vpn/27/tools/make_fixture.py
python analysis/net.catnet.vpn/27/tools/run_checks.py /ruta/privada/catnet/checks
node analysis/net.catnet.vpn/27/tools/probe_node.mjs --replay /ruta/privada/catnet/remote/app-update.json /ruta/privada/catnet/remote/servers.json /ruta/privada/catnet/verified/servers.worker.json > /ruta/privada/catnet/node-replay.json
node analysis/net.catnet.vpn/27/tools/probe_node.mjs --real > /ruta/privada/catnet/node-real.json
python analysis/com.halcon.connect/1391/tools/dependency_inventory.py analysis/net.catnet.vpn/27/dependencies.lock.json --repo-root .
python analysis/net.catnet.vpn/27/tools/finalize.py /ruta/privada/catnet
```

Usar el Python del venv para análisis. En esta ejecución se reutilizó JAR con
`--jar /ruta/al/jadx-1.5.6-all.jar` verificado por checksum. JADX termina3/54
errores; inspeccionar log, no dar por reconstruida toda la app. Latest es la URL
real usada, no una garantía de build futura: exigir hash/identidad de MANIFEST
antes de continuar; si cambia, abrir expediente de nueva build. Un 404 del slug
inicial incorrecto no invalida la descarga comprobada por el endpoint XAPK.

Esperado: preflight público `integrity_required:false`, servers200/3710bytes/6filas,
payloads y xray_payloads200/195bytes HTML. Verify compara todo el JSON con Node,
Python, CLI y child worker; segundo download usa el CLI operativo y su preflight.
Los fixtures son ficticios. Catálogo final27 pruebas Python (12 CATNET+15 NAMO)
y181 Node. Probe Node real aquí sale3/REMOTE_NETWORK_DENIED; no confundir replay
con transporte real. Si Integrity cambia a true, detenerse y usar un flujo
legítimo de dispositivo en otra investigación; no inventar tokens ni downgrade.

El runtime no necesita secretos externos. No ejecutar history como receta actual:
son revisiones conservadas de investigación/negativos. Antes del rollout subir
la versión configurada si el VPS ya supera el piso72; conservar monotonía y
switches existentes. No se fusiona ni despliega con estos comandos.

## Revisión actual (2026-11-09)

Se conserva el entorno anterior como histórico. La revisión actual reutilizó Python3.12.14, Androguard4.1.3, OpenJDK21.0.13 y Node24.22.1; no Androguard4.1.4/JDK17 del primer expediente. Usar requirements-maintenance-20261109.lock.txt y dependencies-maintenance-20261109.lock.json para repetir esta revisión.

~~~bash
python analysis/net.catnet.vpn/27/tools/acquire.py /tmp/catnet27-private
python analysis/_intake/austro-cat-2026-11-09/tools/decompile.py /tmp/catnet27-private
python analysis/net.catnet.vpn/27/tools/recheck_20261109.py /tmp/catnet27-private
python -m unittest tests.test_catnet_vpn tests.test_catnet_retry -v
(cd cloud/web && node --test tests/catnet-vpn.test.mjs)
~~~

Si la fuente vuelve a entregar JSON real, aplicar tools/verify.py al archivo privado catalog-current.json antes de cambiar el estado a verificado. No sustituirlo por un fixture ni inferir restauración de pruebas simuladas.
