# Reproducción desde la raíz del repositorio

Entorno real: CPython 3.12.14, OpenJDK 17.0.20, Node 24.22.1, Linux x86_64; versiones, dependencias transitivas y hashes conocidos en dependencies.lock.json. Se reutilizó un venv analítico existente; no se instalaron paquetes nuevos. Un intento inicial con Python del sistema no tenía Crypto y se corrigió usando el venv, sin cambiar dependencias. La receta siguiente representa los comandos efectivamente utilizados.

Para otro entorno, crear un venv e instalar las versiones de requirements.lock.txt desde PyPI. Hashes de distribuciones no retenidos se marcan null, no se inventan. El worker necesita las dependencias habituales del proyecto además del decoder. La librería compartida HTTP_FenixVPN/codec.py y field_names.json se mantienen como fuente canónica sin modificar.

PY representa el ejecutable del venv. JADX_JAR representa el JAR oficial 1.5.6 ya disponible, comprobado por el script compartido con SHA256 `fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b`. `scripts/apk_analysis/decompile.py --install` permite obtener la distribución oficial fijada por checksum; esa instalación no se ejecutó para esta app.

```sh
mkdir -p private/genis
curl -sS -L --fail --max-time 90 -o private/genis/Genis-latest.xapk -w '%{http_code} %{content_type} %{size_download}' 'https://d.apkpure.com/b/XAPK/com.doriaxvip.tunnel?version=latest&nc=arm64-v8a&sv=23'
$PY analysis/com.doriaxvip.tunnel/76/tools/prepare.py private/genis/Genis-latest.xapk private/genis/unpacked
$PY scripts/apk_analysis/decompile.py private/genis/unpacked/inspected/dex/classes.dex private/genis/jadx1 --jar "$JADX_JAR"
$PY analysis/com.doriaxvip.tunnel/76/tools/recover.py private/genis --download
$PY analysis/com.doriaxvip.tunnel/76/tools/resources.py private/genis
$PY analysis/com.doriaxvip.tunnel/76/tools/census.py private/genis
$PY analysis/com.doriaxvip.tunnel/76/tools/set_constants.py private/genis
$PY analysis/com.doriaxvip.tunnel/76/tools/verify.py private/genis --download
$PY analysis/com.doriaxvip.tunnel/76/tools/integrate.py
$PY analysis/com.doriaxvip.tunnel/76/tools/make_vectors.py
$PY analysis/com.doriaxvip.tunnel/76/tools/verify.py private/genis --download --worker
$PY analysis/com.doriaxvip.tunnel/76/tools/verify.py private/genis --worker
$PY analysis/com.doriaxvip.tunnel/76/tools/run_checks.py private/genis/checks
node analysis/com.doriaxvip.tunnel/76/tools/probe_node.mjs --real private/genis
node analysis/com.doriaxvip.tunnel/76/tools/probe_node.mjs --replay private/genis
$PY analysis/com.halcon.connect/1391/tools/dependency_inventory.py analysis/com.doriaxvip.tunnel/76/dependencies.lock.json --repo-root .
$PY analysis/com.doriaxvip.tunnel/76/tools/finalize.py private/genis
```

XAPK real esperado: 43.416.878 bytes, SHA256 `a19dcdb4cd1c1af697e7f2b7dd76af19f5e018313e2ae9a94ca752cb4a372831`. Latest es mutable: si cambia el binario, detener la receta y revisar el build, no atribuirle este resultado. Preparación y recursos validan el base hash específico; no ejecutan los .so, scripts o código incluido en assets. prepare exige salida vacía. JADX salió 3/14 errores; se revisaron los métodos concretos y se validaron de forma independiente.

set_constants se ejecutó de nuevo tras el censo para fijar también los tipos conocidos. verify se repitió con el worker real después del wiring y tras fijar los tipos, sin cambiar los documentos. run_checks se repitió después de añadir el test del gateway autenticado: resultado final 9 Python + 161 Node. Las revisiones ejecutadas de los scripts están en tools/history; no ejecutar esos parches como scripts.

La salida de Node real es exit3/REMOTE_NETWORK_DENIED; no ignorarla como una prueba aprobada. El replay es exit0/SIMULATED_HTTP_REAL_BYTES y no demuestra transporte real. Antes del rollout comprobar Node en VPS y mantener la versión configurada monotónica. No ejecutar despliegue, merge ni compilación Android como parte de esta receta.

Para uso operativo, sin clave externa:

```sh
$PY decoders/Python/apps/Genis_VPN/server_catalog_decoder.py > private/genis/result.json
```

El CLI acepta también un ciphertext por ruta o --stdin. No acepta destinos de descarga arbitrarios ni cae al catálogo incluido si falla la red.
