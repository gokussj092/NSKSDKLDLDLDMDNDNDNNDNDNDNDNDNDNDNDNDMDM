> **Actualización 2026-11-04:** la consulta automática de URL/contraseña ya está implementada en CLI y broker. [Comportamiento vigente y pruebas](REFRESH_2026_11_04.md). El texto siguiente conserva la investigación inicial y sus limitaciones históricas.

# Reproducción desde raíz del repositorio

Rama `feat/nuevas-integraciones`, base61ad524ee44673d69b36253223dbc9d984663137.
CPython3.12.14, OpenJDK17.0.20, Node24.22.1, Linux x86_64. Guardar todos los
originales, tokens y resultados reales en rutas privadas fuera de Git.

## Preparación e insumos

```sh
python3.12 -m venv /ruta/privada/venv
/ruta/privada/venv/bin/pip install -r analysis/com.doriaxvpn.unlimited/129/requirements.lock.txt
curl --fail --location --max-time 40 'https://apkpure.com/http-conexion/com.doriaxvpn.unlimited/download' -o /ruta/privada/apkpure.html
curl --fail --location --max-time 240 'https://d.apkpure.com/b/XAPK/com.doriaxvpn.unlimited?versionCode=129' -o /ruta/privada/HTTP-Conexion-129.xapk
python analysis/com.doriaxvpn.unlimited/129/tools/prepare.py /ruta/privada/HTTP-Conexion-129.xapk /ruta/privada/doria/unpacked
```

Use el Python del venv en los comandos restantes. Aquí se reutilizó el venv de
NAMO:42 distribuciones instaladas,41 hashes de distribución conservados en su
lock ya versionado. `dependency_inventory.py` confirmó versiones; el finalizador
reutiliza hashes solo si coinciden nombre/versión. No hubo reinstalación nueva.
Para auditar una instalación nueva, usar pip `--report` y comparar sus hashes.

XAPK131197249bytes/SHA256
`5ac95f906ec055945ed15172c186ebfcf3f89cbb0c0eff787c89f7d514a21a08`;
base50875400bytes/SHA256
`d55c4ce6181ccd82b1846fac4a2c2298b6e5f6e807b07509c84cfe654b777d82`.
El wrapper exige package exacto/salida vacía; limita extracción y no ejecuta
scripts del APK. El split es armeabi_v7a; no se requirió su código nativo.

## Recuperación estática

```sh
python scripts/apk_analysis/decompile.py --install
python scripts/apk_analysis/decompile.py /ruta/privada/doria/unpacked/inspected/dex/classes.dex /ruta/privada/doria/jadx1
python scripts/apk_analysis/decompile.py /ruta/privada/doria/unpacked/inspected/dex/classes2.dex /ruta/privada/doria/jadx2
python scripts/apk_analysis/decompile.py /ruta/privada/doria/unpacked/inspected/dex/classes3.dex /ruta/privada/doria/jadx3
python scripts/apk_analysis/decompile.py /ruta/privada/doria/unpacked/inspected/dex/classes4.dex /ruta/privada/doria/jadx4
python analysis/com.doriaxvpn.unlimited/129/tools/find_updater.py /ruta/privada/doria/unpacked/inspected/dex /ruta/privada/doria/updater-methods.json
python analysis/com.doriaxvpn.unlimited/129/tools/signature.py /ruta/privada/doria/unpacked/apks/com.doriaxvpn.unlimited.apk /ruta/privada/doria/signature-report.json
```

Se usó el JAR previamente presente con `--jar /ruta/al/jadx-1.5.6-all.jar`,
checksum verificado. `--install` es preparación de entorno nuevo. Ejecutar
cada DEX aunque el anterior termine3: resultados3/0/3/3,22/0/11/3 errores.
Revisar logs/clases y Dalvik; no tratar salida parcial como build Android.
El buscador encuentra seis métodos, incluido sc1.run con244 instrucciones.
No compilar ni ejecutar clases de guards/licencia/Java original del APK.

## Default, Firebase y fuente vigente

```sh
python analysis/com.doriaxvpn.unlimited/129/tools/recover.py /ruta/privada/doria --download
python analysis/com.doriaxvpn.unlimited/129/tools/probe_remote_config.py /ruta/privada/doria
python analysis/com.doriaxvpn.unlimited/129/tools/recover.py /ruta/privada/doria --download --remote-config
```

Primera ejecución: default /Update devuelve57/251, no es la fuente preferida.
Su revisión está en history; en la investigación esos bytes/reporte se
conservaron privadamente como default.enc/default-recovery-report.json antes
del segundo pase. El probe Firebase obtiene200/200 con token FIS auténtico,
template17; elige /new y la misma contraseña del APK. Usa un perfil analítico
MX/es-MX/API34 y elimina la instalación temporal con200. No usa cuentas ni
fabrica Integrity/AppCheck. Opciones API, IDs, refreshToken, authToken y respuesta
completa se guardan0600 únicamente en esa ruta privada; nunca copiarlos a Git.

La segunda ejecución exige la URL /new y contraseña comprobadas, hace GET
original con agente, headers y cachebuster, y obtiene107/244. Si Remote Config
cambia, el assert requiere revisión manual, no seguir nuevos URLs ciegamente.
La lógica operativa no depende de esos archivos privados o de tokens Firebase.

## Campos, claves inline y paridad completa

```sh
python analysis/com.doriaxvpn.unlimited/129/tools/census_fields.py /ruta/privada/doria /ruta/privada/doria/remote-outer.json
python analysis/com.doriaxvpn.unlimited/129/tools/census_fields.py /ruta/privada/doria /ruta/privada/doria/config-outer.json
python analysis/com.doriaxvpn.unlimited/129/tools/set_format_constants.py /ruta/privada/doria
python analysis/com.doriaxvpn.unlimited/129/tools/verify.py /ruta/privada/doria /ruta/privada/doria/remote.enc /ruta/privada/doria/unpacked/extracted/com.doriaxvpn.unlimited/assets/config.json --download
python analysis/com.doriaxvpn.unlimited/129/tools/make_vectors.py
python analysis/com.doriaxvpn.unlimited/129/tools/run_checks.py /ruta/privada/doria/checks
node analysis/com.doriaxvpn.unlimited/129/tools/probe_node.mjs --real /ruta/privada/doria/node.enc
node analysis/com.doriaxvpn.unlimited/129/tools/probe_node.mjs --replay /ruta/privada/doria/remote.enc /ruta/privada/doria/verified/remote.worker.json
```

Censo:27 nombres de campos GCM,5325 apariciones/5299 distintos en107; asset1
tiene84/84. El censo compara Base64 estricto con whitespace Android para mostrar
el primer supuesto fallido. `generated/protected-fields.json` es la unión
sanitizada y revisada de los nombres; no contiene valores. JCA compara todas
esas aperturas con Python/CLI/worker y el objeto entero, no solo recuentos.

Las constantes ya están en codec.py; el setter reproduce su procedencia con
hashes fijados de la receta, sin .env ni credenciales HTTP. `make_vectors.py`
produce únicamente fixtures ficticios con JCA y nonces deterministas de prueba;
no es un exportador ni debe usarse con datos reales. Revisión JCAv1 fallida por
Base64 interior con LF e intermedia se conservan en history, sin reemplazar la
fuente canónica final.

El PNG original viene de `unpacked/inspected/icon.png`, extraído del base por
el inspector:618×613/449874bytes, SHA2565b0e24bd…83b41a. Se copió byte a byte
a cloud/web/public/server-vpn-icons/http-conexion.png; no se recodifica ni limita
al umbral histórico256KiB.

Run checks:10 Python/147 Node. Node usa cwd cloud/web, el resto raíz. Probe real
aquí sale3/REMOTE_NETWORK_DENIED. Replay: HTTP simulado y bytes/worker reales,
4311432bytes completos. No prueba transporte real del VPS. No quitar TLS/proxy
ni eludir denegaciones; repetir en VPS antes del rollout del operador.

Inventario base ejecutado con el helper compartido de Halcon y completado por
`tools/finalize.py /ruta/privada/doria`; versiones y hashes en lock/MANIFEST.
Scripts compartidos conservan origen/hash/commit; no se modifican. No se espera
Android ni se ejecutan merge/deploy. Al desplegar, incrementar la versión
configurada del VPS si supera el piso67, preservando monotonía y switches.
