# Reproducción desde raíz del repositorio

Base: main45db1d4ed4c18df6911a7f77a744776353223a8c; rama
`feat/nuevas-integraciones`. CPython3.12.14, Java17.0.20, Node24.22.1,
Linux x86_64. APK, SO, decompilación y catálogos reales van en rutas privadas,
nunca en Git. El codec operativo es stdlib; análisis usa dependencias del lock.

## Entorno y adquisición

```sh
python3.12 -m venv /ruta/privada/namo-venv
/ruta/privada/namo-venv/bin/pip install -r analysis/com.appxrayservice.namovpn/35/requirements.lock.txt
curl --fail --location --max-time 40 'https://apkpure.com/namo-vpn/com.appxrayservice.namovpn/download' -o /ruta/privada/apkpure.html
curl --fail --location --max-time 180 'https://d.apkpure.com/b/XAPK/com.appxrayservice.namovpn?versionCode=35&nc=arm64-v8a&sv=24' -o /ruta/privada/NAMO-VPN-35.xapk
python analysis/com.appxrayservice.namovpn/35/tools/prepare.py /ruta/privada/NAMO-VPN-35.xapk /ruta/privada/namo/unpacked
```

Se instaló un venv nuevo con Androguard4.1.4, pyelftools0.33, Capstone5.0.9,
Pillow13.0.0 y PyCryptodome3.23.0 mediante pip `--report`; los42 paquetes
instalados,41 hashes de distribución y relaciones transitivas se conservan
en dependencies.lock. El archivo de reporte original de pip queda privado.
Pip del venv no fue descargado en esa instalación: hash de distribución null.
JADX se ejecutó con JAR ya disponible, comprobado por checksum; no se instalaron
paquetes npm. Usar el Python del venv en los comandos de análisis siguientes.

El XAPK esperado tiene33084055bytes/SHA256
`d97d9f0625f5aecc6641569df709dc32f72a51015f0c3273a92d3e5526290fb1`.
Base8046628bytes/SHA256
`1124a2344ec142526fc2b238f7333aa60a4fc624be3fa4b16846eaaad42516f6`.
`prepare.py` exige salida vacía y package exacto; no ejecuta APK ni SO.

## Fuentes y constantes

```sh
python scripts/apk_analysis/decompile.py --install
python scripts/apk_analysis/decompile.py /ruta/privada/namo/unpacked/inspected/dex/classes.dex /ruta/privada/namo/jadx1
python scripts/apk_analysis/paranoid_strings.py /ruta/privada/namo/jadx1/sources /ruta/privada/namo/jadx1/sources/defpackage/lz1.java /ruta/privada/namo/resolved --inventory --chunk-field b --method q
readelf -Ws /ruta/privada/namo/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libapi-namo.so
python scripts/apk_analysis/elf_inspect.py /ruta/privada/namo/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libapi-namo.so --disassemble 0x6b8 --size 40
python analysis/com.appxrayservice.namovpn/35/tools/signature.py /ruta/privada/namo/unpacked/apks/com.appxrayservice.namovpn.apk /ruta/privada/namo/signature-report.json
python analysis/com.appxrayservice.namovpn/35/tools/recover.py /ruta/privada/namo --download
```

JADX terminó3 con40 errores, conservar su log. La aritmética y las clases
relevantes se cotejan según ANALYSIS; no afirmar reconstrucción Android total.
Se usó `--jar /ruta/al/jadx-1.5.6-all.jar` ya verificado; `--install` anterior
es preparación para entorno nuevo y fija ZIP/JAR por checksum. Cadenas:
890 literales/49 fuentes/937 inventariadas. No ejecutar LSParanoid ni SO;
el helper implementa aritmética pura en Java.

Getters JNI: a0x6b8→string0x4f0; b0x6cc→string0x541. El SO esperado es
SHA256c1242648…e17ebf y4312bytes. `recover.py` fija su hash y fuente, lee las
constantes offline y hace GET HTTPS original con `okhttp/5.3.2`, sin Authorization.
El oráculo Java recibe la clave como dato por stdin y descifra antes que Python.

## Constante inline, icono y comparación completa

```sh
python analysis/com.appxrayservice.namovpn/35/tools/set_format_constant.py /ruta/privada/namo/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libapi-namo.so
python analysis/com.appxrayservice.namovpn/35/tools/extract_icon.py /ruta/privada/NAMO-VPN-35.xapk /ruta/privada/namo/icon.png
python analysis/com.appxrayservice.namovpn/35/tools/verify.py /ruta/privada/namo/unpacked/extracted/config.arm64_v8a/lib/arm64-v8a/libapi-namo.so /ruta/privada/namo/verified /ruta/privada/namo/remote.enc --download
python analysis/com.appxrayservice.namovpn/35/tools/make_vectors.py
python analysis/com.appxrayservice.namovpn/35/tools/run_checks.py /ruta/privada/namo/checks
node analysis/com.appxrayservice.namovpn/35/tools/probe_node.mjs --real /ruta/privada/namo/node.enc
node analysis/com.appxrayservice.namovpn/35/tools/probe_node.mjs --replay /ruta/privada/namo/remote.enc /ruta/privada/namo/verified/remote.worker.json
```

La constante de formato ya viene en el código: `set_format_constant.py`
reproduce su procedencia y escribe esa única línea. No hay `.env` que provisionar
para NAMO. La clave no autentica peticiones ni pertenece a una cuenta.
`extract_icon.py` copia el launcher PNG original de
`res/mipmap-xxxhdpi-v4/ic_launcher.png`,192×192/25421bytes, sin recodificar.
Se conserva en history la primera revisión que rechazó el JPEG llamado icon.png
en el contenedor. No ejecutar esa revisión como método final.

`verify.py` compara documento entero Java/Python/CLI/worker y vuelve a descargar
con el adaptador operativo. Esperado:22.3,14 Servers,13 Networks, SHA256 remoto
578ad82f…eee06. `make_vectors.py` genera datos ficticios con JavaE, nunca copia
registros reales. `run_checks.py` ejecuta Node desde cloud/web y unittest desde
raíz. Solo logs sanitizados y fixtures ficticios entran al expediente.

Node real aquí sale3/REMOTE_NETWORK_DENIED; replay aprobado tiene HTTP
simulado y ciphertext/respuesta del worker reales. Repetir Node real en VPS
antes de certificar ese transporte. No saltar el proxy/TLS ni modificar reglas.

Inventario base ejecutado con
`analysis/com.halcon.connect/1391/tools/dependency_inventory.py` y completado
por `tools/finalize.py /ruta/privada/namo`. Fuentes compartidas se reutilizan
sin cambios, con hash y commit en MANIFEST/lock. No hay autocertificación CI.
Antes del rollout, subir la versión configurada del VPS si supera el piso66;
conservar monotonía, controles y secretos existentes. No se despliega aquí.
