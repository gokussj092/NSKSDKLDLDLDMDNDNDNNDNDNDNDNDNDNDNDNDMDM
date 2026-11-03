# Reproducción desde la raíz del repositorio

Usar un directorio privado fuera de Git. Los marcadores `PRIVATE_DIR` de abajo
son variables de sesión, no una dependencia de rutas temporales del investigador.
No ejecutar APK/SO ni comandos que una APK proporcione.

## Preparación y adquisición pública

Python3.12.14/Linuxx86_64 y Java17.0.20 son el entorno observado. Los scripts
requieren Python3.10+; solo el entorno observado fue probado. No hay binario
`javac` disponible; Java funciona en modo fuente. Curl8.5.0 es el descargador.
Consultar licencias/limitaciones en DEPENDENCIES; no están aprobadas para la
auto ejecución futura de Fase7.

```bash
python -m venv .venv-halcon
.venv-halcon/bin/pip install -r analysis/com.halcon.connect/1391/requirements.lock.txt
python scripts/apk_analysis/decompile.py --install
PRIVATE_DIR=/ruta/privada/halcon1391
mkdir -m 700 "$PRIVATE_DIR"
.venv-halcon/bin/python analysis/com.halcon.connect/1391/tools/acquire.py "$PRIVATE_DIR/downloads" --apk
```

`decompile.py` descarga JADX1.5.6 desde su release oficial y comprueba hashes
de ZIP y JAR. `acquire.py` fija la variante1391 y rechaza un hash XAPK diferente.
Los GET originales fueron hechos mediante curl; posteriormente se ejecutó
`acquire.py "$PRIVATE_DIR/downloads" --apk --verify-existing` sobre los bytes
ya descargados para registrar la receta. La opción verify no realiza red.
No usar nombres/versión del espejo como sustituto de verificar el APK.

## Inventario, extracción y lectura estática

```bash
.venv-halcon/bin/python analysis/com.halcon.connect/1391/tools/inventory.py "$PRIVATE_DIR/downloads/halcon-1391.xapk" "$PRIVATE_DIR/inventory.json"
.venv-halcon/bin/python scripts/apk_analysis/inspect_apk.py "$PRIVATE_DIR/downloads/halcon-1391.xapk" "$PRIVATE_DIR/unpacked"
```

El último comando **falla de forma conocida** porque el nombre de base no es
`base.apk`; conserva las APK extraídas en unpacked/apks. Continuar explícitamente:

```bash
.venv-halcon/bin/python scripts/apk_analysis/inspect_apk.py "$PRIVATE_DIR/unpacked/apks/com.halcon.connect.apk" "$PRIVATE_DIR/base"
python scripts/apk_analysis/decompile.py "$PRIVATE_DIR/base/dex/classes.dex" "$PRIVATE_DIR/jadx1"
python scripts/apk_analysis/decompile.py "$PRIVATE_DIR/base/dex/classes2.dex" "$PRIVATE_DIR/jadx2"
```

classes.dex dio exit3/22 errores; classes2.dex dio exit0. No usar `set -e` al
reproducir esos fallos conocidos. Dejar los logs en el directorio privado.
Buscar con `rg` los nombres `NativeSecurity`, `AESCrypt`, `nativeDecrypt` y
`getDefaultConfig` en las fuentes obtenidas. Los datos sensibles no se imprimen
en un informe ni se copian a Git.

La biblioteca es la entrada exacta `lib/arm64-v8a/libnative-security.so` de
config.arm64_v8a.apk. Puede extraerse mediante el inspector compartido en un
directorio NUEVO (no reutilizar uno que ya contenga archivos):

```bash
.venv-halcon/bin/python scripts/apk_analysis/inspect_apk.py "$PRIVATE_DIR/unpacked/apks/config.arm64_v8a.apk" "$PRIVATE_DIR/native-extract" --native libnative-security.so
.venv-halcon/bin/python analysis/com.halcon.connect/1391/tools/recover.py "$PRIVATE_DIR/native-extract/native/config.arm64_v8a/libnative-security.so" "$PRIVATE_DIR/unpacked/apks/com.halcon.connect.apk" "$PRIVATE_DIR/recovery"
```

La extracción sobre un split no debe usarse para inferir el paquete base; para
la identidad se usa el APK base. `recover.py` valida ambos hashes y escribe
solo archivos0600. **No adjuntar recipe.json al repositorio ni al chat**.
Referencias ARM64 usadas: nativeDecrypt0xe89ac, getSecretHost0xe572c,
getBackupHost0xe58b0, getDefaultConfig0xec91c; XOR0xed24c/0xed310/0xed3e4/
0xed45c y constructor0xf0038. Inspección adicional mediante `elf_inspect.py`
con `--disassemble DIRECCION --size TAMANO`. No se ejecutó el SO.

## Pruebas locales sin red

```bash
.venv-halcon/bin/python -m unittest discover -s analysis/com.halcon.connect/1391/tests -v
HALCON_SYNTHETIC_PASSWORD=synthetic-only java analysis/com.halcon.connect/1391/tools/EnvelopeOracle.java encode analysis/com.halcon.connect/1391/tests/fixtures/expected.json "$PRIVATE_DIR/synthetic.envelope"
cmp analysis/com.halcon.connect/1391/tests/fixtures/synthetic.envelope "$PRIVATE_DIR/synthetic.envelope"
HALCON_SYNTHETIC_PASSWORD=synthetic-only java analysis/com.halcon.connect/1391/tools/EnvelopeOracle.java decode "$PRIVATE_DIR/synthetic.envelope" "$PRIVATE_DIR/roundtrip.json"
cmp analysis/com.halcon.connect/1391/tests/fixtures/expected.json "$PRIVATE_DIR/roundtrip.json"
```

Resultado observado:12 pruebas correctas, comparación JCA completa y cmp sin
diferencias. Contraseña e IV determinista de este bloque son **solo de prueba**.
El objeto de ejemplo no es un catálogo Halcon real ni define su esquema.

## Petición real autorizada y reproducción completa

El propietario autorizó expresamente la petición firmada después del bloqueo
inicial. La restricción anterior de aprobación quedó resuelta. Conservar el
historial; no repetir solicitudes de permiso para la misma fuente/operación.
La documentación de paridad exige conservar todos los datos originales y
comprobar la descarga real completa.

**Corrección respecto al primer intento:** recover.py actual usa SHA256(DER)
en mayúsculas, sin Base64. La revisión equivocada está conservada en history.
Volver a generar la receta privada con el script actual antes de esta prueba.

```bash
.venv-halcon/bin/python analysis/com.halcon.connect/1391/tools/probe.py "$PRIVATE_DIR/recovery/recipe.json" "$PRIVATE_DIR/probe" --source primary --authorized-primary
.venv-halcon/bin/python analysis/com.halcon.connect/1391/tools/verify_real.py "$PRIVATE_DIR/probe/primary.response" "$PRIVATE_DIR/recovery/recipe.json" "$PRIVATE_DIR/verified" --download
node analysis/com.halcon.connect/1391/tools/replay_real.mjs "$PRIVATE_DIR/probe/primary.response" "$PRIVATE_DIR/recovery/recipe.json" "$PRIVATE_DIR/verified/worker-result.json"
.venv-halcon/bin/python analysis/com.halcon.connect/1391/tools/provision_secrets.py "$PRIVATE_DIR/recovery/recipe.json" "$PRIVATE_DIR/HALCON-backend-secrets.env"
```

Resultados reales observados: HTTP 200, 645168 bytes; versión 635, 101 servidores.
verify_real compara todo con JCA y worker aislado y comprueba una descarga
real adicional desde la CLI operativa. replay_real usa esos bytes y resultados
reales, pero **simula HTTP/DNS**: no es una prueba de red del VPS. Node directo
devolvió REMOTE_NETWORK_DENIED en el entorno; esa prueba en VPS sigue pendiente.
No hay nuevos paquetes npm: Node 24.22.1 y módulos nativos.

El respaldo público sigue devolviendo 404 y no sustituye la descarga principal:

```bash
.venv-halcon/bin/python analysis/com.halcon.connect/1391/tools/probe.py "$PRIVATE_DIR/recovery/recipe.json" "$PRIVATE_DIR/probe-backup" --source backup
```

No ejecutar scripts de history como receta actual. No guardar response,
reference.json, recipe.json, env, worker-result.json ni CLI real dentro de Git.
Los dos secretos de provisión solo van al backend, con consumidores detallados
para web y el hijo Halcon en el README operativo; no cambiar otros proveedores.

## Pruebas operativas e icono

```bash
.venv-halcon/bin/python -m unittest discover -s tests -p test_halcon_r_net.py -v
node --test cloud/web/tests/halcon-r-net.test.mjs cloud/web/tests/server-vpn-provider.test.mjs cloud/web/tests/server-vpn-worker-contract.test.mjs
.venv-halcon/bin/python analysis/com.halcon.connect/1391/tools/extract_icon.py "$PRIVATE_DIR/unpacked/apks/com.halcon.connect.apk" "$PRIVATE_DIR/halcon-r-net.png"
```

10 Python operativas y 12 del expediente: 22 en total. Node: 33 pruebas,
incluidas 7 Halcon. El icono no fue dibujado ni redimensionado: el WebP
legacy original de 192x192 se convierte a PNG con igualdad de píxeles.
El fixture operativo catalog.envelope fue producido con el mismo oráculo JCA,
password sintética `S` repetida 65 veces + `A` repetida 64 veces. Nunca usar
esa contraseña sintética ni el IV determinista en datos reales.

## Dependencias y trazabilidad

```bash
.venv-halcon/bin/python analysis/com.halcon.connect/1391/tools/dependency_inventory.py "$PRIVATE_DIR/dependencies.new.json" --repo-root .
```

Comparar, no sobrescribir silenciosamente el lock auditado. La instalación inicial
usó androguard4.1.4/Pillow13.0.0/PyCryptodome3.23.0 y después capstone5.0.9/
pyelftools0.33; las42 versiones instaladas y metadatos están congelados.
No se conservaron hashes de sus wheels; figura null/NEEDS_REVIEW. Los scripts
compartidos están fijados por checksum en dependencies.lock.json y por base Git
en ANALYSIS. No se modifica su interfaz ni se borra scripts/apk_analysis.
