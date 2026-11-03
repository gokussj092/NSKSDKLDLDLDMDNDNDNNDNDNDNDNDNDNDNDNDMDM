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

## Red del catálogo y bloqueo explícito

Solo se verificó el respaldo público con:

```bash
.venv-halcon/bin/python analysis/com.halcon.connect/1391/tools/probe.py "$PRIVATE_DIR/recovery/recipe.json" "$PRIVATE_DIR/probe" --source backup
```

Esperado observado: exit3, HTTP404, text/plain,14 bytes, hash en RESULTS.
No hay credenciales de cuenta, identificador de dispositivo, cookies o tokens
en esa petición. El script prohíbe redirecciones y destinos no reconocidos.

**No ejecutar primary ahora.** Auto-review rechazó enviar la firma derivada
de APK sin autorización explícita del propietario. Tras obtener esa autorización,
la propuesta revisable es el mismo script `--source primary --authorized-primary`.
La opción no concede permiso por sí misma. No ejecutar variantes de history;
conservan fallos y revisiones, no son recetas aprobadas.

Después de una respuesta real autorizada, probar el candidato local con
`envelope_candidate.py RESPUESTA RECIPE_JSON SALIDA_PRIVADA`; autenticar el sobre
no certifica por sí solo campos nativos, esquema o integración del broker.

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
