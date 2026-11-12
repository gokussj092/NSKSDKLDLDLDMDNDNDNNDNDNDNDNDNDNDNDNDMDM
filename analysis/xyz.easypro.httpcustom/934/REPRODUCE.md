# Reproducción — desde la raíz del repositorio

Usar CPython 3.12.14 y versiones de `dependencies.lock.json` en un entorno
aislado. Los pasos de inventario/pruebas no requieren red. Los probes JNI
requieren Unicorn, Capstone y pyelftools. JADX 1.5.3 se obtiene de su release
oficial; hash en el lockfile. No se incluyen binarios de terceros.

Los ejemplos usan `/privado/` como rutas del operador, fuera del checkout.
`auth.json` contiene únicamente password/hwid reales y nunca se añade a Git.
El ID de acceso se lee de otro archivo privado, no de argv.

```sh
python analysis/xyz.easypro.httpcustom/934/tools/inventory.py /privado/muestras
python analysis/xyz.easypro.httpcustom/934/tools/extract_apks.py /privado/original.apks /privado/934
python analysis/xyz.easypro.httpcustom/934/tools/verify_private.py /privado/muestras < /privado/auth.json
python analysis/xyz.easypro.httpcustom/934/tools/inspect_access_wrapper.py /privado/acceso.hc --access-id-stdin < /privado/access-id.txt
python -m unittest discover -s analysis/xyz.easypro.httpcustom/934/tests -v
python -m unittest tests.test_http_custom_899 tests.test_hc_sip_new_variants tests.test_cloud_c2_hc tests.test_hc_legacy57 -v
```

Resultado esperado de estas muestras: nueve exteriores autenticados,
`full_json_authenticated=0`; lector `UNSUPPORTED_SCHEMA`, worker
`DECODE_FAILED`. Verificar hashes contra `generated/inventory.json`.

Hipótesis fallidas conservadas, sin imprimir plaintext ni claves:

```sh
python analysis/xyz.easypro.httpcustom/934/tools/probe_existing_schedule.py /privado/muestras < /privado/auth.json
python analysis/xyz.easypro.httpcustom/934/tools/probe_existing_schedule.py /privado/muestras --historical-fold < /privado/auth.json
```

Receta nativa de investigación. No usarla como motor de producción ni como
validación de importación. Mantener binarios, logs y snapshots fuera de Git.
Un límite de instrucciones no sustituye el límite de tiempo externo:

```sh
python analysis/xyz.easypro.httpcustom/934/tools/unseal.py /privado/934/libruntime.so /privado/934/libruntime-initialized.so
python analysis/xyz.easypro.httpcustom/934/tools/unseal.py /privado/934/libf2c.so /privado/934/libf2c-initialized.so
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/jni_format_probe.py /privado/934/libruntime-initialized.so /privado/934/runtime-jni.json
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/jni_format_probe.py /privado/934/libf2c-initialized.so /privado/934/f2c-jni.json
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libf2c-initialized.so /privado/934/kdf-c.json --entry c
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libf2c-initialized.so /privado/934/kdf-d.json --entry d
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libf2c-initialized.so /privado/934/kdf-session.json --entry c --session
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libf2c-initialized.so /privado/934/kdf-n11.json --entry c --schedule n11
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libf2c-initialized.so /privado/934/kdf-provider.json --entry provider
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libf2c-initialized.so /privado/934/kdf-provider-five.json --entry provider --family 5
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libf2c-initialized.so /privado/934/kdf-envelope.json --entry envelope
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libruntime-initialized.so /privado/934/kdf-native.json --entry native
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libruntime-initialized.so /privado/934/context.json --entry context
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libf2c-initialized.so /privado/934/init.json --entry init
timeout 60s python analysis/xyz.easypro.httpcustom/934/tools/decode_strings.py /privado/934/libf2c-initialized.so /privado/934/strings.json
```

JADX se ejecutó con `-j 4 --show-bad-code -d /privado/934/jadx
/privado/934/base.apk`. Finalizó con 55 errores. Desensamblados puntuales:

```sh
python scripts/apk_analysis/elf_inspect.py /privado/934/libruntime-initialized.so --disassemble 0x78694 --size 0x600
python scripts/apk_analysis/elf_inspect.py /privado/934/libruntime-initialized.so --disassemble 0x28901c --size 0x500
```

El enlace privado fue leído mediante curl GET/HEAD con TLS y sin cookies,
token, API key ni headers de identidad. Repetir solo con una referencia propia
activa; no guardar ni imprimir URLs de destinatarios en logs públicos.
