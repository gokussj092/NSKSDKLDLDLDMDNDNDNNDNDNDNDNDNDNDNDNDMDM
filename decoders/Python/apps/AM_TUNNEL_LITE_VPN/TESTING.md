# Pruebas de AM TUNNEL LITE VPN — soporte parcial

**No se ha descifrado ni validado el catálogo completo.** Las pruebas aprobadas
no habilitan descarga, perfiles exportados ni certificación del exportador.

Comprobaciones del 2026-10-22:

- **4 tests Python**, con 8 vectores JDK sintéticos: hexadecimal/XOR,
  UTF-8 modificado, emoji, NUL, CRLF, campos largos, errores, límites y CLI
  desde fuera del checkout.
- **8 casos de XOR ARM64 original**: bytes iguales a DataOutputStream JDK.
  Solo se ejecuta `xorWithKey`; la copia C++ de strings está modelada. No hay
  JNI, controles de firma, Android, red o llamadas al sistema.
- **43 comprobaciones web**: ficha desactivada incluso si la disponibilidad
  solicitada es true, PNG original, rechazo del broker, versión y switches.
- Extracción real de la primera capa nativa con `liapp_wrapper.py`: ELF de
  657452 bytes y hash esperado. **DEX y catálogo no recuperados.**
- Consulta al enlace extraído: timeout; sin status/cuerpo HTTP verificados.

No se ejecutaron suites completas del proyecto. Las pruebas CI usan solo
fixtures sintéticos, nunca APK/SO, perfiles reales, claves de usuarios o
catálogos descifrados.

```bash
python tests/golden/am_tunnel_lite_generate.py
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_am_tunnel_lite -v
cd cloud/web
node --test tests/server-vpn-catalog.test.mjs \
  tests/server-vpn-version-sync.test.mjs tests/c12-provider-controls.test.mjs
```

Opcional, desde la raíz y con el SO original autorizado en una carpeta privada:

```bash
python tests/golden/am_tunnel_lite_native_oracle.py ruta/libputils.so
python scripts/apk_analysis/liapp_wrapper.py ruta/libefuyxx.so salida-privada/core.so
```

El oracle y el extractor rechazan builds con hashes distintos. El extractor
no es un desempaquetador completo de LIAPP. `ANALYSIS.md` deja los límites y
el siguiente punto de investigación reproducible. Las herramientas pueden
reinstalarse siguiendo `scripts/apk_analysis/RESTORE.md`.

## Continuación de LIAPP y control de identidad

- **7 Python aprobadas**: las 4 anteriores y 3 para LCG/CRC independientes,
  el bloque sintético de metadatos, relación entre enteros, corrupción,
  truncamiento, límites y rechazo de APK de otro build. CI C2 las incluye.
- 4 vectores LCG, 3 CRC y el sobre sintético se generan con las funciones
  ARM64 originales `0x11798`/`0x10994`, sin modelar esas primitivas.
- APK real: **1003 assets** en el fold; **213 bytes de metadatos**, con hash
  esperado y relación interna válidos. Igualdad completa entre el lector
  estático y el checkpoint nativo original; también probado `--buffers`.
- El checkpoint modela archivos y contexto, acelera helpers de memoria,
  cadenas y CRC y conserva límites de instrucciones/memoria. No demuestra
  Android/JNI, validación completa del guard de firma ni arranque de la app.
- El certificado del APK coincide con un SHA-1 admitido en el flujo local de
  PUtils. No se ha establecido que una petición remota exija ese certificado.
- No cambian runtime Cloud, ficha, disponibilidad ni versión del catálogo;
  las **43 web son la validación anterior**, no una suite repetida en este paso.

```bash
python -m unittest tests.test_am_liapp_metadata tests.test_am_tunnel_lite -v
python scripts/apk_analysis/am_liapp_metadata.py ruta/base.apk
python tests/golden/am_liapp_generate.py ruta/core.so
python scripts/apk_analysis/am_liapp_native_probe.py \
  ruta/core.so ruta/base.apk ruta/split_config.arm64_v8a.apk
```

No se ha abierto el documento `pdrv2.json`, ni reconstruido sus clases o
certificado una respuesta remota. Los nuevos tests no cambian ese estado.
