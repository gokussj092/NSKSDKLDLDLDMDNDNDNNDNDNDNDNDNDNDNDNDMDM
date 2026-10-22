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
