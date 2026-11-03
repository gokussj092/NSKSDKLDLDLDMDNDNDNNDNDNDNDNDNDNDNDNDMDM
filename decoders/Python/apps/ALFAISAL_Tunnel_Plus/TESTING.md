# Validación ALFAISAL Tunnel+ — 2026-11-01

APK39 y ficha vigente Version -39WH-wake coinciden. Original y certificados
identificados en manifest. JADX1.5.6 produjo33 errores generales; las rutas
críticas se contrastaron con DEX y no se afirma una decompilación perfecta.
LSParanoid `md.a`, chunk `f30808a`, helper `md.b/md.c`:2329 literales,
15 fuentes y2517 cadenas de inventario. La criptografía y la firma son Java/JCA;
`liboglangyan.so` implementa otro protocolo, no el cifrado del catálogo.

| Muestra | Versión | Servidores | Networks | SSLNetworks | Bytes | Campos no vacíos | CBC conserva original |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| res/0k.js | 0.0.0 | 1 | 0 | 1 | 1196 | 5 | 0 |
| POST real HTTP200 | 4.0.20 | 4 | 51 | 103 | 141420 | 428 | 3 |

SHA256 incluido `cc3243bf5af67fdddede02a092f0adc6e3d6cecd9d7bf80813d6dadc93597d72`.
SHA256 remoto `b6300b5218fadbee8b57001fe3612274f7328511a21c4e7903e7bf504c3c8016`.
Referencias independientes JCA:4 valores únicos incluidos y127 remotos, además
del sobre de cada documento. Documentos completos iguales a Python, CLI stdin
y worker aislado. La CLI `--download` repitió el flujo real y devolvió el mismo
JSON completo. La respuesta real del worker pasa el gateway con HTTP interno
simulado:200,4/51/103 e igualdad de rawText y structuredJson.

```sh
python scripts/apk_analysis/alfaisal_verify.py incluido.enc remoto.enc --runtime
python -m unittest tests.test_alfaisal_tunnel_plus tests.test_izph_vpn_pro \
  tests.test_izph_kind2 tests.test_vip_snipher_pro
```

**33 Python aprobadas /0 skips**,11 nuevas. Vectores JCA sintéticos de Unicode,
todas las familias de campos, desconocidos, SSL, proxy legado y HMAC sobre cuerpo
exacto; worker, inventario254, CLI fuera del checkout, límites, tipos y rechazo
del documento entero; secretos antes de transporte, política de integridad,
redirects y fallo503 sin reintentos. Regresiones IZPH/VIP incluidas.

**163 Node aprobadas /0 skips**,11 nuevas. Mismo vector HMAC JCA para Python y
Node; GET previo sin API key, POST firmado exacto, Content-Length, nonce,
DNS/TLS, redirects bloqueados,503 sin reutilizar nonce, política de integridad,
secretos obligatorios, ficha/icono, controles persistentes, sesión/cuota y las
tres listas completas. Se rechazan respuestas parciales/inconsistentes y se
aceptan catálogos con solo redes SSL. Las otras14 fichas/tests actualizan su
contador54→55 sin aumentar la revisión59 ni cambiar las254 rutas de archivo.

Desde `cloud/web`:

```sh
node --test tests/alfaisal-tunnel-plus.test.mjs tests/izph-vpn-pro.test.mjs \
  tests/vip-snipher-pro.test.mjs tests/server-vpn-provider.test.mjs \
  tests/server-vpn-catalog.test.mjs tests/c12-provider-controls.test.mjs \
  tests/server-vpn-version-sync.test.mjs tests/netcol-vpn.test.mjs \
  tests/wolf-custom-vpn.test.mjs tests/jyfast-vpn-ultra.test.mjs \
  tests/aura-net-vpn.test.mjs tests/mnr-tunnel-plus.test.mjs \
  tests/tunneldoom-vpn.test.mjs tests/mtm-tunnel-lite.test.mjs \
  tests/server-vpn-any-speicers.test.mjs tests/file-formats.test.mjs \
  tests/bd-net-vpn.test.mjs tests/apna-vpn.test.mjs
```

Compose YAML válido: los tres secretos llegan solo a web. El transporte Node
al proveedor se verifica con mocks; la descarga real validada usa Python.
No se afirma egress Node real, ejecución Android, sesión VPN ni prueba VPS.
No se publican catálogos reales descifrados, API keys, firma secreta ni identidad
de la instalación. Fuentes y fixtures en Git usan datos ficticios.
Sin deploy, merge, build Android ni Actions. 90NET sigue pospuesto.
