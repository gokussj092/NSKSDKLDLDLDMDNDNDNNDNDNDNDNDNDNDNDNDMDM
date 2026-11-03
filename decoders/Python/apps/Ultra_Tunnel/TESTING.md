# Validación — Ultra Tunnel v1.0.8.8/build59

2026-11-01, base6d9dc8c, rama fix/http-jireh-current-method.

**Descarga Python real validada:** HTTP200,text/plain,1384477 bytes,
Version5.18,47 servidores/917 redes/5034 campos protegidos distintos.
JSON completo igual a la referencia libsodium+JCA, otra descarga de la CLI
desde/tmp y worker aislado. Ninguna fixture contiene datos reales.

## Comandos

```bash
PYTHONPATH=. python -m unittest tests.test_ultra_tunnel tests.test_cloud_c8_vpn_registry -v
python scripts/cloud_formats_catalog.py
# Generador de referencia sintético, sin importar el motor de producción:
PYTHONPATH=. python -m tests.golden.ultra_tunnel_reference
# Diagnóstico estático del SO original exacto, sin ejecutar JNI:
python scripts/apk_analysis/ultra_tunnel_source_check.py /ruta/privada/libgojni.so
# CLI: stdout contiene todo el catálogo privado:
python decoders/Python/apps/Ultra_Tunnel/server_catalog_decoder.py --download > /ruta/privada/resultado.json
# Compara el documento entero; solo imprime metadatos:
python scripts/apk_analysis/ultra_tunnel_verify.py /ruta/privada/remote.enc --expected /ruta/privada/resultado.json
cd cloud/web
node --test tests/ultra-tunnel.test.mjs tests/server-vpn-catalog.test.mjs tests/server-vpn-provider.test.mjs tests/server-vpn-version-sync.test.mjs tests/c12-provider-controls.test.mjs tests/enaa-tunnel.test.mjs tests/zig-tunnel.test.mjs tests/mm-tunnel.test.mjs
```

Referencia: libsodium crypto_pwhash Argon2id3/8MiB y AES-GCM JDK17+ mediante
el auxiliar genérico en enaa_aes.java. Usa constantes/contextos transcritos
independientemente; no importa el módulo Ultra de producción.
Se generaron tres catálogos sintéticos plain/EO/remoto y un vector KDF.

**9 Python/97 Node aprobadas,0 omisiones.** Incluyen autenticación completa,
campos de todas las secciones, unknowns/Unicode/vacíos/escalares/duplicados de
listas, alteración de tags, framing, tamaño, duplicados JSON, esquemas,
errores saneados, registro del worker, cuotas existentes, controles y refresco.

Replay privado adicional:7 pruebas del gateway con encrypted bytes y resultado
del worker reales, sin subirlos a Git. Las peticiones HTTP y Redis están
simuladas. No es una descarga Node real ni una prueba de producción.

La CLI descargó de nuevo y produjo el mismo JSON. La apertura directa real
tardó61.48s y el worker62.61s, dentro del presupuesto existente120s.
No se amplían límites globales. El SO y el catálogo incluido no son dependencias
del runtime. Dependencias existentes: argon2-cffi25.1.0,PyCryptodome3.23.0.

Node directo: REMOTE_NETWORK_DENIED; DNS devolvió EAI_AGAIN para strongteam.co.
No se alteró TLS, DNS ni proxy para eludirlo. Descarga Node/VPS y Android físico
quedan pendientes. No se ejecutó toda la suite ni builds; sin despliegue/fusión.
[Handoff completo](../../../../docs/cloud/ULTRA_TUNNEL_HANDOFF_2026_11_01.md).
