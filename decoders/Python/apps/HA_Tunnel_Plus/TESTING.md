# Verificación reproducible

Desde la raíz del repositorio, con PyCryptodome:

```sh
python -m unittest tests.test_ha_catalog_export tests.test_ha_tunnel_plus \
  tests.test_cloud_hat_complete tests.test_cloud_xhypher_renamed_files \
  tests.test_compatible_export tests.test_cloud_c0_inventory -v
PYTHONPATH=cloud/workers/python:. python -m unittest discover \
  -s cloud/workers/python -p 'test_*.py' -v
python tests/native_jni_contract.py
cd cloud/web
node --test tests/ha-tunnel-plus.test.mjs tests/server-vpn-catalog.test.mjs \
  tests/server-vpn-provider.test.mjs tests/compatible-export-policy.test.mjs \
  tests/c3-security.test.mjs tests/c12-provider-controls.test.mjs \
  tests/server-vpn-worker-contract.test.mjs tests/ultra-tunnel.test.mjs
```

Resultados del cierre:42 pruebas Python +19 del worker,114 Node,0 skips;
contrato JNI25 descriptores correcto. Incluyen conservación completa,
numéricos desconocidos sin redondear, UTF16/emoji, los cuatro exportadores
previos, rutas Xhypher renombradas, C0 congelado, negociación de cinco destinos,
rechazo de HTML/duplicados/esquemas ambiguos, DNS privado, redirecciones,
switch persistente y contrato autenticado broker/worker. Los tests públicos
usan datos sintéticos; no sustituyen la evidencia real siguiente.

## Referencia independiente sobre entradas privadas

JDK17, Gson incluido en el JAR oficial JADX1.5.6 fijado por las herramientas:

```sh
umask 077
java --class-path /privado/jadx-1.5.6-all.jar \
  tests/golden/ha_tunnel_plus/Ha171Oracle.java catalog \
  /privado/main.txt /privado/jca-catalog.json
java --class-path /privado/jadx-1.5.6-all.jar \
  tests/golden/ha_tunnel_plus/Ha171Oracle.java inspect \
  /privado/config.hat /privado/jca-open.json
java --class-path /privado/jadx-1.5.6-all.jar \
  tests/golden/ha_tunnel_plus/Ha171Oracle.java export \
  /privado/config.hat /privado/jca-open.hat
python decoders/Python/apps/HA_Tunnel_Plus/server_catalog_decoder.py \
  -o /privado/cli-live.json
```

JCA usa SHA1/AES del proveedor Java y XOR por char Java; no importa el codec
Python ni emplea sus resultados como referencia. Reproduce las primitivas
recuperadas de la fuente, no equivale a ejecutar la app en Android.
Los vectores sintéticos históricos de `HatOracle.java` se conservan.
La referencia nueva crea el destino0600 y falla si ya existe.

Recuperación repetible de cadenas sobre el APK MOD exacto documentado:

```sh
python -m pip install unicorn pyelftools capstone
python scripts/apk_analysis/ha_mod_strings.py --apk /privado/ha-171-mod.apk \
  --sources /privado/jadx/sources/app/fast/ssh --output /privado/strings.json
```

Comprobado con925 cadenas iguales al inventario inicial. No necesita Android,
Frida, cuentas ni red. Mantener el inventario privado.

## Lo comprobado y lo pendiente

- GET HTTP200 real296647 bytes y segunda descarga mediante CLI nueva.
  JSON entero igual a JCA, CLI y worker, sin `isPartial`:13 servidores,
  644 métodos y4 grupos. Véanse hash/versiones en ANALYSIS.md.
- Cinco recursos incluidos leídos aparte, sin confundirlos con remoto.
- Dos `.hat` reales históricos abiertos, exportados y reabiertos por JCA y
  worker:16 campos de perfil cada uno y todos los metadatos iguales.
- Gateway con respuesta real del worker y transportes HTTP/Redis simulados;
  esta repetición no se presenta como una petición real desde Node.
- La ejecución Node directa desde este entorno no alcanza el origen por DNS
  EAI_AGAIN. La descarga real Python sí funcionó; falta probar transporte Node
  y disponibilidad en el VPS tras un despliegue autorizado.
- Importación en Android físico, archivo nuevo exportado ejecutando el MOD y
  build Android pendientes. Solo se comprobó el contrato nativo de fuentes;
  no se afirma una compilación de Kotlin/C++ ni compatibilidad física total.

No se fusionó, desplegó, publicó APK, ejecutó CI manual ni cambió C11.
