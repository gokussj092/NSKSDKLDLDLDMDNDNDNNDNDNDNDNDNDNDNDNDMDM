# Validación de VIP Snipher Pro 2.9

Fecha: 2026-10-31, rama `fix/http-jireh-current-method`, base Netcol `9d5c778e`.
Comprobaciones puntuales, sin suite completa, build Android ni despliegue.

## Muestra y referencias

- XAPK APKPure: **59683358 bytes**, SHA256
  `0738801b6fffa10afd01c4b61f091e193dfd976b322a37b5cf7a891821663f44`.
- APK base: SHA256
  `40d856fdbe24824f855be5f16b3341cdfa3e7d82a8c8d622891b60cac94e9b3e`.
- Paquete/manifiesto binario: `dev.renz.soft.vipsnipherpro`, **2.9 / 29**,
  minSDK23, targetSDK36. Certificado SHA1
  `919db7ea6a4d674af519b34f9a23edf4ef77d56c`, igual a la huella pública del mirror.
- Asset `res/aa/d.js`: **252864 bytes**, SHA256
  `ef42646432cb20c3519c9dbee6a545a2a533ecb4a5616880ac9ad7230bcc99fb`.
- JADX1.5.6 fijado por checksum: 39 errores generales. No se presenta como
  descompilación perfecta. LSParanoid: **1824 literales / 71 archivos**, inventario
  de1988 cadenas. Solo aritmética y disassembly, sin ejecutar la aplicación.

`vip_snipher_oracle.java` usa JCA y transcripciones independientes XXTEA y
Threefish; no importa el lector Python. Fixture JSON contiene solo datos
sintéticos, Unicode, campos opcionales, desconocidos y credenciales ficticias.
El oracle ARM64 verifica el hash del SO y ejecuta XXTEA/Threefish con límites
de memoria/instrucciones, sin JNI, llamadas Android ni red.

```sh
python scripts/apk_analysis/vip_snipher_verify.py /ruta/res-aa-d.js \
  --native /ruta/libovpn3.so --runtime
```

Resultado real completo: Version **3.0.22**, **14 servidores / 280 redes**,
**2441 campos / 1750 no vacíos** (modo0:1300, modo1:422, modo2:28).
Igualdad íntegra JCA/Python/worker/CLI stdin. Ocho casos nativos, incluidos
los bordes de ceros Threefish; `isPartial:false`, CLI stdout **172889 bytes**.
La respuesta real del worker pasa también por `fetchWorker`:200, ambas listas
enteras; transporte HTTP interno simulado. No se habilita broker externo.

## Automatizadas

**51 Python aprobadas / 0 skips**, ocho nuevas y regresiones Netcol, Wolf,
HTTP Jireh, JyFast, registro y conservación de inventario.

```sh
python -m unittest tests.test_vip_snipher_pro tests.test_netcol_vpn \
  tests.test_wolf_custom_vpn tests.test_http_jireh tests.test_jyfast_vpn_ultra \
  tests.test_cloud_c8_vpn_registry \
  tests.test_cloud_c8_worker_integration.C8WorkerIntegrationTests.test_unchanged_prior_inventory_and_explicit_new_file_routes
```

**150 Node aprobadas / 0 skips**, en dos grupos:83+67. Incluyen ficha/icono
original, descarga desactivada aun con disponibilidad forzada, rechazo de
broker inexistente antes de transporte, resultado completo y errores/JSON
inconsistentes del worker; regresiones de proveedores, catálogo, sincronización,
formatos, referencias y HTTP Custom online. El generador
`scripts/cloud_formats_catalog.py` confirma metadata de254 formatos intacta.

```sh
cd cloud/web
node --test tests/vip-snipher-pro.test.mjs tests/netcol-vpn.test.mjs \
  tests/wolf-custom-vpn.test.mjs tests/jyfast-vpn-ultra.test.mjs \
  tests/server-vpn-catalog.test.mjs tests/server-vpn-provider.test.mjs \
  tests/server-vpn-version-sync.test.mjs
node --test tests/file-formats.test.mjs tests/server-vpn-any-speicers.test.mjs \
  tests/mtm-tunnel-lite.test.mjs tests/tunneldoom-vpn.test.mjs \
  tests/bd-net-vpn.test.mjs tests/apna-vpn.test.mjs tests/aura-net-vpn.test.mjs \
  tests/mnr-tunnel-plus.test.mjs tests/http-jireh-remote.test.mjs \
  tests/focus-vpn-cloud-remote.test.mjs tests/text-format-catalog.test.mjs \
  tests/http-custom-online.test.mjs
```

## Pendientes concretos

URL del build29 y URL histórica: HTTP404 observado. No hay catálogo remoto
vigente para certificar. Ficha pública `remote:null`, sin switch de proveedor
operativo ni fuente alternativa inventada. Catálogo fuente sigue en59 por
instrucción expresa del propietario. Las rutas V1/V2 y el estado persistente
del panel se conservan; ningún servicio VPS se modificó.

No se probó perfil exportado de build29, importador/exportador Android,
conexión VPN real ni transporte Node al proveedor. APK/SO y documentos reales
no se publican en Git. Original duradero e instrucciones en el handoff.
