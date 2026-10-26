# Pruebas

```sh
python -m unittest tests.test_ha_tunnel_plus tests.test_cloud_hat_complete -v
python -m unittest tests.test_cloud_xhypher_renamed_files tests.test_cloud_c0_inventory -v
cd cloud/web
node --test tests/server-vpn-catalog.test.mjs tests/file-formats.test.mjs \
  tests/mtm-tunnel-lite.test.mjs tests/bd-net-vpn.test.mjs \
  tests/apna-vpn.test.mjs tests/aura-net-vpn.test.mjs \
  tests/mnr-tunnel-plus.test.mjs tests/server-vpn-any-speicers.test.mjs \
  tests/text-format-catalog.test.mjs
```

- 8 pruebas Python: lector completo, seis vectores JCA, Unicode UTF-16/emoji,
  conservación de unknown/protecciones/nulos, equivalencia con el lector Node,
  BOM/saltos de línea, opcionales, errores, límite de entrada y salida privada
  que no sobrescribe. Incluye `hat/test.hat` y `hat/test1.hat` del repositorio.
- 13 regresiones Python: aliases Xhypher por contenido, archivos HA genuinos,
  inventario C0 240 y nueve fuentes UI congeladas intactas.
- 7 regresiones Python adicionales: registro C8 de proveedores y soporte Android
  de Server VPN; sin claves ni lógica de descifrado en el catálogo público.
- 4 regresiones de texto C2: 55+ vectores de protocolos y aliases Dark Tunnel;
  comparación corregida para conservar el salto de línea del stdout legado.
  La prueba ya fallaba en el main de origen por aplicar `rstrip` solo al esperado.
- 75 pruebas Node en los nueve archivos indicados: catálogo52/48 fichas,
  icono original, ficha HA desactivada aun si availability=true, versiones y
  compatibilidad de proveedores existentes.
- `python -m py_compile scripts/apk_analysis/ha_runtime_capture.py` y
  `node --check` del SCRIPT generado, sin ejecutar código de entrada.

Los vectores de `tests/golden/ha_tunnel_plus/jca-vectors.tsv` son exclusivamente
sintéticos, producidos con `HatOracle.java` y JCA AES/ECB/PKCS5Padding. Regenerar:

```sh
java tests/golden/ha_tunnel_plus/HatOracle.java > tests/golden/ha_tunnel_plus/jca-vectors.tsv
```

JCA valida la implementación del formato histórico de forma independiente;
no representa haber ejecutado `AESEncryption` de 1.7.1. La comparación Node
verifica continuidad con el lector completo anterior. Las dos muestras reales
son históricas, no exportaciones nuevas hechas con el APK 1.7.1.

Pendientes: constantes y recursos DexProtector, `hideParams` real, exportación
real de este build, GET del catálogo con comparación completa, dispositivo
Android/Termux físico. No se marca soporte remoto habilitado ni nuevos textos o
IDs cloud. C0 240 y C8 254 permanecen sin añadir extensiones.

El flujo `.github/workflows/cloud-c2.yml` ejecuta ambos módulos HA y se activa
también al cambiar la carpeta del lector o sus vectores sintéticos.
