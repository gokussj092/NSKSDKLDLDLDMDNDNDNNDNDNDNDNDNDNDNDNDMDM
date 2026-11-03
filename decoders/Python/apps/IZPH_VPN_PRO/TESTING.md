# Pruebas de IZPH VPN PRO 6.0

Fecha: **2026-11-01**. Rama `fix/http-jireh-current-method`, base VIP
`799a523b`. Sin build Android, despliegue, fusión a main ni Actions.

## Original y actualización vigente

Google Play consultado en vivo anuncia 6.0; las páginas indexadas que anunciaban
5.9 estaban atrasadas. El XAPK descargado confirma paquete
`com.izphprov2.net`, **6.0 /60**, minSDK24, targetSDK36.

- XAPK 70977739 bytes, SHA256
  `202e41a764200958803af9ef95a62f6d0737bad7848c09fb116a449025e87b64`.
- APK base 27559164 bytes, SHA256
  `127e4124714108d56b1eb20d9cc61ea69eb5f3cf01ac9f76ca8c8f8c27d8d4c7`.
- Firma SHA1 `b54eb2646f84cafdab35d6c55bd7e01608cdd43d`, igual a la familia
  publicada por el mirror; SHA256
  `c1d7cc7d6f31cf485d9c293f568f606792a27d15ad8176b1dbe5539ece5c9fc8`.
- SO ARM64 `libovpn3.so`,9120680bytes, SHA256
  `3c6ad15db5484317c557ae1c1935b102f264c86420552cd53d449045a09ca8c5`.

JADX1.5.6 fijado:33 errores generales; no se presenta como decompilación
perfecta. LSParanoid `fo.a(long)`, campo a, estado `c1.q`: **2070 literales /
95 fuentes /2280 cadenas**. Se resuelve por aritmética, sin ejecutar la app.

`IZPHPROMain.V()` usa el GET literal indicado en README con un StringRequest
sin override de cabeceras. `activities.j.w()` abre `R.raw.g /servers /
0x7f110006`, resuelto por ARSC a `res/ae/e.rj`. `vk1.b/c` llaman JNI con
selectores0/1/2. Los consumidores de Main confirman los mapas explícitos.

## Comparación de documentos reales

| Muestra | Versión | Servidores | Redes | Campos /no vacíos | Bytes cifrados |
| --- | --- | ---: | ---: | ---: | ---: |
| Incluido | 1000.0.1208 | 60 | 110 | 1598 /1224 | 279596 |
| GET vigente HTTP200 | 3234 | 84 | 303 | 3692 /2560 | 480620 |

Incluido SHA256:
`3300d7238a43f8710cc418366944c5a85e8d01fe4120318158461e7bb86559b1`.
Remoto SHA256:
`40e2155da7be0d23bf54fedc239b4cb3adfd2f4dd103dffa3bb8944c0241269e`.
Remoto no vacíos: modo0=1939, modo1=471, modo2=150.

Los documentos completos coinciden con JCA y las transcripciones independientes
XXTEA/Threefish; luego con Python, CLI stdin y worker aislado. CLI stdout
incluido153284bytes/remoto322051bytes, sin truncado. **6 casos ARM64 por
muestra** iguales. El vector JCA de ciphertext con cero final también coincide
con el bloque Threefish ARM64: **13 casos nativos en total**, sin JNI/Android.

El orden Threefish inverso corregido se contrasta con un stream independiente
de varios bloques y tweak variable, no con un roundtrip del mismo código.
Los tests comprueban el lector histórico y el nuevo lector. Los fixtures usan
solo datos ficticios; no incluyen catálogos reales ni cuentas.

```sh
python scripts/apk_analysis/izph_verify.py incluido.enc remoto.enc \
  --native libovpn3.so --runtime
```

La CLI `--download` hizo un GET adicional real y devolvió exactamente el
mismo documento remoto. La respuesta real del worker pasa `fetchWorker` con
HTTP interno simulado:200,84/303,rawText322050bytes e igualdad completa.
El GET real se realizó en Python; el transporte Node al proveedor se prueba
con mocks, no se afirma egress Node real ni ejecución Android.

## Pruebas focalizadas

**22 Python /0 skips**:10 IZPH nuevas,1 regresión histórica kind2 y 11 VIP.
Incluyen tres modos, SSCommand, tipos/desconocidos, rechazos de campos
malformados/documento parcial, límites, stdin fuera del repo, worker y catálogo
de formatos; más orden inverso Threefish y borde de cero final.

```sh
python -m unittest tests.test_izph_vpn_pro tests.test_izph_kind2 \
  tests.test_vip_snipher_pro
```

**152 Node /0 skips**, grupos105+47. Seis pruebas IZPH verifican GET/URL/agente
exactos, ausencia de Authorization de otros proveedores, DNS privado,
redirecciones, icono/ficha, switch persistente y gateway con sesión/cuota.
El resultado completo se conserva y se rechazan respuestas inconsistentes.
Regresiones de VIP, Netcol, Wolf, JyFast, proveedores, catálogo, controles,
sincronización, formatos y las otras fichas cuyo contador pasó53→54.

```sh
cd cloud/web
node --test tests/izph-vpn-pro.test.mjs tests/vip-snipher-pro.test.mjs \
  tests/server-vpn-provider.test.mjs tests/server-vpn-catalog.test.mjs \
  tests/c12-provider-controls.test.mjs tests/server-vpn-version-sync.test.mjs \
  tests/netcol-vpn.test.mjs tests/wolf-custom-vpn.test.mjs tests/jyfast-vpn-ultra.test.mjs
node --test tests/aura-net-vpn.test.mjs tests/mnr-tunnel-plus.test.mjs \
  tests/tunneldoom-vpn.test.mjs tests/mtm-tunnel-lite.test.mjs \
  tests/server-vpn-any-speicers.test.mjs tests/file-formats.test.mjs \
  tests/bd-net-vpn.test.mjs tests/apna-vpn.test.mjs
```

El generador `scripts/cloud_formats_catalog.py` confirma254 rutas efectivas,
240 C0 y28 overrides intactos. No se registra .rj ni una nueva extensión.

## Límites explícitos

Fuente remota y método validados; ficha/broker/control preparados para el
lote59. No despliegue VPS, Android físico, JNI completo ni conexión VPN real.
Perfil .izph exportado real6.0 no aportado; no se certifica ese exportador.
Datos reales y binarios permanecen fuera de Git. Recuperación e IDs en el handoff.
