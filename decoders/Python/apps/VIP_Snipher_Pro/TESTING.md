# Validación de VIP Snipher Pro 2.9

Actualizado: **2026-11-01**. Rama `fix/http-jireh-current-method`.
Sin despliegue, fusión a main, build Android ni conexión VPN real.

## Versión, original y fuente

Google Play consultado de nuevo anuncia **2.9** en su HTML y APKPure mantiene
**2.9 /29** como último build. Original recuperado y contrastado:

- XAPK: **59683358 bytes**, SHA256
  `0738801b6fffa10afd01c4b61f091e193dfd976b322a37b5cf7a891821663f44`.
- APK base SHA256
  `40d856fdbe24824f855be5f16b3341cdfa3e7d82a8c8d622891b60cac94e9b3e`.
- Paquete `dev.renz.soft.vipsnipherpro`, versión **2.9 /29**, minSDK23,
  targetSDK36; certificado SHA1
  `919db7ea6a4d674af519b34f9a23edf4ef77d56c`.
- SO ARM64 SHA256
  `0e9f382d7d7249a55c9fcfcd21a1e02c01c98b506a7d95c518a1931e7c809a66`.

JADX1.5.6 fijado por checksum: 39 errores generales; no se presenta como
descompilación perfecta. LSParanoid: **1824 literales /71 fuentes**,
1988 cadenas inventariadas. `VIPSNIPHERPROMain.P()` fija la URL exacta
documentada en README; `s.getHeaders()` declara Accept, versión API y
Authorization. No declara User-Agent propio. No confundir el agente de la
herramienta con un valor original de Android.

Se repitió el GET fijo con la credencial incluida en el APK: **HTTP200**, sin
redirecciones ni acceso a otros endpoints. La credencial solo estuvo en
memoria; su valor no se imprime ni se publica en Git. Las tres pruebas
anónimas previas (agente por defecto, herramienta, Dalvik) dieron404.

## Documentos reales completos

| Muestra | Bytes cifrados | Versión | Servidores | Redes | Campos /no vacíos |
| --- | ---: | --- | ---: | ---: | ---: |
| Asset `res/aa/d.js` | 252864 | 3.0.22 | 14 | 280 | 2441 /1750 |
| GET autenticado | 323244 | 8.0.61 | 47 | 273 | 2829 /1974 |

SHA256 remoto:
`1d68e41fedfd42dead2f6a1285c39494108ca9fe2f949578dd1cda2470aa49e5`.
Remoto: modo0 **1546**, modo1 **368**, modo2 **60** campos no vacíos.
JSON completo igual entre Java independiente, Python, CLI stdin y worker
aislado; `isPartial:false`, CLI stdout **221911 bytes**, sin truncado.
**6 casos nativos ARM64** remotos iguales; el asset incluido conserva los
**8 casos** anteriores, incluidos dos bordes de ceros Threefish.

`vip_snipher_oracle.java` usa JCA y transcripciones independientes XXTEA y
Threefish. El oracle nativo verifica el hash del SO y ejecuta primitivas con
límites de memoria/instrucciones, sin JNI/Android ni red.

```sh
python scripts/apk_analysis/vip_snipher_verify.py catalogo.enc \
  --native libovpn3.so --runtime
```

La respuesta real completa del worker pasa también por `fetchWorker`:
HTTP200, **47/273**, igualdad total de JSON y rawText (**221910 bytes**, sin
el salto de línea de stdout CLI). El transporte HTTP interno fue simulado.
El GET real al proveedor se realizó en Python; no se afirma egress Node real.

## Automatizadas actuales

**11 Python aprobadas /0 skips**: tres modos independientes, estructura
completa, campos desconocidos, rechazos de documento parcial, límites,
worker, inventario histórico, CLI y autorización fija sin exposición.

```sh
python -m unittest tests.test_vip_snipher_pro
```

**99 Node aprobadas /0 skips**, incluidas **8 específicas de VIP**. Cubren
cabeceras y GET exactos, secreto ausente/inválido antes de DNS, TLS/DNS público,
todas las redirecciones bloqueadas, ausencia de credencial en otros proveedores,
ficha/icono, control persistente, sesión del gateway, documento íntegro y
rechazo de salidas inconsistentes. Una repetición de las 8 específicas también
pasó tras añadir el caso de salto de línea final en Authorization.

```sh
cd cloud/web
node --test tests/vip-snipher-pro.test.mjs tests/server-vpn-provider.test.mjs \
  tests/server-vpn-catalog.test.mjs tests/server-vpn-version-sync.test.mjs \
  tests/c12-provider-controls.test.mjs tests/netcol-vpn.test.mjs \
  tests/wolf-custom-vpn.test.mjs tests/jyfast-vpn-ultra.test.mjs
```

Los fixtures usan solo credenciales ficticias. El broker Node y el transporte
al worker usan mocks en estas pruebas; se conserva aparte la prueba GET real
y la igualdad del catálogo remoto real completo. Los grupos históricos
de 51 Python /150 Node corresponden al primer lector offline.

## Despliegue y límites pendientes

La fuente remota y el método están validados. El despliegue del lote 59 todavía
debe provisionar `SPDECODE_VIP_SNIPHER_AUTHORIZATION` como secreto del backend.
Compose la transmite únicamente a web; el worker descifra bytes sin secretos
de descarga. El catálogo público y los switches no contienen su valor.

Se mantienen **59 /53 fichas**, C0 **240**, C8 **254**, overrides **28**.
No se añaden rutas genéricas `.js/.rj`; las rutas históricas
`.vipsnipherpro` y `vipsnipherpro://` permanecen. No se probó un perfil
exportado del build29 ni importación/exportación o conexión VPN Android.
No se ejecutó el JNI completo. Padding/JSON no sustituyen una MAC.

APK, SO, catálogos reales y credenciales no se publican en Git. IDs de los
originales duraderos y reproducción en el handoff.
