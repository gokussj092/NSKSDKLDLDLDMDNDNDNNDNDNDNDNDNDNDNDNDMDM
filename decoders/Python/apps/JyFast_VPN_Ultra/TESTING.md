# Evidencia y reproducción: JyFast VPN Ultra 9

Comprobado el 2026-10-31, sin despliegue ni cambios en `main`.

## Procedencia

- Descarga: `https://d.apkpure.net/b/XAPK/http.jyfast.vpnultra?version=latest`.
  El nombre `latest` devolvió **9 / build 9**, no la versión 10 anunciada.
- XAPK: 53680197 bytes; SHA-256
  `1c1a900695e1ee6b3906806a37278d2407e99f505b906749ace28d71c650611e`.
- Base APK: 25417048 bytes; SHA-256
  `266561adfefdc2245fd0ad6dd74dc44cbdc3e07ac7034790315de9e6464869eb`.
- Certificado original SHA-256:
  `5bd175715917cb6be21bc3fa5b25000edc92ec4aa224c27f93d4cd76cb9c60f8`.
- ARM64 `libprominexVMP+.so`: 644656 bytes; SHA-256
  `fcf34bb13c2b6ca3e76a804ed90bc3dc1e142ed28cd9d9ad29d2a78389da988a`.
- `assets/prominex-vmp+.vmp`: 202412 bytes; SHA-256
  `3b1497a20a8adad9d8fc86057a27b3689f28290ed4e45675fec97ed29cbb84be`.

El sondeo nativo se reproduce desde la raíz con dependencias de análisis
`unicorn`, `pyelftools`, `capstone` y `pycryptodome`:

```bash
python scripts/apk_analysis/jyfast_vmp_strings.py /ruta/libprominexVMP+.so /ruta/base.apk
```

Recupera 16 constantes por defecto, incluidas fuente, encabezado, modos y
contraseñas. El modelo tiene límite de instrucciones y no ejecuta hilos ni
llamadas del sistema reales. Los índices 2372–2376 pertenecen también a una
implementación AESCrypt distinta: el catálogo activo se normaliza desde
**Rt.a/b**, evitando mezclar la derivación hexadecimal de otra clase.

## Pruebas automatizadas

Desde la raíz, con PyCryptodome 3.23.0 y JDK disponible:

```bash
python -m unittest tests.test_jyfast_vpn_ultra tests.test_http_jireh
```

Las 10 pruebas nuevas de
`tests/test_jyfast_vpn_ultra.py` cubren ambos modos, los 22 campos, claves y
tipos desconocidos, Unicode, vacíos, worker real aislado, lote incompleto,
JSON ambiguo, límites, errores sin datos, CLI fuera del repositorio, fuentes
fijas y el hash del icono. Los vectores GCM/DES compartidos ejercitan el
importador SKS. La comprobación Java no tuvo skips en esta ejecución.

`tests/golden/jyfast_oracle.java` es un oráculo JCA independiente normalizado
del DEX. Los vectores guardados se generaron con ese oráculo, sin datos reales.
Su interfaz por stdin es `enc` o `dec`, tabulador, contraseña UTF-8 en Base64,
tabulador, valor UTF-8 en Base64; cada línea devuelve el resultado en Base64.

Desde `cloud/web`:

```bash
node --test tests/jyfast-vpn-ultra.test.mjs tests/server-vpn-provider.test.mjs tests/http-jireh-remote.test.mjs tests/focus-vpn-cloud-remote.test.mjs tests/server-vpn-catalog.test.mjs tests/server-vpn-version-sync.test.mjs
node --test tests/file-formats.test.mjs tests/server-vpn-any-speicers.test.mjs tests/mtm-tunnel-lite.test.mjs tests/tunneldoom-vpn.test.mjs tests/bd-net-vpn.test.mjs tests/apna-vpn.test.mjs tests/aura-net-vpn.test.mjs tests/mnr-tunnel-plus.test.mjs tests/text-format-catalog.test.mjs tests/http-custom-online.test.mjs
```

Resultados: **23 Python y 132 Node aprobadas**, sin skips. Los controles
comprueban que añadir JyFast preserve un proveedor Jireh desactivado y avance
la versión; los transportes rechazan DNS privado y redirecciones. No se lanzó
GitHub Actions para estas comprobaciones locales.

## Datos reales, conservados fuera de Git

| Fuente | Version | Servidores | Bytes cifrados | Campos no vacíos descifrados |
| --- | --- | ---: | ---: | ---: |
| free | 33 | 44 | 69128 | 387 |
| premium | 27 | 49 | 77661 | 400 |

SHA-256 de las respuestas cifradas:

- free: `403b7b7fa7f05a2399e322cbd34bbc55b0cb5e7e9603d84e3d21bd3fb967d073`.
- premium: `ab366324cfc98d0f5aa0cd0d7676a4c67c72f4ffb718589c085c2746d5137ba6`.

Se comparó la totalidad de ambos JSON y sus 787 campos con Java, Python y el
worker aislado. El lote produjo 135122 bytes UTF-8, 93 servidores y
`isPartial=false`. El CLI final también descargó y descifró los dos modos.
La primera captura gratuita fue 32/43 (67623 bytes): un cambio del proveedor
explica esa diferencia, no se fija el recuento en las pruebas.

Pendientes explícitos: APK 10, modo custom (404), claves de los assets
incluidos, archivo exportado real de JyFast, ejecución Android completa,
conexión VPN y despliegue. La emulación de cadenas y las pruebas sintéticas
no certifican esos flujos. El transporte Node no llegó al proveedor real
desde este entorno; su contrato se comprobó con DNS/HTTP simulados.
