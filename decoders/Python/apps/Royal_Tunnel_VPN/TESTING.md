# Verificación — Royal Tunnel VPN 7.0

Fecha: 2026-10-19. Paquete `kd.app.royaltunnelplus`, versionCode 7.
Rama `feat/cloud-c8-vps-installer-updater`, PR #94.
El análisis se hizo directamente sobre el APK entregado; no se consultó ni
reutilizó `xtproy.py` para reconstruir el formato. El APK, las bibliotecas,
catálogos reales y resultados privados no se incluyen en Git.

## Evidencia de origen

| Muestra | SHA-256 |
|---|---|
| ZIP recibido | `efd3855497e64c1b7063f45b22cc1ae3defb7ac1fbc8d12caf5ffb397ea64882` |
| Contenedor APKS | `e7126ed4757af4b2429a8007da00fed793a2f83c9a38fb692450eec98a4d73e7` |
| `base.apk` | `008bffc727c3dcde94b7f9d01afd82f1753f7133541c34241dd0f37847b4f1eb` |
| `libwg-pro.so` ARM64 | `76264219e7639f04f55165ea3f7f0f4679d02f2192719acf329f6555f7e65a67` |
| Java original `AbstractC3277lF` obtenido con JADX | `bb19b2f05ef973aa74be4354173044c03fa28b79e03d8f0e5efb51c28ba53551` |
| `res/raw/noobdev.js`, 261660 bytes | `d9252abce06e3c86ddfae8e5972d93e479206955585ed2691fbd742d1b98ed4c` |
| Respuesta HTTP 200 HTML, 195 bytes | `5b131ca14aa96311d3432b0062c7443d3b0e6346ec279bd376a75f0a76bcd5d7` |
| PNG Royal original, 415664 bytes | `d5b0acadb3759da52c90cd45a671e264ed98b58e5c838d496e6999b5e1198309` |

El PNG corresponde a `base.apk:res/drawable/icon.png`, 720 × 718.
No se sustituyó por `ic_launcher`, que en este APK contiene una marca residual
diferente. Su exceso de tamaño y la indisponibilidad del catálogo bloquean la
incorporación al catálogo público. No se modifica la versión pública 4.

## Paridad independiente

Se resolvieron las constantes LSParanoid del código entregado. Los métodos
originales Java `E/a/q` se ejecutaron en un lanzador local, sustituyendo
únicamente `GZIPHeader.OS_UNKNOWN` por 255 y sin dependencias Android.
CFB y CBC de todos los campos se contrastaron mediante Java JCE, sin utilizar
el descifrador Python para generar el resultado esperado.

| Catálogo | Servidores | Tweaks | Campos protegidos no vacíos | JSON completo |
|---|---:|---:|---:|---|
| Recurso del APK | 27 | 100 | 1485 | Igual al Java original/JCE |
| Endpoint remoto | — | — | — | HTML «Site Unavailable»; no validado |

Se verificó también la paridad del catálogo real local atravesando el
subproceso privado Cloud, sin recortes ni `isPartial=true`.
La salida legible local del lector ocupa 154618 bytes.

Para el formato `.roy`, se siguieron `ExportActivity.n/onActivityResult`,
`RoyalTunnelMain.R`, `AbstractC4425sf.d` y `AbstractC4129qk.f/g`.
Se ejecutaron las instrucciones ARM64 originales de `Nbencrypt` en Unicorn
para los modos 0 y 1. El arnés reemplaza JNI, libc, vectores estándar y las
llamadas EVP/BIO por adaptadores; **no se ejecutó Android ni la app completa**.
La composición del sobre, orden y longitud de bloques proceden de las
instrucciones nativas. Diez vectores de distinto tamaño, Unicode y bloques
límite coinciden byte por byte con AES generado independientemente por
Java JCE, incluyendo nonce/IV y tag/padding. Nonces/IV deterministas se usan
exclusivamente en estos fixtures sintéticos, nunca para exportar datos reales.

`tests/golden/royal_tunnel_vectors.json` contiene esos vectores, siete perfiles
sintéticos (tipos 0, 5, 6, 7, 8, 9 y 10), un catálogo sintético completo y
entradas inválidas cifradas. Cuentas ficticias, dominios `.invalid`.
`tests/golden/royal_tunnel_oracle.java` conserva el oráculo reproducible
Java/JCE y el inverso Java de XXTEA utilizado para cifrar el catálogo sintético.
No se presenta ese inverso como un cifrador original extraído del APK.

## Pruebas automatizadas

`tests/test_royal_tunnel.py` cubre salida JSON íntegra, servidor como cadena
JSON, metadatos de bloqueo/PIN/caducidad, grupos de protocolos, tweaks con
clave distinta, flags de texto y propiedades desconocidas sin recursión
heurística. Prueba archivos, stdin, BOM, Base64 envuelto/sin padding y una
copia de los tres módulos fuera del repositorio. Rechaza marca/versión
incompatibles, tag GCM alterado, bloques truncados, campos inválidos, enlaces
Cloud usados como archivo, tipos incorrectos, duplicados, NaN/Infinity,
surrogates, profundidad excesiva y entradas de más de 8 MiB.

La descarga simulada comprueba URL fija, límite, timeout, HTTP inválido,
compresión, redirecciones, HTML y errores de red sin divulgar sus cuerpos.
Las pruebas ejecutan los subprocesos Cloud reales tanto con perfiles como
con el catálogo y confirman que `.xtp` conserva su ruta anterior. La prueba
de regresión C2 conserva además el `.roy` antiguo: el router lo identifica
por su alfabeto Unicode, sin importar su algoritmo en el lector nuevo ni
reintentar un archivo moderno corrupto con el motor histórico.
No hay solicitudes a proveedores durante CI.

```bash
python -m unittest discover -s tests -p 'test_royal_tunnel.py' -v
python -m unittest discover -s tests -v
python -m unittest discover -s cloud/workers/python -v
python -m unittest discover -s cloud/infra/vps/tests -v
cd cloud/web
npm test
```

Resultados locales finales: **597 pruebas** de la suite principal Python,
satisfactorias con **9 omisiones existentes** por muestras privadas ausentes;
**13** controles específicos de Royal incluidos en esa suite; worker **11**,
VPS/QA **39**, gates Cloud **4**, Node **60**, sin fallos. La regresión C2 de
`.roy` histórico vuelve a coincidir con su fuente original, sin reescribir
snapshots. Los avisos de drift histórico C2 permanecen visibles. No se
recompila Next.js porque no cambia ningún archivo de su aplicación.

## Límites y pendientes

No se recibió un `.roy` independiente exportado por un usuario. Las pruebas
nativas/JCE corroboran el formato y los perfiles sintéticos, pero el campo
Cloud `exporterCertified` sigue en `false`. No se ensayó la interfaz Android,
conectividad VPN ni vigencia de cuentas. Se conservan los valores almacenados,
sin calcular transformaciones de conexión `NoobLevel`, `sLevel*`,
`Jencrypt1` o `Jencryhenx`. Otras versiones requieren otro análisis.

El catálogo remoto debe volver a validarse cuando entregue datos cifrados.
También hace falta resolver el límite de icono original de 256 KiB antes de
registrar Royal en el broker, contrato y metadatos públicos. No se afirma
que el proveedor público esté habilitado ni que el remoto tenga 27 servidores.
