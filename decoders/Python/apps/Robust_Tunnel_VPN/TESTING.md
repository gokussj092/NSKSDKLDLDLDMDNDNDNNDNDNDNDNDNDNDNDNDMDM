# Verificación — Robust Tunnel VPN isvsoft 16.4.7

Fecha: 2026-10-19. Rama: `feat/cloud-c8-vps-installer-updater`.
App: `app.robusttunnelvpn.nishat.build`, versionCode 16.
Las muestras reales y sus resultados quedan fuera de Git; los fixtures de CI
contienen únicamente datos ficticios y dominios `.invalid`.

## Muestras identificadas

| Elemento | SHA-256 |
|---|---|
| ZIP recibido | `54dd8559e8c33b13cc80d272f06e0a68c5819dcdc432a0cfaef7000648270b1a` |
| Contenedor APKS | `4f584b9cb16a147308af9c32d107a49f0320572a02f9b35f84bd036a860f065b` |
| `base.apk` | `a48ff3aaabb3eb7e3bfd3cc610020b931ede0770c2447de4eba02ae8553238f2` |
| `libisvsoftpro.so` ARM64 | `861f2ca9b0878fd124814616e735edf764c3cf9b32ece8356458c52ef986288a` |
| Java `utils.c` obtenido por JADX | `cd1d635acd5319ed8f94f0d7800ee9e088fcca76c0426112ef96cfd0ec5dedbd` |
| Asset `conf`, 703488 bytes | `7fac50ec4e7297f3770c1bc2ab6f51925a808399c00e3334e5b18d30c6997a7c` |
| Respuesta remota, 1273912 bytes | `6ef6a5e79792f6913dd5aa30c4d66b3e0560b87316d6c78b9ef715c091d058c0` |
| Icono original, 13661 bytes | `2eb1a386a18b79cc9e9e9ab70d5deb772d24ba657a9ad5ca3ed2e97e03e62e24` |

El icono corresponde al recurso de manifest `0x7f0800f4`, resuelto en
`split_config.xhdpi.apk` como `res/drawable-xhdpi-v4/icon.png`.

## Paridad real e independiente

Se obtuvo la URL y el material de formato desde `XEz4WHn` y los getters JNI.
El bootstrap usa AES-256/ECB con SHA-256 de material Base64; se resolvió en el
análisis, sin trasladarlo al lector ni usar cuentas o identificación de dispositivo.

Se ejecutaron las funciones originales Java de `androidx.lifecycle.utils.c`,
tras resolver StringFog y sustituir únicamente el entorno Android por un
lanzador local. No se empleó el descifrador Python para generar el resultado
de referencia. Se compararon el sobre y **todos** los campos reconocidos,
manteniendo sus posiciones, valores desconocidos y tipos del JSON.

| Catálogo | Servidores | Tweaks | Certificados | Campos descifrados | JSON completo |
|---|---:|---:|---:|---:|---|
| Asset local | 74 | 434 | 1 | 1094 | Idéntico al Java original |
| Remoto real | 151 | 1187 | 6 | 2644 | Idéntico al Java original |

La salida legible local ocupa 334180 bytes y la remota 753476 bytes. La prueba
del catálogo real atravesó además el subproceso aislado Cloud y conservó el JSON
íntegro con `isPartial=false`. No se incluyen los catálogos reales, APK, claves
de usuarios ni bibliotecas nativas en el repositorio.

El CLI final, invocado sin argumentos con `python -S`, descargó el catálogo
real y produjo exactamente el JSON validado arriba, sin APK ni paquetes pip.

## Pruebas automatizadas sin red

`tests/golden/robust_tunnel_vectors.json` se generó con el **cifrador Java
original**, no con un inverso del Python bajo prueba. Incluye un catálogo
completo sintético, vectores cortos/largos, Unicode y claves de distintas
longitudes, además de documentos inválidos cifrados con el mismo algoritmo.

`tests/test_robust_tunnel.py` verifica el JSON completo, credenciales y campos
anidados, multilineales, cadenas V2Ray/UDP, números, nulos y propiedades
desconocidas; BOM, saltos de línea, Base64 sin padding; CLI con archivo/stdin
desde una copia aislada con `python -S`, sin imports del repositorio.

Se rechazan Base64/UTF-8/hexadecimal inválidos, bloques incompletos, campos
protegidos corruptos, esquemas incorrectos, claves JSON duplicadas, valores
no finitos, profundidad excesiva y entradas de más de 8 MiB. Una descarga
simulada comprueba URL fija, límite de bytes, errores HTTP, compresión,
respuesta vacía y rechazo de redirecciones. Los tests Cloud invocan el worker
real, sin descargar desde proveedores en CI.

El test Node del broker cubre ambos proveedores con query fijo (My Tunnel
Proxy y Robust), conserva TLS e IP anclada y rechaza cambio/eliminación de
query, otro dominio, HTTP e IP loopback. Las pruebas previas de proveedores e
inventario se mantienen; no se añade una extensión al inventario de archivos.

```bash
python -m unittest discover -s tests -p 'test_robust_tunnel.py' -v
python -m unittest discover -s tests -v
python -m unittest discover -s cloud/workers/python -v
python -m unittest discover -s cloud/infra/vps/tests -v
cd cloud/web
npm test
npm run build
```

Resultados locales: **584 pruebas** de la suite principal Python, satisfactorias
con 9 omisiones existentes por muestras privadas ausentes; **11** del worker;
**39** del instalador/QA; **4** de gates Cloud; **60** de Node, sin fallos.
`npm run build` terminó correctamente. Los controles C5 de aislamiento de
fuentes y la regresión de motores anteriores forman parte de la suite principal.
El aviso de drift histórico C2 se conserva, sin reescribir sus snapshots.

## Límites de lo comprobado

No se recibió una exportación de perfil independiente ni se identificó una
rutina de exportación propia. La ruta de importación consume el mismo formato
de catálogo real validado arriba, sin extensión obligatoria. No se simuló una
prueba de interfaz Android, conectividad VPN ni validez de las cuentas.
La caché `CustomTweaks` es almacenamiento local y no otro formato exportado.
Otras versiones isvsoft pueden cambiar claves, delta, estructura o URL.

No se realiza despliegue VPS, cambio Android, compilación/publicación APK ni
fusión del PR como parte de esta incorporación backend.
