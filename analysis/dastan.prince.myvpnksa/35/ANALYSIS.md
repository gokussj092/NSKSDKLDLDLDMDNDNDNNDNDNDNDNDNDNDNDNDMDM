# Investigación de PrinceBuild35

Fecha2026-11-03. Autorización del propietario: repetir la integración de
catálogo, incluida petición original real, solo Cloud. No se ejecutó la APK ni
el SO, no se invocaron APIs de usuarios, cuentas, atestación o licencia.

## Identidad y muestras

La URL solicitada fue Google Play con `id=dastan.prince.myvpnksa`. El manifiesto
del APK obtenido del mirror APKPure identifica **FNF TUNNEL BD**, PrinceBuild35,
versionCode35; namespace interno `fnf.vpn.app`. No hay equivalencia de firma
comprobada contra Google Play ni certificación de última versión.
Hashes/tamaños completos en MANIFEST. El XAPK contiene APK base con nombre del
paquete, splits de idiomas, densidad y ARM64. El inspector compartido no
identifica ese nombre como `base.apk` automáticamente: se seleccionó por su
nombre exacto y después se confirmó el manifiesto, sin renombrar su contenido.

## Descubrimiento reproducible

1. Descarga pública con curl; inspección ZIP offline y manifiesto con
   Androguard4.1.4. Se extrajeron dos DEX, `assets/gremlin.json`, `server.psi`,
   el original `res/drawable/ic_app_icon.png` y `libputils.so` del split ARM64.
   `prepare.py` reproduce esta selección y fue ejecutado en un directorio nuevo.
2. JADX1.5.6 sobre cada DEX, `--no-res --decompilation-mode simple -j4`, salida3
   con18/9 errores. El código relevante quedó disponible, pero esas salidas no
   son una compilación Android ni prueban toda la app.
3. `paranoid_strings.py` sobre JADX2 y el chunk
   `org/lsposed/lsparanoid/Deobfuscator$MHRTUNNELVPN$app.java`:1496 literales
   resueltos en58 fuentes; inventario2097 cadenas. Se interpreta únicamente la
   aritmética de strings, sin ejecutar clases de la APK.
4. `OpenVPNClient.z()` construye `AI(URL,new Hy(this),...)` con el updater que
   fija el adaptador. `AI.f()` devuelve headers vacíos. `Hy.b()` abre la respuesta
   con `AbstractC0398oi.c`, lee `Version`/`Payloads` y escribe `gremlin.json`.
   El updater no usa la API de cuentas que aparece en otra actividad.
5. `AbstractC0398oi` confirma clave de formato `...|...`, delta con signo
   -1638454863 (`0x9e5729b1`), palabras little endian y longitud al final. La
   referencia Java canónica implementa esa recurrencia sin importar Python.
6. Se inspeccionó ELF con readelf/pyelftools/Capstone, nunca se ejecutó el SO.
   `xorWithKey`0x1466d4/548bytes contiene la constante nativa de12 bytes que
   coincide con BD NET. Es evidencia de familia, **no evidencia de que los
   registros de este catálogo deban pasar por XOR**.

## Hipótesis corregida y evidencia negativa

El primer candidato reutilizó `BD_NET_VPN.decode_json_bytes`, incluidos sus
campos hex/XOR. El asset49.9 no reveló el problema; la respuesta real82.0 falló
en `/Payloads/67/host`: era un texto corto interpretable como hexadecimal,
no un ciphertext. Se conserva el script ejecutado en
`tools/history/recover_v1_inner_xor.py`. Fallo: `Invalid JNI leading byte`.

La inspección de `OpenVPNClient` confirma lectura directa de `server_host`,
`host`, `payload`, `sausage` mediante `getString`, sin `pDecrypt` en esa ruta.
Los usos de `pDecrypt` corresponden a importación/perfiles y al túnel Psiphon,
fuera de este alcance. El método final reutiliza **solo** el sobre externo y
conserva sin transformación todo el documento interior. El vector ficticio
incluye textos hexadecimales para impedir que reaparezca esa corrupción.

## Verificación y alcance

GET real al updater original: HTTP200, `text/plain; charset=utf-8`,613664bytes,
catálogo82.0 con28 Free_servers y1193 Payloads, otras tres listas de servidores
vacías. Varias descargas tuvieron el mismo SHA256. No requería credenciales,
cookies ni atestación. El JSON entero coincide con Java, CLI y child worker;
incluido49.9 también coincide. Resultados sanitizados en `generated/`.

Primitiva no autenticada: límites y esquema rechazan corrupción detectada;
no se promete detectar toda modificación maliciosa válida de XXTEA.
No se comprobó que las cuentas/servidores VPN conecten. No hay rutas nuevas de
archivo, texto o exportación certificadas.

El intento Node real falló antes del transporte con `REMOTE_NETWORK_DENIED`.
El replay usa ciphertext real y resultado real del worker, con DNS/HTTPS
simulados explícitamente. No equivale a una petición Node real ni a un rollout
VPS. Android, merge y despliegue quedan fuera de la ejecución solicitada.
