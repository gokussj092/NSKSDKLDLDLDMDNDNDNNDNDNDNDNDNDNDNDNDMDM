# Verificación — My Tunnel Proxy 2.3

Fecha de análisis: 2026-10-19. Rama: `feat/cloud-c8-vps-installer-updater`.
Las muestras y resultados reales permanecen fuera de Git. Los fixtures de CI
solo contienen valores ficticios y hosts reservados `.invalid`.

## Identificación reproducible

| Muestra | SHA-256 |
|---|---|
| ZIP recibido | `60101bcc51431df94842acd2b358a1d4a28352cf6eb6cf1d4afc316a125ba461` |
| Contenedor APKS | `face296ad86b877bd81cc4e6be207e409438c542a6ae5f9ef15672cad21b39a7` |
| `base.apk`, versión 2.3 (23) | `228a088fa36bf80d6de9412c189c88802a019033f2c639cb9f678a55e06e2cce` |
| `libovpn3.so` ARM64 | `e7588d92dba560c24f2df2295aac93b08e649c382dbe34cbf3924bd31115ecb9` |
| Respuesta remota cifrada, 676524 bytes | `48d2ba0f714a0429691f89cff9b7b3d7745241942c096158a8292fcf8c28dc46` |
| Icono PNG original, 82407 bytes | `cdf83eafa496d555c11e88bb14d92c95ff096c648d274196b4336c599fbfe592` |

## Prueba real satisfactoria

Se descargó la URL original, mediante HTTPS y sin cuenta de usuario, y se
comparó **todo el objeto JSON**, incluidos campos desconocidos y tipos, con
una segunda implementación que ejecuta el código ARM64 original en Unicorn.
Las derivaciones HKDF se contrastaron también con OpenSSL.

Resultado: **44 servidores, 601 redes**; 3034 campos tipo 0, 711 campos tipo 1
y 48 campos tipo 2. Se verificó además el sobre tipo 0 completo. La comparación
del JSON íntegro fue idéntica; la salida legible ocupa 419423 bytes.
No se probaron conexiones VPN ni validez de las cuentas remotas.

El CLI final, ejecutado sin argumentos y sin APK, descargó y descifró la
respuesta real. Su JSON coincidió íntegramente con el resultado validado arriba.

La biblioteca nativa se utilizó únicamente durante el análisis local. No se
incluyen APK, `.so`, cuentas ni el catálogo real en el repositorio y no se
necesitan en ejecución. Los lectores no dependen de Unicorn, JADX o Androguard.

## Vectores independientes y casos negativos

`tests/golden/my_tunnel_proxy_vectors.json` contiene perfiles y catálogos
sintéticos, generados con `xxtea_encrypt` y `threefishEncryptBlockWords` de la
biblioteca original. No se genera el ciphertext usando el descifrador probado.

Se comprueban: los tres tipos nativos; Unicode; bloques múltiples; el byte AES
cero final; paridad JSON completa; credenciales anidadas; propiedades nuevas;
PIN/vencimiento sin cambios; BOM y saltos de línea Base64; stdin y CLI desde
otro directorio; descarga fija y acotada; referencia Cloud sin descarga.

Se rechazan: prefijos/documentos incorrectos, campos corruptos, bloques
incompletos, Base64/UTF-8 inválidos, JSON duplicado/no finito, profundidad
excesiva y entradas de más de 8 MiB. Cloud se prueba por sus subprocesos reales
de archivo, texto y catálogo, sin truncamiento ni `isPartial=true`.

Las pruebas Node del broker usan respuestas simuladas: confirman el query fijo,
TLS e IP anclada y rechazan redirecciones a otro host, HTTP, cambio/eliminación
del query e IP loopback. No hay consultas a proveedores en CI.

```bash
python -m unittest discover -s tests -p 'test_my_tunnel_proxy.py' -v
python -m unittest discover -s tests -p 'test_cloud_c8*.py' -v
python -m unittest discover -s cloud/infra/vps/tests -v
cd cloud/web
npm test
npm run build
```

Resultados locales: 573 pruebas de la suite principal Python, satisfactorias
con 9 omisiones ya existentes por muestras privadas ausentes; 11 pruebas del
worker; 39 pruebas del instalador/QA; 4 de los gates Cloud; 59 de Node.
`npm run build` terminó correctamente. Los controles de aislamiento de fuentes
C5 y la paridad de los motores históricos forman parte de la suite principal.
El aviso de drift histórico C2 se conserva, sin actualizar sus snapshots.

## Pendientes explícitos

Una exportación `.mtp` real de la app no fue proporcionada: compatibilidad
confirmada mediante exportador analizado y vectores nativos, no certificación
con archivos reales. Las referencias Cloud autenticadas se identifican sin
descargar su destino. No se realizó despliegue VPS, prueba instrumental Android,
compilación APK ni publicación; esos pasos no forman parte de este cambio backend.
