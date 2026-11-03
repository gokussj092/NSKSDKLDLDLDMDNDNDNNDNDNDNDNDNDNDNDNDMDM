# Wolf Custom VPN: integración y recuperación persistente

Estado actualizado el **2026-10-31**. Este documento sustituye el punto inicial
`7a6eb25a` de esta misma rama. La integración verificada está en
`decoders/Python/apps/Wolf_Custom_VPN/`; consultar sus `README.md`, `TESTING.md`+y `manifest.json` para el método, hashes y alcance exacto.

## Estado que debe recuperar el siguiente chat

- Repo Goku: `gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`.
- Rama: `fix/http-jireh-current-method`. Jireh/JyFast previos y los cambios de
  caché de revisión 58 se conservan; la nueva revisión mínima es **59**.
- Wolf Custom VPN, paquete `core.vpn3jx.xtreme`, **v2.8.1.2 / build 13**.
- Fuente activa: `https://strongteam.co/api/wolfcustom/newv1.txt`, recuperada
  desde `ConfigUpdate.b`. No usar la fuente histórica `/api/wolf/` como fallback.
- Método moderno: Base64(nonce12 || ciphertext || tag16), AES-256-GCM sin AAD,
  dos claves de 32 bytes directos, verificadas en ARM64 de `libgojni.so` y
  `libgoinjector.so`. No usar el KDF Argon2 del lector Wolf antiguo para estos
  catálogos. `wolf_native_constants.py` verifica bibliotecas y bindings.
- Catálogo incluido **1.01: 1 servidor / 3 redes / 31 campos cifrados**.
  Remoto observado **6.45: 164 servidores / 2015 redes / 13267 campos**.
  Muestra previa 6.44: 164 / 2014 / 13260. Los tres JSON completos coinciden
  entre JCA, Python y worker, con `isPartial=false`. Los recuentos pueden variar.
- Nueva tarjeta, PNG del launcher, broker fijo y control individual
  `wolf-custom-vpn`; **51 tarjetas**. Los switches persistentes se conservan.
- `.wolf` moderno es un NetworkList exportado por `NetworkAdapter.v`, validado
  con fixtures JCA. Conserva fallback histórico y `.wolftunnel` anterior.
  C0 **240**, inventario efectivo **254**, overrides C8 **28**.
- **34 Python / 140 Node aprobadas**, sin skips. Prueba de caché 57 conservada
  y nueva prueba de actualización desde 58. Sin suite completa ni APK/CI nuevos.
- El catálogo lógico actual lo consumen V1/V2 por sus rutas existentes;
  esta integración no crea inventarios separados. Leer también
  `docs/cloud/CATALOGS_UPDATE_RUNBOOK.md` antes de hablar de un despliegue.

## Archivo duradero, independiente de la limpieza local

**`Wolf-Custom-VPN-2.8.1.2-build13.xapk`** está guardado en ChatGPT Library:
**`libfile_2db70a357b208191b86e7a7f93ed05de`**. La creación finalizó correctamente
y se aplicaron sus metadatos al archivo local. Contiene los cuatro APKs
originales: base, ARM64, idioma en y mdpi. Materializar por ese ID usando la
habilidad Library; no depender de que APKPure siga ofreciendo esta versión.

- XAPK: **59349423 bytes**, SHA-256
  `d82f07a06fb9b0e1e42e1b0010601c65697bd595057b6a323db5eec5ad59a58d`.
- Base APK: **30511568 bytes**, SHA-256
  `7511b35542ba6ab0f75bfc01808038d53d007a90cd5567c5133e748ae7c83660`.
- Firma SHA-256:
  `bd6515d3f58f73aa59ae99ae1d2aff74c4e2665c3bd677fbefea77222e88fc6b`.

La descarga que funcionó fue
`https://d.apkpure.com/b/XAPK/core.vpn3jx.xtreme?version=latest`; una URL net
devolvió primero 403 y la web mostró v1.10 antigua. El manifiesto binario del
archivo descargado confirmó v2.8.1.2 / 13. No sustituir esa evidencia por el
título de una página o un enlace con el nombre `latest`.

## Reconstrucción tras limpieza

1. Recuperar el HEAD actual de la rama con Goku y leer los documentos por app.
2. Materializar el XAPK guardado y verificar su SHA-256 antes de extraerlo.
3. Crear un entorno Python con `scripts/apk_analysis/requirements.txt`, las
   dependencias por app y un JDK. Extraer ambas bibliotecas ARM64 del split.
4. `decompile.py --install` recupera JADX con checksum. Su salida parcial no
   certifica el método: usar `dex_method.py` para las rutas originales y
   `paranoid_strings.py` para las cadenas LSParanoid. Este último resolvió
   6081 llamadas literales en 327 fuentes; esos volcados privados no van en Git.
5. Ejecutar `wolf_native_constants.py /ruta/lib/arm64-v8a`. Después,
   `wolf_verify.py /ruta/catalogo-cifrado --worker` compara el documento entero
   y todos los valores que autentican con ambas claves mediante JCA/Python y
   el worker real. Solo imprime hashes/recuentos, no configuraciones.
6. Usar las pruebas dirigidas documentadas en `TESTING.md`. El launcher original
   WebP y su PNG con los mismos píxeles están en Git; no es necesario redibujar.

El checkout parcial `spdecode/`, venv `jireh-venv/` y `investigation/wolf/` fueron
temporales. Sus catálogos, configuraciones y volcados privados son prescindibles
para recuperar el método; no adjuntarlos a Git ni exponer credenciales reales.
La herramienta, fixtures sintéticos, documentación y binario original duradero
son suficientes para continuar.

## Pendientes y autorización

Pendientes: `.wolf` real exportado en teléfono, ejecución de la app original,
conexión VPN y despliegue VPS. Las lecturas nativas y los vectores sintéticos
no certifican esos flujos. El transporte Node hacia el proveedor real no se
probó desde este entorno: se comprobaron sus controles con DNS/HTTPS simulados,
y la descarga real con Python. No afirmar que ya aparece en producción.

No fusionar `main`, desplegar, publicar APK/novedades, borrar `switches.json`
ni activar GitHub Actions automáticamente. Guardar cambios en commits
`[skip ci]` con lease del HEAD verificado. El usuario pidió persistencia para
continuar incluso si se agota su crédito o se borra el entorno temporal.
