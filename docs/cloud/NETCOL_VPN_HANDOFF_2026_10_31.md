# Netcol VPN: integración y recuperación persistente

Actualizado el 2026-10-31. Repo Goku
`gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`, rama
`fix/http-jireh-current-method`, después de Wolf `22f8da94`.

**Instrucción actual del propietario:** añadir `com.netcol.vpn` manteniendo
la revisión del catálogo **59**, porque aún no actualizó ese lote en el VPS.
El catálogo contiene **52 tarjetas**. No aumentar la constante en esta tarea,
no reiniciar switches ni modificar las rutas compartidas V1/V2.

## Estado y pruebas

- Netcol VPN **14.2 / build 142** confirmado por manifiesto binario y firma.
- Carpeta `decoders/Python/apps/Netcol_VPN/` con lector de catálogo, validación,
  dependencias, manifest y documentación de método/pruebas.
- URL activa recuperada de Firebase Remote Config `NEW_URL_UPDATE`:
  `https://raw.githubusercontent.com/jdavidag/setting/main/tO6oD1drTvL2.json`.
  HTTP 200 comprobado; el fallback `/jdavidag/update/main/Config` solo devuelve
  un byte vacío de contenido y **no se usa**.
- Sobre: alfabeto de 16 símbolos de bloques, Base64, AES-256-CBC/PKCS7,
  SHA256(hexadecimal UTF-8 mayúsculo de `FamiliaGelves24`), IV cero.
- Campos: seis Blowfish-CBC/PKCS5 con `UniversalPro24` y `ServerUser` con
  `LiamSebas18`; IV `abcdefgh`. ServerPass, tipos mixtos y claves desconocidas
  se conservan. Ver recetas y trazas exactas en el README por app.
- Cada uno de los dos assets idénticos: **0 / 2 servidores / 14 campos**.
  Remoto: **162 / 172 servidores / 1204 campos**. JSON completo igual a JCA,
  Python, CLI real y worker aislado; `isPartial=false`. Gateway completo 200
  con transporte interno simulado.
- **43 pruebas Python / 146 Node aprobadas**, sin skips. Incluyen regresiones
  Wolf, Jireh y JyFast. Ningún formato de archivo nuevo: 240/254 rutas, 28
  overrides C8. No se identificó exportación propia; no inventar `.netcol`.
- Tarjeta, icono y control individual `netcol-vpn`. Launcher WebP original
  conservado y PNG verificado con los mismos píxeles; no redibujar.

## Entrada duradera

Archivo guardado y finalizado correctamente en ChatGPT Library:
**`Netcol-VPN-14.2-build142.xapk`**, ID
**`libfile_e75eaf1858108191be9bc2e88a598ec2`**.

Contiene base, ARM64, en y mdpi. XAPK **55901014 bytes**, SHA-256
`f5ff0468b89c847916b5164f665e406afe2cfb3861e994c228df385f3bd9007a`.
Base APK **22102188 bytes**, SHA-256
`1f449d216199f5f6ebc55087e6e8cbe8248aafa3fe158e898d9abbc17d68dd7a`.
Firma SHA-1 `782749d51dc4c29b560d51b032b98490c287f988`.

Después de una limpieza, recuperar el checkout actual de la rama y materializar
ese archivo mediante Library. No depender de que la URL `latest` conserve el
mismo build. Extraer los APKs, confirmar hashes y recrear las dependencias con
`scripts/apk_analysis/requirements.txt` y las de esta app; usar JDK.

`netcol_source.py /ruta/base.apk --fetch` repite la consulta SDK pública con
identificador anónimo; no imprime API keys ni interpreta las otras entradas
de Firebase. Solo compara la fuente devuelta con la fijada, sin actualizar ni
redirigir el broker automáticamente. `netcol_verify.py /ruta/cifrado --worker`
compara todo el JSON mediante JCA/Python/worker e imprime únicamente métricas
y hashes. El oráculo y los vectores sintéticos están en `tests/golden/netcol*`.
Para revisar rutas originales se conservan `decompile.py` y `dex_method.py`.

Los directorios `investigation/netcol/`, el venv y el checkout parcial fueron
temporales. Los APKs, catálogos reales, respuesta completa Firebase y
credenciales descifradas **no van en Git**. El binario original duradero,
herramientas, documentación y vectores permiten reconstruir el análisis.

Pendientes: ejecución Android/conexión VPN, transporte Node real al proveedor
y despliegue VPS. No se certifica exportador ni un formato propio no observado.
Sin suite completa, compilación Android, merge a `main`, despliegue ni nuevas
ejecuciones de GitHub Actions. Usar commits `[skip ci]` y lease del HEAD.
