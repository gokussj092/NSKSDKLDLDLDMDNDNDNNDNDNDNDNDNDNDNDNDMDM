# Caso de diagnóstico: exportación Dark Tunnel renombrada a `.ar`

**Fecha de registro:** 2026-10-24.  
**Estado:** documentado; **sin corrección de código solicitada**.  
**Alcance:** clasificación de una muestra recibida de terceros; **no representa un fallo demostrado de SP-DECODE ni un nuevo formato de archivo**.

## Contexto

Se recibió para revisión una configuración compartida en un grupo con extensión
`.ar`. Al importarla en SP-DECODE, el archivo se dirigió al motor asociado a
esa extensión y no produjo el resultado esperado. Posteriormente, el propietario
aclaró que terceros habían **renombrado un archivo originalmente `.dark` a
`.ar`**, sin convertir su formato interno.

El contenido confirma la identificación como **Dark Tunnel**:

- Comienza con el esquema `darktunnel://`.
- Su capa de transporte es Base64 y contiene un objeto JSON exterior.
- El JSON incluye la propiedad `encryptedLockedConfig`, correspondiente a
  una variante protegida de Dark Tunnel.
- Que exista una capa exterior en Base64 **no significa** que todos sus campos
  estén en texto claro: esta variante también usa capas criptográficas internas.

La extensión `.ar` **sí existe como formato independiente** en la matriz
histórica de SP-DECODE (`AR Pro / MSY`) y tiene su propio decodificador,
`decoders/Python/ar_pro.py`. El motor de Dark Tunnel se encuentra en
`decoders/Python/DARKTUNNEL.py`.

## Diagnóstico correcto

**Causa de este caso:** extensión alterada por terceros, incompatible con la
identidad real del contenido. **No** es evidencia de que el formato legítimo
`.ar` esté roto, de que se necesite otro método criptográfico para `.ar` ni
de que Android necesite una nueva compilación.

El hecho de que el archivo concreto pueda abrirse con el método Dark Tunnel
no autoriza a tratar **todos** los `.ar` como `.dark`, ni a aplicar
descifrados alternativos entre familias distintas cuando falle una autenticación.

La observación se limita a esta muestra. Si en el futuro aparece un archivo
`.ar` exportado realmente por una aplicación AR Pro / MSY y falla con una
extensión original confirmada, ese caso deberá investigarse por separado.

## Procedimiento para incidencias similares

1. Confirmar la **aplicación exportadora**, versión y extensión original con
   la persona que creó el archivo; no asumir que el nombre compartido es fiable.
2. Inspeccionar solo la envoltura y la firma del contenido
   (esquema, encabezado, Base64/JSON y marcadores de formato), sin publicar
   configuraciones privadas ni credenciales.
3. Distinguir entre **archivo renombrado**, **método verdaderamente no
   soportado**, **archivo dañado** y **fallo operativo**.
4. Probar el decodificador propio de la familia confirmada en QA privada. No
   introducir rutas cruzadas ni fallback criptográfico indiscriminado.
5. Pedir una exportación original cuando se requiera reproducir el caso. No
   conservar muestras con servidores, usuarios o contraseñas en el repositorio.

## Decisión del propietario

- **NO** modificar `ar_pro.py`, `DARKTUNNEL.py`, los routers Python, el
  catálogo de extensiones, los detectores de texto, la API ni Android por
  este incidente.
- **NO** registrar el caso como defecto confirmado del decodificador `.ar`.
- **NO** incrementar `versionName`/`versionCode`, recompilar APK/AAB,
  desplegar al VPS ni anunciar soporte nuevo por este archivo.
- Dejar esta nota documental para evitar que la misma muestra renombrada
  provoque futuras integraciones incorrectas.

**Referencias del código:** `docs/cloud/C0_FORMAT_MATRIX.csv`,
`decoders/Python/ar_pro.py`, `decoders/Python/DARKTUNNEL.py` y
`docs/android/REAL_DECODER_PARITY_TRIAGE.md`.

> Esta nota no contiene el nombre de la configuración recibida, resultados
> descifrados, servidores, payloads, credenciales ni copias del archivo real.
