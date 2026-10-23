# CREEB INJECTOR 38.0 (40)

Paquete exacto `com.creeb.Injector`; clases `com.creeb.injector`. Lector offline
de archivos **`.creeb`**, preparado para el backend del PR #96 y el bot.
Python 3.10+ y PyCryptodome; no requiere APK, Android, biblioteca nativa,
contraseña del usuario ni HWID en runtime.

```bash
python -m pip install -r decoders/Python/apps/CREEB_INJECTOR/requirements.txt
python decoders/Python/apps/CREEB_INJECTOR/file_decoder.py perfil.creeb
python decoders/Python/apps/CREEB_INJECTOR/file_decoder.py - < perfil.creeb
```

API: `file_decoder.run(data: bytes) -> str`, JSON completo sin red.

## Dos formatos del APK

- **Individual:** bytes DES-ECB/PKCS5 → XML Java Properties. Se devuelve
  `format`, `properties` (mapa de Java, última clave repetida prevalece),
  `entries` (todas las entradas en orden, incluso repetidas) y `raw_xml` exacto.
  Los valores de Properties siguen siendo cadenas; no se renombran claves ni
  se convierte a objeto un campo que contiene JSON o una configuración VPN.
- **Varios perfiles:** JSON UTF-8, `type:"creeb_profile_bundle"`, `version:1`,
  lista `profiles`. Se conserva íntegro, con `prefs`, `security`, mensaje,
  tipos y miembros desconocidos. Esta variante se exporta sin cifrado exterior.

No se añade un envoltorio Base64 ni se reutiliza el antiguo método `.crev`:
ese script histórico usa XXTEA y otros sufijos. Su ruta permanece intacta.
El token Cloud `CREEBINJ-...` es una referencia a un documento Firestore, no un
catálogo ni un archivo autocontenido; su descarga no forma parte de este lector.

## Contraseña y HWID

**No son necesarios para descifrar en esta versión.** El perfil individual
guarda `file.proteger`, `file.pedirLogin`, `file.passwordHash`, `blockHwid` y
`hwidstring` dentro del XML. La app abre el DES con una constante fija antes
de validar esas opciones. El bundle JSON contiene las mismas restricciones
en `security`; ya es legible antes del diálogo.

La app puede pedir la contraseña al **importar**, pero este lector no debe
pedirla para **leer** el archivo. Se conserva el hash almacenado; no se recupera
ni se calcula por fuerza bruta la contraseña original. Tampoco se cambia el
HWID ni se interpreta una caducidad como un error del cifrado. No se extrapola
esta conclusión a otras aplicaciones o versiones futuras.

## Catálogo

**No identificado en el APK analizado.** El único endpoint de `UpdateAsync`
consultado devuelve metadatos de actualización del APK (`newVersion`, `apkUrl`,
`versionNotes`), sin servidores. No se presenta como un catálogo ni se añade
una ficha/proveedor ficticio a Server VPN. Los perfiles locales del usuario
y las configuraciones Cloud referenciadas por token son funciones diferentes.

La integración añade `.creeb` a C8 y al bot: **250** rutas efectivas; C0 sigue
congelado en **240**. Server VPN conserva **35 / 37 fichas** y sus switches.
Sin cambios de diseño/Android, despliegue de VPS, fusión, APK o novedades C11.
La detección del nuevo sufijo en clientes anteriores queda para una futura
actualización del cliente.

Validación: **10 pruebas enfocadas** (9 del lector y una de registro),
**10 regresiones AboWaged**, cinco documentos sintéticos completos, tres DES
iguales a JDK y los cinco iguales al worker. **Pendiente una exportación real
`.creeb`**; no se certifica una importación real en un teléfono.

Ver [ANALYSIS.md](ANALYSIS.md), [TESTING.md](TESTING.md) y la recuperación en
[RESTORE.md](../../../../scripts/apk_analysis/RESTORE.md).
