# Reproducción de la recepción

Desde raíz del repositorio, con Python 3.12.14 / curl 8.5.0. Mantener proxy y
verificación TLS normales. No se ejecutó la APK ni se usaron credenciales.

Petición original ejecutada:

```sh
curl -sS -L --fail --max-time 60 -o private/hexcustom/mediafire.html 'https://www.mediafire.com/file/ypaiywpzrvslef1/Hex+Custom.apk/file'
```

Dos GET urllib posteriores al enlace canónico y API pública get_info están
conservados como URLs fijas en tools/probe_mediafire.py. User-Agent usado:
Mozilla/5.0. Las respuestas se guardaron como canonical.response y
public-info.response. Ambos HTTP 200 / text/html / 195 bytes; no contenían enlace de APK.

Receta actual ejecutada para importar esas tres observaciones conservadas:

```sh
python analysis/_intake/mediafire-ypaiywpzrvslef1/tools/probe_mediafire.py private/hexcustom analysis/_intake/mediafire-ypaiywpzrvslef1/generated/access.json --existing
```

Omitir --existing permite repetir exactamente los tres destinos públicos,
sin cambiar ruta de red ni introducir una ubicación arbitraria. La detección
ZIP/AndroidManifest es solo un candidato de contenedor, no valida firmas,
identidad ni métodos. Las tres entradas HTML actuales se rechazan como APK.

Comprobación independiente de UI: navegación directa al enlace original en
Chrome cloud, AX: título Site Unavailable; texto Unable to access this site.
Sin CAPTCHA, login o advertencia identificados; no se afirma su causa técnica.

Se consultaron README/ANALYSIS y hex_custom_recover.py históricos en Git como
referencia, pero no se ejecutó su receta ni se reutilizó un binario anterior
para sustituir el enlace solicitado. Primero se necesita la APK exacta.
