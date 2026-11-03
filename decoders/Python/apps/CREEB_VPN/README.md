# Revisión vigente50.0/build50 — 2026-11-01

Versión50.0 reconfirmada en HTML vivo de Play; el original privado recuperado
coincide en todos sus hashes con el ya analizado. **Remoto todavía pendiente.**
Se recuperó el paso omitido: GET JSON digest/bypassActive previo al POST con
Play Integrity y nonce. Hoy ese GET devuelve HTML200/195 y el POST de fallo
sin token devuelve HTML405/163. Falta ensayar el POST original con un token
válido y su nonce/diagnostics reales; no se deduce que ese POST también falle.

El script `scripts/apk_analysis/creeb_vpn_remote_probe.py` ejecuta la secuencia,
acepta una solicitud original fresca desde archivo0600 y valida todo el
catálogo antes de escribir JSON. Conserva valores privados fuera de Git; no
fabrica atestaciones ni reusa automáticamente tokens. La prueba real actual
termina exit1/catalogValid:false, sin archivo JSON remoto.
Incluido1.0.0/1 servidor/1 tweak otra vez igual a JDK/CLI/worker; **esto no
completa la descarga remota**.26 Python correctas. Sin broker habilitado,
fusión, despliegue, APK ni C11. [Flujo, hashes y límites](ANALYSIS.md).

---

# CREEB VPN 50.0 (50)

Paquete `com.creebtunnel.vpn`. Lector offline de archivos `.crev` y catálogo
`assets/data.creeb`. Es distinto de **CREEB INJECTOR 38.0**, cuyo `.creeb`
exportado usa DES/XML o JSON de perfiles. El nombre del asset no registra
`.creeb` como archivo de CREEB VPN.

Usa XXTEA modificado (`delta=-1703701580`), Base64 estándar y JSON. Se reutiliza
la primitiva de `decoders/Python/crev.py`, incorporando la clave de servidores
y la selección exacta de clave por `pInfo` que faltaban en el lector antiguo.
Se conservan todas las secciones, filas, metadatos y campos desconocidos.
No depende de Android, APK, JNI o acceso de red durante el descifrado.

## Uso

Desde un checkout completo, instalar `requirements.txt` de esta carpeta:

```bash
python decoders/Python/apps/CREEB_VPN/file_decoder.py /ruta/config.crev > /ruta/resultado.json
python decoders/Python/apps/CREEB_VPN/server_catalog_decoder.py /ruta/data.creeb > /ruta/catalogo.json
```

Ambos aceptan `-` para stdin y exponen `run(data: bytes) -> str`. Devuelven el
JSON íntegro o un error; no generan resultados parciales silenciosos. El
importador también admite JSON directo con los campos internos aún cifrados.
No se detectan/enumeran servidores arbitrarios ni se interpretan enlaces cloud
`CREEBVPN-...` como archivos: estos son referencias de Firestore, sin muestra.

## Contraseña, dispositivo y catálogo

No se pide contraseña externa, public key ni ID del dispositivo. `Security`
se obtiene con la clave fija antes de validar PasswordProtect, DeviceIDLock,
caducidad y otras restricciones de importación. Esos valores se conservan
como datos; no participan en XXTEA. `Slowchave` es configuración del túnel.

Catálogo **incluido** comprobado: versión **1.0.0**, **1 servidor / 1 ajuste**,
con igualdad de todo el JSON frente a JDK, CLI y worker. Los datos reales no se
publican; pueden extraerse de la copia del APKS con las herramientas guardadas.

La app intenta actualizar mediante Play Integrity. El endpoint fijo no entregó
un catálogo aquí (GET: HTML «Site Unavailable»; POST sin token: HTTP 405 HTML).
Esto no demuestra que el servidor haya rechazado una atestación. **Descarga
remota pendiente**, tarjeta con icono y `remote:null`, siempre desactivada.
No hay tokens inventados ni cambios para eludir Play Integrity.

El icono launcher es VectorDrawable; se conserva el recurso original compilado
y su PNG 512×512 renderizado a partir de las 756 rutas originales. No se cambió
la marca; el antialiasing de Cairo puede diferir del de Android.

C8/bot enrutan `.crev` a esta receta. C0 sigue congelado y `.cer`/`.cerv`
conservan su lector histórico. `.creeb` mantiene su lector CREEB INJECTOR.
Sin despliegue, fusión, cambios de diseño Android ni anuncios C11.
Ver `ANALYSIS.md`, `TESTING.md` y `scripts/apk_analysis/RESTORE.md`.
