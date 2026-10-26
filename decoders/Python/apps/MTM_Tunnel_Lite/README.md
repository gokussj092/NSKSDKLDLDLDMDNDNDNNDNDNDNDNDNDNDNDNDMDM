# MTM Tunnel Lite MTM (40)

Paquete `com.mtmtunnel.lite`. Lector completo del catálogo incluido,
actualizador online y archivos de actualización cifrados `.json` / `.v2`.
Conserva todas las listas, credenciales, payloads y campos desconocidos.
Python 3.10+, biblioteca estándar; no requiere contraseña personal ni HWID.

## Termux

Descargar `mtm_tunnel_lite.py` y ejecutarlo en la carpeta donde se guardó:

```sh
pkg install python
python mtm_tunnel_lite.py
python mtm_tunnel_lite.py actualizacion.v2 -o resultado.json
python mtm_tunnel_lite.py actualizacion.json -o resultado_local.json
python mtm_tunnel_lite.py - --stdout
```

Sin argumentos descarga exclusivamente el actualizador fijo del APK y guarda
`mtm_catalogo.json`. `-` recibe el catálogo cifrado por stdin, útil para texto
pegado. Los archivos de salida se crean con permisos 0600 y nunca se
sobrescriben. `--stdout` muestra el documento completo, incluidas credenciales.
El script no exporta perfiles para reimportarlos en MTM.

## Integración

- Server VPN: ficha `mtm-tunnel-lite`, PNG original y switch persistente.
  Descarga autenticada a través del broker existente; worker sin red.
- C8 / bot: `.v2` prueba primero el catálogo MTM; si no abre ese cifrado,
  conserva el lector histórico e-V2Ray. Un catálogo abierto pero inválido falla.
- `.json` se lee en la CLI explícita; no se registra el sufijo genérico en el
  menú global. No se inventan `.mtm`, `.mtl` ni esquemas `mtm://`.
- El indicador offline de `.v2` describe el lector Android e-V2Ray que ya
  existía. **MTM requiere Cloud o este script**, sin nuevo lector Android nativo.
- No se identificó un formato propio de clipboard ni importación online por
  clave/enlace individual equivalente a HTTP Injector Cloud. El actualizador
  de catálogo es la función online verificada; `vmess://` sigue la ruta común.

Catálogos reales íntegros: asset 35.55 (29 servidores / 471 payloads), remoto
37.63 (27 / 479). Ambos comparados con JDK y worker. Falta un archivo `.v2`
exportado por un usuario y ejecución en Termux/Android físicos. Véanse
[ANALYSIS.md](ANALYSIS.md) y [TESTING.md](TESTING.md).

El bundle autónomo se genera desde el algoritmo canónico de HX, con clave
explícita y sin modificar los defaults compartidos:

```sh
python scripts/apk_analysis/mtm_bundle.py /tmp/mtm_tunnel_lite.py
```
