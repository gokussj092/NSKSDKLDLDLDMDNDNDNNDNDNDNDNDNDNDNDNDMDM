# ANY VPN — 16kb-page-size (40)

Catálogo y archivos `.dtk` para `com.markvpnpro.pinas`, reutilizando el worker
aislado de SP-DECODE. No requiere contraseña del usuario, root ni una aplicación
Android instalada. Dependencia: Python 3 y PyCryptodome.

## Script autónomo para Termux

Copiar `codec.py` como `any_vpn.py`; no depende de otras carpetas del repositorio.

```bash
pkg install python clang make curl
pip install pycryptodome==3.23.0
curl -fL 'https://raw.githubusercontent.com/Gh0stDeveloper/SP-DECODE/feat/mm-tunnel-1-10-11-1-decoders/decoders/Python/apps/ANY_VPN/codec.py' -o any_vpn.py
python any_vpn.py -o servidores.json
python any_vpn.py --file perfil.dtk -o perfil.json
python any_vpn.py --catalog copia-cifrada.txt -o copia.json
```

Los archivos de salida deben ser nuevos: se crean con permiso 0600 y nunca se
sobrescriben. Ejecutar desde el HOME de Termux; el script no imprime el contenido
descifrado, solo ruta y conteos. El JSON contiene datos de la configuración y
se conserva localmente. `--catalog` también acepta una copia privada de
`Servers.js`, que la aplicación guarda en JSON con sus campos aún cifrados.

| Fuente real contrastada íntegramente | Versión | Servidores | Redes |
|---|---|---:|---:|
| Incluido en DEX, `c_11.conf` | 1.1 | 12 | 46 |
| GET oficial de `config_url` | 5.84 | 13 | 91 |

El origen principal **no es `assets/tk.js`**. `MainBaseActivity.getJSONObject`
abre el `Servers.js` descargado o el catálogo cifrado incluido en `c_11.conf`.
Se identificó y reprodujo la URL real que obtiene `ActivityUi.checkResources`
de `config_url`, después de AES y sus sustituciones de caracteres.

La CLI y el broker usan exclusivamente esa URL HTTPS fija y el User-Agent
`okhttp/5.0.0-alpha.12` incluido en este APK. La primera petición con el agente
Python fue 403; con el agente oficial, HTTP 200 y 118208 bytes. La URL histórica
`c_11.data_url` también respondió 403 y no se registra como fuente alternativa.
No se consultan APIs de login, caducidad, cuentas o congelación. No se acepta
una URL arbitraria del usuario ni de un catálogo descargado.

## Formato y contraseña

`UtilsKey.key=red1987`; `AESHelper` deriva SHA-256 UTF-8, usa AES-256-CBC,
IV cero, padding PKCS7 y Base64 estándar. La misma primitiva abre el exterior
y los campos conocidos de servidores, redes y metadatos. Se conservan todos
los perfiles, certificados en claro, DNS, indicadores y campos desconocidos;
un campo protegido inválido rechaza el documento entero. CBC no incluye MAC,
por lo que padding y estructura no equivalen a autenticidad criptográfica.

`FileUtilKt.writeToFile` escribe `.dtk` con el mismo cifrado. El importador abre
el exterior y procesa `server` / `network` como cadenas JSON. Para una salida
legible, el lector convierte esas cadenas en objetos JSON y abre sus campos.
No se pierde ningún otro dato del contenedor. No solicita contraseñas.

No hubo exportación real `.dtk` adjunta. Se verificaron dos contenedores
sintéticos completos, uno de red y otro combinado, con JDK y worker. El código
de `attemptExportServer` contiene una llamada a `encrypt` antes de construir
un JSONObject: se documenta como anomalía del exportador, sin corregir el APK
ni afirmar que la exportación de servidor funcione en un teléfono.

No se identificó un esquema propietario de exportación por texto ni cloud de
perfiles mediante token. El manifest solo registra esquemas `file` y `content`.
La descarga de actualizaciones de catálogo es independiente del login.

## Integración

ANY VPN y Speicers Pro se incorporan al catálogo público por la instrucción
posterior del usuario, sustituyendo la exclusión inicial de Speicers. Catálogo
mínimo **41 / 42 fichas**, iconos originales y control individual del panel,
sin reiniciar switches existentes. El formato `.dtk` aparece en los metadatos
remotos de archivos: C0 se mantiene en 240 y C8 sube a 251. Sin cambio de diseño
Android, APK, novedades C11, fusión ni despliegue automáticos.

Ver ANALYSIS.md y TESTING.md para evidencia, límites y recuperación.
