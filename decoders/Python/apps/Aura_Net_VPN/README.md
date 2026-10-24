# Aura Net VPN — AuraNet_v9 (19)

Paquete `civ.snipher.v2ray`. Lector de archivos `.aura` y catálogo completo de
servidores y redes. No necesita contraseña del usuario, root, APK ni SO para
descifrar. Las constantes internas del formato no dependen del dispositivo.

## Catálogos reales comprobados el 24 de octubre de 2026

| Fuente | Versión | Servidores | Redes | Campos cifrados distintos |
|---|---|---|---|---|
| `assets/configfile.json` | 1.01 | 4 | 663 | 40 |
| GET fijo del actualizador Go | 2.18 | 14 | 685 | 424 |

Los dos documentos completos coinciden con la referencia independiente
libsodium/JDK y el worker aislado. Se conservan todas las secciones, campos
desconocidos, tipos, restricciones y registros. El catálogo remoto usa una
envoltura distinta del asset: ambos métodos y sus campos internos se abren
con autenticación GCM. No se devuelven campos cifrados rotos como éxito parcial.

## Script autónomo y Termux

`codec.py` es autocontenido y se puede copiar como `aura_net_vpn.py`. Requiere
Python 3.10+, `argon2-cffi` y `pycryptodome`; no importa el repositorio:

```sh
python -m pip install argon2-cffi pycryptodome
python aura_net_vpn.py
python aura_net_vpn.py --summary
python aura_net_vpn.py --input configfile.json --output incluido.json
python aura_net_vpn.py --stdin < remoto.enc > remoto.json
python aura_net_vpn.py --file perfil.aura --output perfil.json
```

Sin opciones descarga únicamente la fuente fija del APK, descifra todo y
guarda `aura_net_catalogo.json`. Usa archivos 0600 y rechaza sobrescrituras;
para repetir, indicar otro nombre con `--output`. Las fuentes locales no
descargan contenido. `--summary` emite solo recuentos de catálogo. La CLI
autónoma admite los métodos de AuraNet_v9; el wrapper del repositorio conserva
además las variantes históricas de Ultra/Sandok.

Se probó fuera del repositorio con las dependencias instaladas. Termux puede
necesitar su compilador y libffi para instalar dependencias C sin ruedas
precompiladas; no se certifica una ejecución Android/Termux real en esta entrega.

## Archivos y compatibilidad

El APK exporta `.aura` con `NetworkAdapter.u`: Gson → `Libv2ray.encrypt` →
archivo MediaStore, MIME `application/x-aura`. `ConfigFileParser` importa con
`parseConfig` (decrypt), con alternativa DO. No recibe una contraseña personal.
No se identificó un esquema propietario Aura ni un servicio de perfiles por
token; la app comparte un archivo y texto promocional. Los enlaces V2Ray
estándar no se registran como un formato propio nuevo.

`.aura` ya existía: se actualiza su ruta C8 y la delegación del bot, conservando
el lector histórico y sus claves. Una vez autenticado el exterior moderno,
un error del JSON o de un campo interno detiene la lectura y no entra al
fallback histórico. Las pruebas sintéticas conservan Unicode y restricciones;
**falta una exportación `.aura` real de este build y una prueba Android**.

## Integración

PR #99, rama `feat/mm-tunnel-1-10-11-1-decoders`, sobre APNA `a76add0`.
Proveedor `aura-net-vpn`, PNG original, broker HTTPS fijo y control individual
persistente; se respeta el interruptor global y los proveedores deshabilitados.
Catálogo mínimo **43 / 44 fichas**, C0 **240**, C8 **252**: `.aura` es una
ruta preexistente, no un sufijo añadido. El indicador offline del inventario
se conserva para la compatibilidad histórica; no se actualiza el lector
Android ni se anuncia compatibilidad offline nueva con este build.

Ver [ANALYSIS.md](ANALYSIS.md) y [TESTING.md](TESTING.md). Sin fusión,
despliegue VPS, publicación APK o C11. Los APK, SO, DEX y datos reales quedan
fuera de Git; se conservan herramientas y fixtures sintéticos reutilizables.
