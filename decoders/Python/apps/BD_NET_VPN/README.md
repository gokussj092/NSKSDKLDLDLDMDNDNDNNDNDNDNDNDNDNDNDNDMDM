# BD NET VPN — PrinceBuild111 (111)

Paquete `dastan.prince.bdfreevpn`. Catálogo completo, archivos `.bdnet` y
enlaces `bdnet://`. Python 3.10+ con biblioteca estándar; sin root, APK,
bibliotecas nativas o contraseña criptográfica del usuario en producción.

## Catálogos comprobados el 24 de octubre de 2026

| Fuente | Versión | Servidores | Configuraciones | Campos cifrados distintos |
|---|---|---|---|---|
| `assets/gunny.json` del APK | 57 | 20 | 257 | 187 |
| Fuente remota literal del APK | 56 | 19 | 255 | 187 |

El remoto es **anterior al incluido**. Se muestran por separado y no se
mezclan ni se modifica su versión. Ambos documentos completos coinciden con
la referencia Java y el worker aislado, incluidos los campos internos.
Se conservan las 18 secciones originales, tipos, listas y valores.

Una carga de cada catálogo contiene bytes no textuales después de un NUL.
Su campo muestra el prefijo que consume JNI y `_spdecodeBinaryFields`
conserva la ruta JSON, hexadecimal original y **todos** los bytes XOR en
Base64. Los NUL y secuencias UTF válidas del resto de campos se conservan,
sin `errors=ignore`, caracteres perdidos o interpretación de identificadores
hexadecimales como contraseñas cifradas.

## Script autónomo / Termux

Copiar `codec.py` como `bd_net_vpn.py`. Solo necesita Python:

```sh
pkg install python
python bd_net_vpn.py
python bd_net_vpn.py --summary
python bd_net_vpn.py --output catalogo_otro.json
python bd_net_vpn.py --apks 'BD NET VPN_PrinceBuild111.apks' --output incluido.json
python bd_net_vpn.py --input gunny.json --output local.json
python bd_net_vpn.py --file perfil.bdnet --output perfil.json
python bd_net_vpn.py --text 'bdnet://HEX' --output texto.json
```

Sin opciones descarga la fuente fija y guarda `bd_net_catalogo.json`, modo
0600 y sin sobrescribir. `--stdin` acepta un catálogo cifrado; las fuentes
locales no acceden a la red. `--summary` solo emite recuentos de catálogo.
Se probó el script fuera del repositorio y con `python -S`, sin paquetes pip.
La ejecución real se probó en Linux; Android/Termux real sigue pendiente.

## Formatos y límites

Catálogo: Base64 → XXTEA modificado, delta `0x9E5729B1`, clave interna fija y
longitud final little-endian. Perfil/campos: hexadecimal → XOR fijo de doce
bytes → unidades UTF-16 JNI. El catálogo incluye secuencias de dos bytes
no canónicas que un decoder UTF-8 estricto no admite; el lector las contrasta
con `DataInputStream.readUTF` y no descarta sus caracteres.

La UI descifra el JSON antes de leer `tweak_password`: es una restricción de
importación, no una entrada al cifrado. Se conservan contraseña, HWID,
expiración y flags. No se identificó un cloud de perfiles por token.
El formato no tiene MAC; validación estructural no significa autenticación.

La app contiene LIAPP. Los helpers de catálogo, edición/importación de
tweaks, cadenas y XOR nativo bastan para estos lectores, sin recuperar ni
ejecutar todo el DEX protegido. Cinco vectores de la función ARM64 original
coinciden con el XOR independiente. **Falta una exportación `.bdnet` real
de este build y una prueba Android.**

## Integración

PR #99, rama `feat/mm-tunnel-1-10-11-1-decoders`, sobre Aura `5a5abe5`.
Tarjeta `bd-net-vpn`, PNG original, broker HTTPS fijo e interruptor individual
persistente. Catálogo mínimo **44 / 45 fichas**, C0 **240**, C8 **252**,
24 overrides: `.bdnet` ya existía. Se conserva la función C0 genérica y
los sufijos hermanos; el bot delega específicamente archivos/enlaces BD NET.
El flag offline preexistente corresponde al lector histórico Android y
no certifica esta versión con un lector Android nuevo.

Ver [ANALYSIS.md](ANALYSIS.md) y [TESTING.md](TESTING.md). Sin fusión,
despliegue, APK o novedades automáticas. Binarios y catálogos reales fuera
de Git; herramientas y pruebas sintéticas conservadas.
