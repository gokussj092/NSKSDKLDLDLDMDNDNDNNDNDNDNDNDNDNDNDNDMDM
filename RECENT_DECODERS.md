# Decodificadores Python recientes

Los scripts recientes se identifican por sus nombres en mayúsculas y se ejecutan como procesos Python independientes.

## Invocación

El bot usa `sys.executable`, que equivale al mismo Python con el que se inició el bot:

```bash
python decoders/Python/DARKTUNNEL.py "archivo.dark"
python decoders/Python/HTTPCUSTOM.py "archivo.hc"
python decoders/Python/HTTPINJECTOR.py "archivo.ehi"
python decoders/Python/HTTPINJECTORLITE.py "archivo.ehil"
python decoders/Python/NPVTUNNEL.py "archivo.npv4"
python decoders/Python/SSCCUSTOM.py "archivo.ssc"
```

Internamente `subprocess.run()` usa una lista de argumentos y `shell=False`. Las comillas del ejemplo son sintaxis de terminal; el bot transmite la ruta completa como un único argumento incluso cuando contiene espacios.

Cada script mantiene además `run(file_bytes)` para poder reutilizar el motor de descifrado desde Python.

## KSH VPN 1.3.2 — catálogo cifrado

`decoders/Python/ksh_vpn.py` decodifica el catálogo JSON `enc` de KSH VPN
mediante AES-256-GCM autenticado y conserva todas las configuraciones.
Admite archivos locales y descarga HTTPS explícita con `--url`.

```bash
python decoders/Python/ksh_vpn.py servers.json -o ksh_decoded.json
python decoders/Python/ksh_vpn.py --url -o ksh_decoded.json
```

Motor independiente, sin registrar una extensión `.ksh` no comprobada.
Véanse [formato, evidencia real y límites](docs/KSH_VPN_1_3_2.md).

## REESE TUNNEL 3.23.12 — archivos .RT

`decoders/Python/reese_tunnel.py` recupera el JSON completo `meta/config`
de exportaciones RSE5 C3/C4 y lectores históricos RSE1–RSE4, verificando
GCM y el HMAC exterior donde corresponde. La muestra `.RT` aportada se
validó como C4 ligado al certificado público del APK. Se preservan todos
los campos, perfiles V2Ray y banner.

```bash
python decoders/Python/reese_tunnel.py "Telkom unlimited v2ray.RT" -o reese_decoded.json
```

Opciones para credenciales originales: `--hwid`, `--ask-password`,
`--password-file` y `--signer-sha256`. No se identificó un catálogo remoto
VPN en las rutas revisadas de este APK.
[Formato, pruebas independientes y límites](docs/REESE_TUNNEL_3_23_12.md).

## FlexNet V2.3 B42 — v5 y catálogos

`decoders/Python/flexnet_b42.py` lee FLXCFG v5 offline y catálogos FBS1
integrados; puede procesar archivos online con una clave de contenido
legítima aportada y respuestas remotas con su clave RSA de petición.
La muestra `Free Host.flex` es v5 online y no se descifró sin la autorización
requerida. Se autenticó y recuperó el catálogo real de siete servidores.

```bash
python decoders/Python/flexnet_b42.py "Free Host.flex" --inspect
python decoders/Python/flexnet_b42.py "FlexNet V2.3 B42 (1).apk" --builtin-catalog -o flexnet_servers.json
```

El motor `flex.py` conserva v1–v4 y delega v5 al nuevo lector.
[Uso, formatos, evidencia y límites online](docs/FLEXNET_V2_3_B42.md).

## Flujo por decodificador

### decoders/Python/DARKTUNNEL.py

1. Lee el archivo completo como bytes.
2. Lo interpreta como texto UTF-8 y elimina un posible esquema `...://`.
3. Decodifica el contenedor Base64 y carga el JSON externo.
4. Descifra `encryptedLockedConfig` mediante AES-CFB.
5. Desempaqueta estructuras MessagePack.
6. Procesa el bloque interno cifrado y normaliza el resultado para JSON.
7. Imprime el resultado por `stdout`.

Dependencias relevantes: `pycryptodome` y `msgpack`.

### decoders/Python/HTTPCUSTOM.py

1. Lee el archivo completo como bytes.
2. Aplica la transformación XOR inicial usada por el formato.
3. Descifra el contenedor exterior mediante las claves ChaCha20 configuradas.
4. Detecta el formato antiguo o nuevo.
5. Deriva el nonce dinámico a partir de los metadatos de protección disponibles.
6. Descifra los tokens individuales y procesa credenciales SSH/proxy cuando corresponde.
7. Devuelve un JSON estructurado con `Protections` y `Config`.

Dependencia relevante: `pycryptodome`.

### decoders/Python/HTTPINJECTOR.py

1. Procesa únicamente HTTP Injector completo `.ehi`.
2. Extrae el payload de la estructura binaria.
3. Prueba los IV conocidos y procesa AES-CBC/XXTEA.
4. Para formatos modernos deriva Argon2id y verifica ChaCha20-Poly1305.
5. Devuelve los valores descifrados conservando el orden del JSON raíz.

Dependencias relevantes: `pycryptodome` y `argon2-cffi`.

### decoders/Python/HTTPINJECTORLITE.py

1. Procesa únicamente HTTP Injector Lite `.ehil`.
2. Valida la cabecera Lite y extrae su payload binario.
3. Prueba las claves y los IV exclusivos de HTTP Injector Lite 5.4.0.
4. Descifra sus dos capas AES-CBC y repara únicamente el primer bloque variable.
5. Abre los campos protegidos mediante XOR, hexadecimal y el alfabeto Base64 propio de Lite.
6. Devuelve los valores descifrados conservando el orden del JSON raíz.

Este script es independiente de `HTTPINJECTOR.py`; HTTP Injector Lite se trata como una variante separada y optimizada, no como el formato normal. Puede usar `cryptography` como alternativa cuando PyCryptodome no está disponible.

### decoders/Python/NPVTUNNEL.py

1. Lee el archivo completo como bytes y lo convierte a texto UTF-8.
2. Elimina las cabeceras `NPVTSUB1` o `NPVT1` cuando existen.
3. Separa el contenido por comas y toma el payload cifrado esperado.
4. Carga el estado white-box AES embebido en el propio script.
5. Genera el flujo de claves por bloques y aplica XOR al ciphertext.
6. Intenta interpretar el texto descifrado como JSON.

No necesita archivos externos para cargar el estado white-box porque está embebido en el script.

### decoders/Python/SSCCUSTOM.py

1. Lee el archivo como texto UTF-8.
2. Si comienza con `ssc://`, elimina el esquema e invierte el contenido restante.
3. Convierte el contenido hexadecimal a bytes.
4. Descifra la primera capa ChaCha20.
5. Detecta si existe una segunda capa y deriva su nonce.
6. Descifra campos internos mediante las claves y nonces correspondientes.
7. Traduce las claves abreviadas a nombres legibles y devuelve JSON.

Dependencia relevante: `pycryptodome`.

## Salida y códigos de retorno

- `0`: el archivo fue decodificado y el resultado se imprimió por `stdout`.
- `1`: el script se ejecutó, pero el contenido no pudo ser decodificado o ocurrió un error de descifrado.
- `2`: uso incorrecto de la CLI, archivo inexistente o error de lectura.

El bot captura `stdout` y `stderr` y conserva el código de retorno para informar errores correctamente.

## Maya Tunnel y XUI Tunnel

Ambas aplicaciones usan el contenedor nativo NoobCrypt actual:

1. Base64 exterior.
2. IV de 16 bytes al inicio.
3. AES-256-CBC.
4. PKCS#7.
5. Prefijo de aplicación seguido de un objeto JSON.
6. Descifrado recursivo de valores internos `Base64(nonce + ciphertext + tag)` mediante AES-256-GCM.

Cada aplicación conserva su propia clave y extensión: `.maya` y `.xui`. Un valor sólo se sustituye cuando la etiqueta GCM es válida, por lo que un Base64 normal no se confunde con contenido cifrado.

## SocksIP Tunnel

El método reproducido desde el APK suministrado usa Base64, AES-128-ECB, PKCS#7 y Java Object Serialization. El lector incluido valida límites, referencias, descriptores y tipos primitivos sin ejecutar objetos Java.

Las muestras aportadas contienen una segunda capa `VER7`. Se detecta como variante incompatible y no se interpreta como si fuera la serialización Java conocida. El APK completo 15.14.4 suministrado contiene tres DEX y la biblioteca nativa correspondiente, pero su ruta de importación no incluye `VER7`: después de AES-ECB entrega el resultado directamente a `ObjectInputStream`. Por tanto, hace falta otra variante del APK que realmente pueda importar esas muestras, o una exportación nueva creada por el APK recibido.
