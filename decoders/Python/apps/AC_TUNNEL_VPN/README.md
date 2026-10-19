# AC TUNNEL VPN 1.4

Paquete `com.boss.actunnelvpn`, versionCode **14**. Análisis del APK entregado,
con lectores separados para perfiles y catálogo, sin APK durante la ejecución.
Icono original `AC_TUNNEL_VPN.png`: 512×512, 188312 bytes, extraído de
`base.apk:res/o/cp.png`. Se conserva completo, conforme a la política general
de mantener el icono original aunque supere antiguos límites de peso.

## Uso

Python 3.10 o posterior y PyCryptodome:

```bash
python -m pip install -r requirements.txt
python file_decoder.py perfil.actun
python file_decoder.py < perfil.actun
python server_catalog_decoder.py > catalogo.json
python server_catalog_decoder.py actualizacion.js > catalogo.json
python server_catalog_decoder.py --stdin < actualizacion.rj
```

Sin argumentos, **el lector del catálogo descarga el catálogo remoto real e
imprime todo el JSON**. El lector de archivos usa stdin si se omite su ruta.
`run(data: bytes) -> str` es completamente offline en ambos módulos.

En el repositorio se reutilizan las primitivas de `decoders/Python/renz.py`,
sin modificar ese motor histórico. El ZIP descargable incluye una copia exacta
como `renz.py` junto a `codec.py` y los lectores; mantenerlos en la misma carpeta.
No hacen falta el APK, bibliotecas Android, Java, Unicorn ni claves personales.

## Métodos comprobados

| Entrada | Tratamiento |
| --- | --- |
| Perfil `.actun` | Texto `actunnelvpn://` seguido del sobre cifrado y JSON con campos protegidos |
| Texto `actunnelvpn://` | Mismo formato que el archivo exportado por la app |
| Catálogo remoto | GET a la URL fija original; sobre cifrado y listas completas `Servers`/`Networks` |
| Actualización `.js`/`.rj` | Copia del mismo catálogo; lectura offline, sin ejecutar JavaScript |
| Referencia `acvpn://` | Identificador Cloud cifrado; no contiene por sí solo el perfil |

Para inspeccionar únicamente el identificador de una referencia:

```bash
python file_decoder.py --reference referencia.txt
```

Este modo devuelve `kind: cloud_reference`, `reference` y
`profileDownloaded: false`. El APK resuelve estos identificadores mediante un
repositorio GitHub autenticado. El lector no incorpora credenciales de cuenta
incluidas en la aplicación ni automatiza esa descarga. No confundir el
identificador con un perfil recuperado. La descarga del catálogo fijo sí está
implementada y validada; es independiente de las referencias Cloud.

La app también importa OpenVPN/PKCS#12 estándar: no son otro formato propietario
cifrado y no se añade un lector específico para ellos.

## Cifrado confirmado en este APK

1. **Tipo 0, sobre y campos generales:** Base64 → AES-128-CBC/PKCS#7 → XXTEA
   personalizado → restar 2 a cada byte → UTF-8. La exportación suma 2 antes de
   XXTEA. Clave: primeros 16 bytes de SHA-256 de la semilla nativa; IV fijo.
2. **Tipo 1, hosts/payloads/V2Ray:** Base64 → Threefish-256 → AES-128-CBC/PKCS#7.
   HKDF-SHA256 deriva dos claves con sales de 16/32 bytes. El tweak Threefish es
   `[índice_de_bloque, 0]`. Se comprueban las dos longitudes posibles del relleno
   a 32 bytes para conservar ceros legítimos del criptograma AES.
3. **Tipo 2, usuario/contraseña:** Base64 → XXTEA → IV de 16 bytes +
   AES-256-CBC/PKCS#7. PBKDF2-HMAC-SHA256, 100000 iteraciones, sal de 32 bytes.
   Aquí se usa Base64 normal, no un alfabeto invisible.

XXTEA comparte la primitiva RENZ: delta `0x7a56d3e1` y `6 + 52/n` rondas, con
palabra de longitud final little-endian. Semilla, sal, IV, orden de operaciones
y consumidores Java se verificaron contra **este** APK, no se dedujeron del
nombre o de un catálogo histórico. Las primitivas ya existentes se reutilizan.

Se descifran solo los campos en ubicaciones comprobadas: registros de servidor
/perfil y objetos `ProxySettings`, `SlowDNS`, `V2Ray` y `UDPOptions`. Metadatos,
valores desconocidos, tipos, PIN, caducidad y bloqueos se conservan. No se
reinterpretan cadenas que parecen Base64 ni se convierte `CustomV2RAYConfig`
de texto a objeto.

## Catálogo y validación

URL fija original:

```text
https://rttunnelv2ray.xyz/api/files/app?json=7ef7a9a142eb1f77a56f
```

Observado el **19 de octubre de 2026**:

| Fuente | Servidores | Perfiles de red | Bytes cifrados |
| --- | ---: | ---: | ---: |
| Incluida en `res/aa/e.js` | 1 | 1 | 1516 |
| Descarga real | 24 | 1248 | 999168 |

La respuesta real declara `text/html`, pero su cuerpo es Base64 cifrado válido.
Se valida el contenido y su estructura; un cuerpo HTML real se rechaza. El
lector no mezcla la pequeña muestra del APK con la descarga ni limita listas.

Ambos JSON completos coinciden con un oráculo que ejecuta las primitivas ARM64
originales. El remoto contiene 6319 campos protegidos no vacíos comprobados:
4935 tipo 0, 1354 tipo 1 y 30 tipo 2. También se verifican las derivaciones y
vectores con OpenSSL independiente y la salida completa del subproceso Cloud.
Ver [TESTING.md](TESTING.md).

No se recibió un `.actun` exportado independientemente: la ruta de exportación
se comprobó en Java/desensamblado y con perfiles sintéticos cifrados mediante
las primitivas nativas. `exporterCertified` permanece `false`.

## Integración Cloud y límites

- Ruta C8 `.actun` para el prefijo real; los `.actun` históricos sin prefijo
  mantienen RENZ. `.actunnelvpn` y `actunnel://` conservan sus rutas anteriores.
- Textos `actunnelvpn://` con `Name` usan el lector actualizado. Los documentos
  genéricos históricos sin ese campo mantienen su resultado RENZ. Si falla un
  campo de un perfil moderno, no se entrega una salida parcial ni se reintenta
  con otro algoritmo.
- Proveedor fijo `ac-tunnel-vpn` en bridge, broker HTTPS, OpenAPI y catálogo
  público **versión mínima 7**; interruptor global desactivado por defecto.
- C0 conserva 240 extensiones y C8 246: `.actun` ya estaba registrada.
- El broker fija destino y consulta, valida DNS/IP pública, ancla la conexión y
  verifica TLS. La URL nunca se acepta desde la entrada del usuario.
- CLI: 8 MiB de entrada/salida, profundidad JSON máxima 64, descarga limitada a
  25 segundos, sin redirecciones ni compresión. Cloud mantiene sus presupuestos
  generales de 8 MiB cifrados/4 MiB de salida del catálogo.

Icono idéntico en esta carpeta y el backend. No se cambia Android ni el diseño
web. Mantener la actualización del cliente indicada en la guía antes de activar
catálogos con imágenes grandes. Trabajo en `feat/cloud-c8-vps-installer-updater`,
PR #94; sin fusión, despliegue ni publicación de APK.
