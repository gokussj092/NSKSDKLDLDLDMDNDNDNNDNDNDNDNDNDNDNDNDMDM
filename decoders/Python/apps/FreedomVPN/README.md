# FreedomVPN 1.0.29

Paquete `com.zfreevpn.dev`, build **125**. Lector de catálogo para el PR #96,
rama `feat/austroplus-vpn-13-0-1-decoders`.

Descarga HTTPS real autorizada: **147 servidores**, Version **4.4.88**, con
**1176 campos cifrados procesados**. El documento completo coincide con el
oracle Java independiente, la CLI real y el worker aislado. El catálogo inicial
también coincide completo: 1 servidor, Version 1.0.0. No son límites de registros.

## Uso

Python >=3.10 y `pip install -r requirements.txt`. Conservar `codec.py` y la
carpeta hermana `HTTP_FenixVPN`, con `codec.py` y `field_names.json`, para
validación, Base64, rotación Java y renderizado compartidos.

```bash
python server_catalog_decoder.py > catalogo.json
python server_catalog_decoder.py --download > catalogo.json
python server_catalog_decoder.py copia_cifrada.txt > copia.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt > copia.json
```

Fuente fija recuperada del updater:
`https://raw.githubusercontent.com/geko2023/shield/refs/heads/master/free`.
No se aceptan URLs del cliente ni redirecciones. Archivo/stdin y
`run(data: bytes) -> str` funcionan sin red. Se conserva todo el JSON, versiones,
notas, `password`, campos opacos, vacíos, tipos y registros sin filtrar o deduplicar.
Entrada/salida del lector: 8 MiB; worker y HTTP conservan sus presupuestos
generales. Un exceso o registro inválido falla sin devolver éxito parcial.

## Formato recuperado

- `Ri.i/h/a` abre Base64 con XXTEA de delta **-170877363**, palabras little-endian,
  longitud final y clave UTF-8 truncada/completada a 16 bytes. No usa el delta
  estándar de XXTEA. `Cf(22)` aporta la contraseña exterior.
- `CU.f` abre `ServerIP` mediante AES-128-ECB/PKCS7. `ServerUser` usa la misma
  variante XXTEA con otra clave.
- `P5.c` transforma pares de un alfabeto de símbolos en bytes Base64 y abre
  AES-256-CBC/PKCS7 con IV cero y SHA-256 del hexadecimal ASCII mayúsculo de
  la clave. Aplica a Payload, SNI, udpserver, udpobfs y v2rayJson, con sus
  claves respectivas. La forma almacenada de ServerPass también se abre con
  este sobre y la clave de udpobfs; todas sus variantes observadas validan
  padding/UTF-8 y coinciden con el JDK.
- Los ocho campos se exponen con la rotación Java `26 - 1`. ProxyIP, puertos,
  campos SlowDNS/UDP de control y banderas permanecen en su forma original.
  `v2rayJson` conserva su tipo string original.
- El cliente actual genera su credencial de conexión por usuario/hora UTC y
  datos del dispositivo mediante `V10.d`, sin consumir el ServerPass almacenado.
  Este lector muestra el dato almacenado; no fabrica la credencial dinámica.

Proveedor `freedom-vpn`, worker aislado, control administrativo e icono PNG
original incluidos. Catálogo público mínimo **21**, con 23 fichas. Se conserva
el PNG de compatibilidad del lanzador, `res/mipmap-xxxhdpi-v4/ic_launcher.png`,
192×192, sin reconstruir el XML adaptativo ni redimensionar. No se identificó
una fuente separada de usuarios en la ruta de actualización analizada.

Comprobaciones dirigidas, sin suites completas, según petición del usuario.
HTTPS/CLI reales por Python; transporte externo Node controlado. No se acredita
despliegue VPS, sesiones VPN o ejecución Android. Esta entrega añade el catálogo;
no registra una nueva extensión ni certifica archivos exportados. Los APK,
catálogos reales y perfiles descodificados quedan fuera de Git. Ver `TESTING.md`.
