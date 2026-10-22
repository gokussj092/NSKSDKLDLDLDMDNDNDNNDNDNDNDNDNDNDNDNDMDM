# RJC TUNNEL PRO RJC-6

Paquete `com.rjct.pro`, build 6. Catálogo completo registrado en Cloud como
`rjc-tunnel-pro`, con fuente HTTPS fija, control administrativo e icono original.
Python 3.10+, biblioteca estándar; no requiere APK ni librerías nativas al ejecutar.

```bash
python server_catalog_decoder.py --download > catalogo.json
python server_catalog_decoder.py copia-cifrada > catalogo.json
python server_catalog_decoder.py --stdin < copia-cifrada > catalogo.json
```

Sin argumentos descarga la misma fuente fija. `run(data: bytes) -> str` trabaja
offline; stdout contiene el documento completo y los errores van a stderr con
código 1. Entrada/salida limitadas a 8 MiB; no hay límite de registros ni filtros
por protocolo, país o visibilidad en la interfaz.

Fuente recuperada de `OpenVPNClient` y las constantes LSParanoid:
`https://raw.githubusercontent.com/pipoyrichards/RJCPRO/refs/heads/main/FEBRUARY`.
La descarga valida TLS, rechaza redirecciones/HTML y aplica timeout y límite de
bytes. El broker Cloud conserva el control de DNS/IP y no acepta URL arbitraria.

`AbstractC0015Mm.a/b/f/g` y `HJ.e` confirman la misma receta que Mx Tunnel PRO:
Base64 estándar, XXTEA con delta `-1638454863` / `0x9e5729b1`, clave de formato
`...|...` truncada/rellenada a 16 bytes, palabras little-endian y tráiler de
longitud. Se reutiliza su motor sin duplicar ni modificar la criptografía.
Conservar `codec.py`, `../Mx_Tunnel_PRO/codec.py` y
`../HX_Tunnel_VPN/HX_Tunnel_VPN.py` al copiar fuera del repositorio.

Los consumidores leen directamente los campos JSON internos. Se devuelve todo
el objeto: `Version`, `Changelogs`, `Username`, `Password`, `Free_servers`,
`Premium_servers`, `Vip_servers`, `Private_servers`, `Payloads`, propiedades
desconocidas, vacíos, tipos y duplicados. Los ajustes privados del teléfono no
se mezclan con la descarga. No se inventan credenciales de sesión Android.

Descarga real autorizada del **2026-10-22**: HTTP 200, versión **22.4**,
**41 servidores y 1253 payloads**. El asset `gremlin.json` contiene versión
**15.1**, **46 servidores y 1205 payloads**. Ambos documentos completos coinciden
con JDK independiente, CLI y worker aislado sin salida parcial. Son recuentos
observados, no límites. Las listas Premium/Vip/Private vacías se conservan.

PNG original exacto de `res/drawable/ic_app_icon.png`, 512×512. Integración de
catálogo; no se certifica un formato de perfil exportado sin muestra validada.
La API de acceso de la app no se presenta como otro catálogo de usuarios.
Ver [TESTING.md](TESTING.md) y [manifest.json](manifest.json).
