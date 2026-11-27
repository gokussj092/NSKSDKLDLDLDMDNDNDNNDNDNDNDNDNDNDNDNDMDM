# ANALYSIS — ThaiVPN Connect 2.4 (`com.openvpnservice.thaivpnconnect`, code 24)

- **App:** ThaiVPN Connect 2.4 (versionCode 24)
- **APK analizado:** `ThaiVPN_Connect_2.4_0_nr7d.apks`
  (31,834,446 bytes); base.apk extraído, SHA-256
  `9c63e5736de4f5513ede5591575b8e3356e8d38d68d96296a119b78db78285b8`
  (10,585,924 bytes). El hash del bundle `.apks` original no se
  conservó: `null`, no inventado.
- **Fecha:** 2026-11-27
- **Alcance:** catálogo en vivo + archivo `profile.json`. Sin
  esquema de texto propio. Sin push, sin despliegue.
- **Veredicto: EL CATÁLOGO ABRE EN VIVO. `profile.json` es
  VERIFIED_SYNTHETIC** (round-trip con el catálogo en vivo; falta
  un archivo real exportado por la app).

> Primera vez que se decodifica esta app: búsqueda de
> `thaivpnconnect` en el repo = 0 resultados; `decoders.json` no
> contiene ningún `thai`. No confundir con `thailand.vpn.globalvpn`
> ni con Siam VPN (`siam.pro.net`): paquetes distintos.

## 1. Catálogo en vivo — XXTEA + Base64 interno

- **Observación:** `libapi-thaivpn.so` (4 KB, en el split arm64)
  expone 3 métodos JNI (`MainDetail.a/b/c`): `a()` = URL del
  catálogo, `b()` = la clave estática (ver `thaivpn.py`), `c()` = URL de ping
  (`https://thaivapp.my.id/kuay/ping.json`, lista de 8 hosts para
  checar servidores; no es el catálogo).
- **Descarga:** GET plano a `https://thaivapp.my.id/app/thvpn.json`,
  sin cabeceras ni auth (así lo hace `MainActivity.y()`). HTTP 200,
  un blob Base64 de una línea (~31,836 B; `Last-Modified: Wed, 25
  Nov 2026`).
- **Capa externa:** XXTEA (`Q0.f.o` / `Q0.f.q`, delta `772515655`),
  clave estática de `MainDetail.b()` (ver `thaivpn.py`),
  rellenada con ceros a 16 bytes → JSON con
  `Version`, `Message`, `Servers`, `Networks`, `setOpenVPN`.
- **Capa interna:** varios campos vienen en Base64 estándar (la
  app los decodifica en runtime con `H0.y.E`): servidores
  (`ServerIP`, `NameServer`, `ServerDNS`, `Username`, `Password`,
  `PublicKey`, `UDPConfig` (JSON), `setOpenVPN` (texto .ovpn),
  `V2Ray`); redes (`Sni`, `Payload`, `SquidProxy`, `ServerDNS`);
  nivel superior (`setOpenVPN`). El resto es texto plano.
- **Verificación:** `thaivpn.py --check-catalog` = OK, ningún valor
  codificado restante (revisión manual del JSON completo
  incluida). Catálogo v17.9, mensaje "🆙 LATEST UPDATE 21/09/2026":
  1 servidor gratis (`GENERAL 01`, `k2.thailandserver.my.id`,
  usuario/contraseña `freevpn` / `freevpn`), 0 premium; 24 redes
  (OVPN 13, SSH 11; HTTP Proxy 14, UDP Hysteria 4, SSL SNI 3,
  SlowDNS 3). `setOpenVPN` superior: config OpenVPN completa
  (6,140 B) con `remote 127.0.0.1 1194` como placeholder (la app
  lo sustituye por el servidor real en runtime).

## 2. Archivo `profile.json`

- **Observación:** la app escribe el mismo JSON cifrado
  (XXTEA + Base64) en su archivo privado `profile.json` tras cada
  actualización (`y.z` cifra, `j3/C1855a.a()` lee).
- **Verificación:** round-trip cifrado→descifrado idéntico con un
  `profile.json` generado desde el catálogo en vivo.
  **Pendiente:** confirmar con un `profile.json` real exportado
  desde la app instalada.
- **Decisión de ruteo:** el decoder NO se conecta a `engine.py`.
  El archivo se llama literalmente `profile.json` (sufijo
  `json`); registrar un motor `json` reclamaría todos los
  `.json` que importe un usuario. El motor no tiene dispatch por
  nombre de archivo. La ruta viva soportada es el catálogo; el
  file decoder se entrega para uso de operador/manual y para la
  verificación round-trip del expediente.

## 3. Texto

Sin esquema propio. La parte V2Ray (`V2RayConfigManager`) solo
maneja `vmess://`, `vless://`, `trojan://` y `ss://`, ya cubiertos
por los decodificadores genéricos. Nada que registrar.

## 4. Auditoría HMAC (sección 2.2 de la política)

| Ámbito | Estado | Evidencia |
|---|---|---|
| Archivo/catálogo | Ningún HMAC observado | El sobre es XXTEA + Base64; no hay MAC ni firma |
| Transporte VPN | No observado | No se trazó ningún handshake |
| Autenticación de conexión | NOT_OBSERVED | Las credenciales son usuario/contraseña y `auth_str` Hysteria del catálogo; no se intentó ningún login en vivo |

No se guardan claves de sesión, tokens ni credenciales reales en
este expediente.

## 5. Herramientas

jadx (DEX → `Q0.f.o`/`Q0.f.q`, `H0.y.E`, `MainActivity.y()`); las
librerías nativas viven todas en `split_config.arm64_v8a.apk`
(`libapi-thaivpn.so`, `libgojni.so`, `libv2ray.so`,
`libovpncli.so`, `libovpnudp.so`, `libdns.so`, `libtun2socks.so`,
`libpdnsd.so`, `libconscrypt_jni.so`). Solo biblioteca estándar
de Python 3.12 para el decoder. Detalle y comandos en
REPRODUCE.md.
