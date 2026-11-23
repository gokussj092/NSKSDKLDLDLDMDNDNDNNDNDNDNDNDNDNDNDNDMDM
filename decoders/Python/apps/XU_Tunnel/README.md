# XU Tunnel 6.0 (com.technore.xrptunnelplus) — archivos `.xu`

Paquete `com.technore.xrptunnelplus`, versión 6.0, build 6.
**Solo archivos: no se integra el catálogo en vivo** (autorización de Pedro,
2026-11-23, condición FILES ONLY). El catálogo vivo v1.3.40 se descifró desde
el caché del teléfono, pero su descarga en vivo no es posible (token de
`deeptun.xyz` desconocido) y 39 valores quedan sin descifrar; no se cablea
broker, ni entrada C8 de catálogo, ni tarjeta, ni catálogo suministrado.

## Origen

- `.apks` `XU_TUNNEL_6.0_1_0yld.apks` (48,681,455 B, SHA-256
  `d017091a2a483cef512b35d696b0da22e707699f4ec35b973ac667f5aad419f1`).
- Framework NoobCrypt / NoobDev (fork de v2rayNG, `com.noobdev.vpn`).
  Misma familia y mismas claves de formato que XUI Tunnel 6.0.
- Dossier: `analysis/com.technore.xrptunnelplus/6/`.

## Método

Un archivo `.xu` es una línea de Base64 estándar:

```
Base64 → IV = primeros 16 B, ciphertext = resto
plaintext = AES-256-CBC descifrado, clave KEY_FIELD (32 B), PKCS#7
plaintext = "XU Tunnel VPN" + { JSON del perfil }   (sin separador)
```

- `KEY_FIELD` es la constante pública de formato de la app, recuperada de
  `libovpn3.so` (split arm64) y verificada byte a byte contra la entrada
  `"xui"` de `decoders/Python/_noobcrypt.py` del repo. **No es una
  credencial de cuenta.** Es la misma clave que abre los archivos `.xui`
  de XUI Tunnel 6.0; solo cambian el host y el token del catálogo.
- El descifrador acepta el prefijo `"XU Tunnel VPN"` o `"XU Tunnel"` y
  parsea el JSON desde el primer `{`. El prefijo exacto se infiere del
  hermano XUI Tunnel (que comprueba `startsWith(app_name)`); falta un
  `.xu` real para confirmarlo.
- Campos que aplica la app (misma familia que XUI): `ExpireDate` (ms epoch,
  0 = sin caducidad), `RootBlock`, `DeviceID`, `MobileData`, `PSInstall`,
  `isMsg`, `CFGMessage`, `NoobDev`, `SNIHost`, `Payload`, `ProxyHost`,
  `ProxyPort`, `useOvpnServer`, `useSshServer`, `serverDnsMode`,
  `TlSVersion`, `DNSHost`, `UDPhost`, `UDPobfs`, `UDPauth`, `UDPDownMbps`,
  `UDPUpMbps`, `isPassON`.
- La app no declara esquema URI propio: importa por `ACTION_VIEW`,
  esquemas `content`/`file`, `pathPattern .*\.xu`. No hay `xu://`.

## Uso

```bash
python xutunnel_archivos.py --file perfil.xu
python xutunnel_archivos.py --self-test
python xutunnel_archivos.py --file perfil.xu -o perfil.json
```

Solo biblioteca estándar (Python >= 3.10, sin APK en runtime). La API
offline es `decode(data: bytes) -> dict` y `run(data: bytes) -> str | None`
(JSON del perfil o `None`; nunca un dict parcial). Un archivo no válido
termina con código 1 y sin contenido parcial en stdout.

## Integración (solo archivos)

- Motor Cloud: entrada `"xu"` en `_C8_FILE_ENGINES`
  (`cloud/workers/python/engine.py`) → `decoders/Python/apps/XU_Tunnel/xutunnel_archivos.py`.
  La ruta suministrada (`FILE_ROUTES`, derivada de
  `supplied-integrations.json`) apunta al mismo módulo.
- Inventario público generado: `cloud/web/content/file-formats.json`
  (`offlineSupported: false`, `cloudSupported: true`, sin credenciales).
- Inventario suministrado: `cloud/web/content/supplied-integrations.json`,
  id `xu-tunnel`, `catalogState: FILE_ONLY`, `requests: []`, sin tarjeta
  en `cloud/web/lib/server-vpn-catalog.mjs` (patrón Hex Tunnel / Fx Tunnel).
- Icono original exacto: `cloud/web/public/server-vpn-icons/xu-tunnel.png`
  (PNG 500×500, 163622 bytes, SHA-256 `4b6db182…0d2e`, sin redibujar).
- No se toca nada bajo `android/` ni `decoders.json`, `switches.json`,
  `C0_FORMAT_MATRIX.csv`. Sin cambios en `text-formats.json` (no hay
  esquema de texto), sin broker, sin `catalog_vpn_bridge.py`.
- `CATALOG_VERSION` no se toca en este cambio (el coordinador lo sube
  una vez para todo el lote).

## Evidencia y límites

- Vector de prueba real en el módulo (`TEST_VECTOR`, construido con el
  método CBC verificado, IV 00..0f): descifra a `ExpireDate`
  1798761600000, `CFGMessage "Test config"`, `SNIHost "example.com"`.
  Verificado contra PyCryptodome en la construcción.
- **`.xu` es VERIFIED_SYNTHETIC**: round-trip con vector de prueba; falta
  un `.xu` real exportado por la app para VERIFIED_REAL y para confirmar
  el prefijo exacto del nombre de app.
- El catálogo en vivo (v1.3.40, 61 servidores, 708 tweaks) **NO** se
  integra: la descarga en vivo no es posible (token desconocido) y 39
  valores hex quedan sin descifrar (usuario/contraseña SSH de 17
  servidores + `DNSTTKey` de 5 servidores). El descifrador del catálogo
  (`xutunnel.py`) no forma parte de esta entrega.
- Pruebas: [TESTING.md](TESTING.md).
