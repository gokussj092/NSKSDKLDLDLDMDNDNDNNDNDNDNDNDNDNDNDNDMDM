# 1FTunnel 0.7.1 (build 127)

Lector offline de perfiles y enlaces de `com.oneftunnel.app`, actualizado desde la
cobertura del repo (0.6.99, build 125). Sin catálogo: la app no descarga ninguna
lista de servidores.

```bash
python 1FTunnel.py --file perfil.1ftnl
python 1FTunnel.py --file perfil.1ftnl --password Ghost
cat perfil.1ftnl | python 1FTunnel.py --stdin
python 1FTunnel.py --url "1ftunnel://locked-v2/...." --password Ghost
python 1FTunnel.py --url https://ejemplo.test/perfil.txt
python 1FTunnel.py --self-test
python 1FTunnel_archivos.py perfil.1ftnl
```

Solo stdlib de Python 3.10+. Sin red salvo `--url` explícito.

## Qué cambió en 0.7.1 respecto al repo (0.6.99)

- La KDF nativa **no cambió**: verificada por emulación Unicorn de
  `liboneftunnel-security.so` — es byte a byte la misma que la del repo (mismo
  `ROOT_KEY`, mismas etiquetas v1/v2, slots 0 y 1).
- Novedad: documento `CFG1` **v6**, que añade la sección SlowDns (`hasSlowDns` +
  resolver/nameserver/publicKey + recordType). Los enums no cambiaron de orden
  (InjectMode añade `SLOWDNS=5` al final; los demás idénticos a 0.6.99,
  confirmados por el `<clinit>` de cada enum).
- El resto de formatos es el mismo que en 0.6.99.

## Formatos

- Contenedor binario `1FT1` v1-v3 + textos `1FTnl.` / `1FT1.` /
  `1ftunnel://1FTnl/` / `1ftunnel://1FT1/`: AES-256-GCM + HKDF-SHA256.
  Archivos `.1ftnl` (MIME `application/x-1ftunnel-config`).
- Documento `CFG1` v1-v6: ID, nombre, fechas, mensaje, máscara de campos, SSH,
  inyección, DNS, Xray y (v6) SlowDns.
- `1ftunnel://locked-v2/`: PBKDF2-HmacSHA1 (150.000 iters, 256 bits) +
  AES-256-GCM; el plaintext es el JSON de un TunnelConfig.
- `1ftunnel://locked/` (v1): AES-256-GCM con clave en Android Keystore del
  dispositivo que lo generó (no exportable). **No se puede abrir offline**: el
  script lo reporta como `DEVICE_KEY_REQUIRED`.
- `1FTlb.` / `1ftunnel://1FTlb/`: grupo de balanceo de carga, JSON
  `{"format": "1ftunnel-load-balance", "version": 1, "name": ...,
  "strategy": ..., "primary": "<texto 1FT1>", "secondary": "<texto 1FT1>"}`.
- Backup `1FTunnel-backup-*.json` (MIME `application/x-1ftunnel-backup`):
  `{"format": "1ftunnel-config-backup", "version": 1, "createdAt": ms,
  "entries": ["1FTnl....", ...]}` (máx. 2000).
- `1ftunnel://<base64url(JSON de TunnelConfig)>`: enlace JSON en claro.

## Sin catálogo (verificado)

Las únicas URLs en el APK son `https://api.ipify.org` (comprobador de IP
pública — verificado en vivo: devuelve solo la IP), `https://t.me/OneFTunnel`,
`https://t.me/Oneftnl` y `https://www.1forcrkuota.com` (tienda del autor).
No hay endpoint de catálogo que replicar; `--url` sirve para descargar un
enlace/texto 1FT1 publicado por el usuario, o acepta un enlace `1ftunnel://`
directo. Nunca se inventan servidores.

## Verificación

- `1FTunnel.py --self-test`: **12/12 OK** (1FT1 v6 con SlowDns, 1FT1 v3 sin
  SlowDns, locked-v2 con contraseña, LB con 2 entradas, backup con 2 entradas,
  enlace JSON en claro, y 5 casos negativos: sin contraseña, contraseña mala,
  locked v1, texto alterado, texto inválido). Los vectores son sintéticos de
  sal/nonce fijos, generados con la lógica del codec del repo + PyCryptodome y
  descifrados con el código stdlib del script (validación cruzada).
- `--file` (texto `.1ftnl` y binario `1FT1`), `--stdin`, `--url` http local y
  `--url 1ftunnel://locked-v2/` probados y funcionando.
- `1FTunnel_archivos.py --self-test`: 12/12 OK; `--file` y stdin probados con
  `.1ftnl` y backup JSON.

## Pendiente

Un `.1ftnl` real exportado por la 0.7.1 en un teléfono cerraría la verificación
extremo a extremo del `CFG1` v6 (la sección SlowDns está verificada contra la
estructura del APK y vectores sintéticos, pero no contra una exportación real
de esta versión). El repo ya verificó una muestra real en 0.6.99.
