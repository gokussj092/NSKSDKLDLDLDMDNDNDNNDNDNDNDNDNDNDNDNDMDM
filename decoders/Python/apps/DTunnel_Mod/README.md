# DTunnel Mod / Fastiver Vpn Pro 4.2.5 — catálogo y enlaces vpn://

- Paquete: `com.dtunnel.v2ray.pro`, app label "Fastiver Vpn Pro", versión **4.2.5**,
  versionCode 9, minSdk 21.
- APK proporcionado por Pedro (archivo `dtunnelmod_5.apk`, 26.247.089 B, SHA-256
  `6d0afdc3ad02873cb146b4995bab9c8ba1f25dbfd86f711ad59d2cff0eba64c4`).
- **El repo SP-DECODE ya cubría esta app y esta misma versión**
  (`decoders/Python/apps/DTunnel_Mod/dtunnelmod.py`, con documento
  `docs/DTUNNELMOD_4_2_5.md`): el SHA-256 del APK es byte-idéntico al del
  documento del repo. Este trabajo verifica esa cobertura contra el APK
  entregado y contra el servicio en vivo hoy, y la reescribe en stdlib puro
  con el formato de tanda (sin PyCryptodome).
- Librerías nativas (ambos ABI dentro del APK único): libdtunnel.so,
  libjbcrypto.so, libengine.so, libLight.so, libgojni.so, libopenvpn.so,
  libovpnutil.so, libopvpnutil.so, libovpnexec.so, libpdnsd.so,
  libtun2socks.so, libtun2socks5.so. 1 dex. La URL y la semilla del catálogo
  NO aparecen en claro en el DEX ni en las .so (cadenas ofuscadas; el método
  se recuperó del `libLight.so` nativo en el análisis del repo); la
  verificación aquí es de extremo a extremo en vivo.

## Catálogo en vivo — OK (verificado 2026-11-14)

Petición exacta (igual que la app):

```text
GET https://dtmod.cloud/api/dtunnelmod
User-Agent: DTunnelMod (@DTunnelMod, @DTunnelModGroup, @LightXVD)
dtunnel-token: <user_id de assets/credentials.json>
dtunnel-update: app_config
```

- Cuerpo: una línea Base64, **80.600 B**, SHA-256
  `184829b561546c560390ff2e2c318d7e3d381812413a1d9a63985fda2f90b03c`.
- Cifrado: Base64 → **AES-256-CBC, key = SHA-256(semilla), IV 16 ceros**,
  PKCS#7. La semilla es una constante de formato embebida en el cliente
  (ver DTunnel.py); no es `user_id` ni `token` de una cuenta. El formato no
  tiene MAC: un padding y JSON válidos no prueban integridad.
- **Resultado en vivo: 49 perfiles, los 49 ACTIVE, los 49 con payload.**
  El catálogo no tiene campo de versión: es una lista plana de perfiles
  (22 campos cada uno: category, mode, name, server, proxy, auth, dns_server,
  config_payload, config_openvpn, config_v2ray, udp_ports, etc.).
  - Categorías: SERVIDOR VIP 28, MULTIPAIS📱🇦🇷🇲🇽🇨🇴🇨🇱🇧🇯🇪🇨 15,
    SERVIDOR PÚBLICO GRATIS 6.
  - Modos: SSH_PROXY 16, SSL_DIRECT 16, SSL_PROXY 9, SSH_DIRECT 8.
  - config_openvpn y config_v2ray: 0 de 49 (todos usan payload SSH/SSL).
- Comparación con la validación del repo (18 oct 2026): entonces eran 46
  perfiles; hoy son 49. El método sigue vigente.
- Otras dos actualizaciones, mismo cifrado, también verificadas en vivo hoy:
  `--kind layout` → 37 ajustes de interfaz; `--kind texts` → 108 textos.
- Verificación cruzada: mi script en stdlib puro reproduce **byte a byte el
  mismo JSON** que el script del repo (PyCryptodome) sobre la respuesta viva
  guardada (`catalog_sample.b64`).

## Archivos y enlaces propios

- **No hay formato propio de archivo exportable.** La app no exporta ni
  importa archivos de configuración; el catálogo vive en una base Room
  interna (`dt_app_config.db`), que es un contenedor interno, no una
  exportación de usuario.
- **`vpn://`** — enlace de texto: Base64 estándar de un objeto JSON UTF-8
  con el perfil completo, sin cifrar. Es el formato que la app importa al
  pegar el enlace. Decodificado por `DTunnel.py --link` y por
  `DTunnel_archivos.py`.
- **`http(s)://dt.com.br/import/<...>`** — deep link declarado en el
  manifiesto (MainActivity, VIEW + BROWSABLE). Su carga útil **no está
  verificada**: el host no responde desde aquí y no hay una muestra real.
  `DTunnel_archivos.py` intenta descifrar el segmento como Base64 de JSON
  (o como `vpn://` embebido) y reporta `IMPORT_URL_UNVERIFIED` si no es eso,
  en lugar de inventar un perfil.
- Sin `.sks` ni otro esquema propio.

## Archivos

- `DTunnel.py` — stdlib puro. `decode()` + `run()` + CLI `--url/--file/--stdin/
  --link/--self-test/-o` y `--kind catalog|layout|texts`. `--self-test` 9/9
  OK (vectores FIPS-197 AES-256, round-trip CBC con la clave del catálogo,
  round-trip `vpn://`, rechazos honestos). `--url` usa ahora el identificador
  suministrado y autorizado expresamente por el propietario el 2026-11-14.
  `--credentials-file` y `--request-id-file` siguen disponibles como overrides.
- `DTunnel_archivos.py` — enlaces `vpn://`, deep links `dt.com.br/import/`,
  respuestas cifradas guardadas y JSON en claro. `--self-test` 9/9 OK,
  incluido el catálogo vivo real de 49 perfiles.
- `DTunnel.png` — 512×512, del `ic_launcher.png` del APK (1206×1206).
- `catalog_sample.b64` — cuerpo vivo 2026-11-14 (80.600 B).
- `catalog_sample.json` — catálogo descifrado (49 perfiles).
- Trabajo en `work/` (respuesta viva, layout/texts vivos, credentials.json
  del APK — solo para la prueba en vivo, no se distribuye).

## Pendiente

El valor integrado se publica en el repositorio público por autorización
expresa del propietario. No se incorpora al catálogo público ni a la APK.
La descarga con ese valor y el worker aislado fue verificada: HTTP 200,
80.600 bytes y 49 perfiles completos. Evidencia sanitizada:
`analysis/com.dtunnel.v2ray.pro/9/generated/authorized-catalog-proof.json`.

Un enlace `vpn://` real copiado de la app cerraría la verificación extremo a
extremo del importador (el formato está validado contra el código de la app
y por round-trip, pero sin muestra real de un perfil exportado). Lo mismo
para la carga útil de un enlace `dt.com.br/import/` real.
