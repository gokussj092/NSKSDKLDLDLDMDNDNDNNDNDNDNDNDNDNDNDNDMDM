# DeepTune-VPN — archivos y catálogo

App: DeepTune-VPN, paquete `tun.deep.vpn`, versionCode 8,
versionName `v8` (verificado con androguard 4.1.4 sobre el
`base.apk` extraído del `.apks`). APK `DeepTune-VPN_v8.apks`,
SHA-256
`64c44faf28607e80c6e1214129ee1b0368f0657e98fd5d83700d6531c9031e91`.

## Catálogo en vivo

- Descarga: `GET https://strongteam.co/api/deeptune/deep3.txt`,
  cabecera `User-Agent: DeepTune-VPN`. Se descarta el byte en el
  índice 3 del texto y se descifra.
- Cifrado (extraído del APK v8, `libgojni.so` — AndroidLibXrayLite):
  Base64(`salt[0:16] || nonce[16:28] || ciphertext[28:]`),
  Argon2id (t=3, m=8192 KiB, p=1, keyLen=32) + AES-256-GCM,
  AAD = salt. Los campos dentro del JSON usan la misma construcción.
  Si un valor no descifra con ninguna contraseña, es texto plano y se
  deja como está (igual que la app).
- El JSON de resultado lleva SOLO los datos del catálogo, todo
  descifrado; NUNCA incluye las URLs/endpoints de descarga (regla del
  propietario, 2026-11-15). Las URLs y las contraseñas viven solo en
  los scripts operativos y en el registro supplied.

## Uso

```sh
python deeptune_vpn_catalog.py [-o catalogo.json]
python deeptune_vpn.py <configfile.json|deep3.txt|json-descifrado> [-o salida.json]
```

Requiere: `argon2-cffi`, `cryptography`, `requests` (la descarga usa
`requests` si está disponible — la respuesta se trunca con `urllib`
detrás de Cloudflare — con respaldo a `urllib`; reintenta hasta 3
veces por transporte si el descifrado falla).

## Archivos

DeepTune-VPN **no tiene extensión de archivo propia ni esquema de
enlace propio**. Lo que decodifica `deeptune_vpn.py`:

- `configfile.json` del APK (activo en la app): Base64 cifrado con la
  contraseña de campos.
- `deep3.txt` descargado (catálogo en vivo): se descarta el byte en
  el índice 3, contraseña de archivo.
- Un JSON ya descifrado: solo descifra los campos que sigan cifrados.

La app también importa enlaces estándar VLESS/VMess/trojan/ss y JSON
de configuración Sandok; esos ya los decodifica SP-DECODE y no
necesitan este script.

## Probado (2026-11-17, re-corrida en vivo)

- Catálogo en vivo: **v3.12, 6 servidores, 102 redes** (la muestra
  entregada era v3.11, 6 servidores, 101 redes: la única diferencia
  es la versión y UNA red nueva; los 6 servidores son idénticos
  campo a campo). Descarga + descifrado completos en **17,6 s** en
  esta VM (dentro del tope de 120 s del catálogo).
- Asset empaquetado: `work/bundled.json` (configfile del APK) abre
  con `deeptune_vpn.py` → **v1.01, 9 servidores, 111 redes** en 5,1 s.
- `py_compile` de ambos scripts: OK. Los scripts no traen
  `--self-test`; la verificación es la re-corrida en vivo + el asset
  empaquetado (ver expediente).

## Limitación conocida: valores que NO descifran del todo

El catálogo en vivo v3.12 se entrega con valores que quedan cifrados
en el resultado (tal cual, sin inventar nada):

- **12 valores de campo no abren con ninguna de las dos
  contraseñas**: `SlowDNSHost` ×3, `SlowDNSKey` ×6 y `V2rayUUID` ×3
  (los 9 de los 3 servidores OVPN/SSH — `Global Server Online--01`,
  `--02` y `-- SSH` — más `SlowDNSKey` en los otros 3 servidores).
  Son 2 valores cifrados compartidos distintos para `SlowDNSKey`.
- **48 valores SÍ descifran con las contraseñas existentes pero el
  script no los intenta** (no están en sus listas de campos):
  `ServerIPHost`, `UDP_obfs`, `UDP_user`, `H2pass` en los 6
  servidores (24 valores) y `BugDNS` en 24 de las 102 redes (todos
  descifran a `8.8.8.8`). Es una laguna de la lista de campos del
  script, no un fallo criptográfico. **El coordinador 2026-11-17 SÍ amplió las listas** (`ServerIPHost`, `UDP_obfs`, `UDP_user`, `H2pass`, `BugDNS`) tras verificar en vivo que los 48 descifran con las contraseñas existentes; re-corrida v3.12 confirmada (ver REPORT.md, addendum del coordinador).

## Dependencia que falta en el worker

Los scripts importan `cryptography.hazmat.primitives.ciphers.aead`
(`AESGCM`) en el nivel superior, sin fallback. `cryptography` **NO
está en el `requirements.txt` raíz del repo** (verificado: un venv
limpio con solo ese `requirements.txt` no puede importar
`cryptography`). Los demás usos de `cryptography` en el repo son
fallbacks perezosos tras `pycryptodome`; DeepTune es el único que la
exige en el nivel superior. Sin añadir `cryptography` al
`requirements.txt` (y reconstruir la imagen del worker), el módulo
falla con `ImportError` en el worker. Ver REPORT.md, spec §4.

## Pendiente

1. ~~Decidir la ampliación de las listas de campos (48 valores) y el
   `decryptionStatus` del resultado (ver REPORT.md).~~ — **Hecho por el coordinador 2026-11-17**: listas ampliadas y verificadas en vivo (v3.12); `decryptionStatus` con regla precisa por campo (solo los 12 reales).
2. Añadir `cryptography` al `requirements.txt` del worker.
3. Integración al repo: solo con autorización expresa del
   propietario. NO subir nada a GitHub sin ella.
