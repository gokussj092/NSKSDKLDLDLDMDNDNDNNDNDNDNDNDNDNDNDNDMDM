# M Light — archivos y catálogo

App: M Light (Play: "PausaVPN - (SSH/UDP/V2RAY)"), paquete
`com.pausatotal.mlight`, versionCode 80, versionName 3.1.55. APK
verificado: XAPK oficial 3.1.55 de APKPure, SHA-256
`44425c6f955ac14d122476f30fcd3180ab0857b8fc0d73f392b4e1e1980d4d3b`.

## Catálogo en vivo

- Descarga: `GET` al `config.json` del repo público de PausaStudio en
  GitHub raw, sin cabeceras ni User-Agent propios (defecto de Java),
  timeouts 15 s, exige HTTP 200. La app lee el cuerpo línea a línea y
  lo concatena sin saltos; lo guarda en `getFilesDir()` como
  `ic_launcher.png`. Si no existe el archivo local, usa el asset
  `assets/flags/iusacel.png` (config ofuscado v1.0.0, no es un PNG).
- Cifrado ("AESCrypt"): texto baybayin (pares de caracteres = 1 byte,
  alfabeto de 17 caracteres) → Base64 → AES/CBC/PKCS7, IV 16 bytes
  cero, clave = SHA-256 del hex en mayúsculas de la clave en claro
  que sale de `getAESKey()` en `libsec_core.so`. El texto plano es el
  JSON del catálogo, ya en claro (sin sobres internos: 0 valores con
  caracteres baybayin tras el descifrado exterior).
- URL secundaria: `messages-config.json` del mismo repo, mismo
  cifrado (JsonVersion 1.0.26). No está cableada como segunda fuente
  del catálogo (ver REPORT.md, pregunta abierta 1).
- El JSON de resultado lleva SOLO los datos del catálogo, todo
  descifrado; NUNCA incluye las URLs/endpoints de descarga (regla del
  propietario, 2026-11-15). Las URLs y la clave viven solo en el
  script operativo y en el registro supplied.

## Uso

```sh
python M_Light.py --download [-o catalogo.json] [--fields] [--messages]
python M_Light.py --raw respuesta_guardada.txt [-o catalogo.json]
python M_Light.py --self-test
python M_Light_archivos.py archivo.pausa [-o perfil.json]
python M_Light_archivos.py --link "pausa://..." [-o perfil.json]
python M_Light_archivos.py --encrypt perfil.json [-o archivo.pausa]
python M_Light_archivos.py --self-test
```

Solo biblioteca estándar (Python 3.10+). `pycryptodome` es opcional:
sin él, los scripts usan el fallback AES puro en Python incluido.

## Archivos `.pausa` y enlaces `pausa://`

- Export: `java.util.Properties.store()` → `AESCrypt.encrypt` →
  cadena baybayin-hex. Import: prueba (a) Base64 → AES/CBC con la
  contraseña de archivos y (b) formato baybayin-hex/AESCrypt; después
  JSON o `Properties.load()`. La app valida `file.blockHwid` = `"1"`
  o vacío.
- Enlace `pausa://` (también `pausa:`): quita el prefijo, corta en
  `?`, `Uri.decode`, alimenta los bytes como stream de importación.
- **NO VERIFICADO de extremo a extremo**: no existe ningún archivo
  `.pausa` real exportado por la app en un teléfono. Round-trip
  sintético verificado (ver "Probado").

## Probado (2026-11-17, re-corrida en vivo)

- Catálogo en vivo: **v1.0.115, 117 servidores**, 40 valores distintos
  de `MyServer`, 3.814 campos (1.984 no vacíos). Re-corrida en vivo
  byte-idéntica a la muestra entregada (`catalogo_vivo.json`,
  SHA-256
  `7e61c89fc62cb9fd162df2aabd5260b608e262e2ba6f6ef3840d40dae4cc0cd1`).
- Self-test `M_Light.py`: **5/5 OK** (vector FIPS-197 AES-256,
  derivación de clave, round-trip baybayin/AES, asset bundled
  v1.0.0, muestra viva v1.0.115 / 117 servidores).
- Self-test `M_Light_archivos.py`: **6/6 OK** (round-trips
  baybayin/base64/JSON/enlace, parser `java.util.Properties`,
  rechazo de contraseña incorrecta).
- `py_compile` de ambos scripts: OK.

## Nota sobre ServerUser/ServerPass compartidos

En el catálogo vivo v1.0.115, `ServerUser` es idéntico en 112/117
servidores y `ServerPass` en 79/117 (un mismo valor de 8 caracteres).
Veredicto verificado por flujo de código (NOTES.md §10 del análisis
original): es la **credencial SSH literal del operador**, sin segunda
capa de descifrado — la app la copia verbatim a prefs y la entrega a
Trilead/OpenVPN. El valor concreto está documentado en el expediente
`analysis/com.pausatotal.mlight/80/ANALYSIS.md` y en REPORT.md, no
aquí. No se intentó ninguna conexión SSH contra el servidor del
operador.

## Pendiente

1. Un archivo `.pausa` real exportado por la app en un teléfono,
   para verificar el decodificador de extremo a extremo.
2. Integración al repo: solo con autorización expresa del
   propietario. NO subir nada a GitHub sin ella.
