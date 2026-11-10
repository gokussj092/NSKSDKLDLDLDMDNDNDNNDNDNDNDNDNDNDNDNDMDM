# NPV Tunnel 124.0.37 (577)

El motor existente se mantiene en `decoders/Python/npvs.py`; no se duplica.
NPVS v5 app-key 2 y contraseña passphrase 1, con salida JSON completa.
Python 3.10+ y PyCryptodome; no requiere APK ni Go/JDK en producción.

```bash
python decoders/Python/npvs.py archivo.npvs
python decoders/Python/npvs.py protegido.npvs --credentials-stdin < credenciales.json
```

Para contraseña: `{"password":"contraseña de exportación"}` por stdin, no argv.
`run(data, password=...)`, `decode_npvs` y `decode_npvs_complete` conservan las
llamadas antiguas sin argumentos extra. El worker `.npvs` usa esa misma API.

Modo recipient v5/v6: una public key identifica al destinatario; no sustituye
su privada ECDH. Con `public_key` / JSON `publicKey` se comprueba coincidencia
y se informa `PRIVATE_KEY_REQUIRED`. **No se anuncia ese modo como descifrado**.
Los dos ejemplos Rjo normal/public-key aportados son el mismo archivo v6.
La nueva muestra **Kurdo vip bunq.npvs** es v5 app-key 2, sin destinatarios:
se abre completa sin contraseña ni public key (20 registros, 12 campos internos
`npvs1:`). No se modifica el lector v4 `NPVTUNNEL.py`.

## Script de textos separado

`text_decoder.py` reconoce `npvt://`, `npvt-ssh://`, `npvt-vless://`,
`npvt-vmess://` y `npv://`. Está integrado en el dispatcher de textos Cloud y en la detección de
Android en PR #96; la versión anterior del cliente todavía requiere una
actualización APK para solicitar los nuevos prefijos al servidor.
El router legado `npvt_links.py` sigue atendiendo `dns://` y `npvs1:`.
No se añaden motores criptográficos al APK.

```bash
python decoders/Python/apps/NPV_Tunnel/text_decoder.py enlace.txt
cat enlace.txt | python decoders/Python/apps/NPV_Tunnel/text_decoder.py -
```

API: `identify(text) -> prefijo | None`, `decode(text) -> dict | list`,
`decode_text(text) -> str | None` y `run(data: bytes) -> str`.
Devuelve `None` solo para un esquema no reconocido; un payload reconocido pero
inválido lanza `DecodeError` con `.code`, sin devolver datos parcialmente abiertos.

Base64/JSON y los campos explícitos `npvs1:` funcionan con este único script y
la biblioteca estándar. Si el texto transporta un binario `NPVS`, delega en el
`npvs.py` canónico del checkout, conservando firma y tags. Para copiarlo fuera
del repositorio con ese soporte, colocar `npvs.py` junto a `text_decoder.py`
e instalar PyCryptodome. Admite `password` / `public_key` opcionales para esa
ruta y `--credentials-stdin` con un archivo de entrada; nunca credenciales en argv.

La representación `npvt-ssh://Base64(JSON)` está confirmada en el APK
124.0.37. Los otros cuatro prefijos pedidos se aceptan como aliases del
transporte, **sin certificar cifrados distintos o exportaciones reales que
no se aportaron**. El módulo no adivina claves ni transforma un blob desconocido
en un resultado aparente. Un texto que use otro cifrado requiere un ejemplo
real para implementar y comprobar su ruta. Detalles en
`docs/NPV_TEXT_AND_NORMAL_FILE.md`.

Método original: `docs/NPVS_V5_INVESTIGATION_HANDOFF.md`. Extensión, hashes,
límites y pendientes: `docs/NPVS_PROTECTED_FILES.md`. Herramientas y recuperación
en `scripts/apk_analysis/`. Pendiente actualizar la VPS; sin APK/UI/catálogo nuevos.

Revisión de Offline 2026-11-09: aliases, DNS/npvs1 y errores de campos anidados
en `analysis/_intake/npv-offline-text-20261109/`. Solo C++ y entrada de textos
Offline; el lector Python y el servicio no cambian. No se aportó un enlace
real nuevo para certificar versiones adicionales.

Expediente del consumidor Offline build 42: `analysis/com.ghostdeveloper.spdecode.offline/42/`.
