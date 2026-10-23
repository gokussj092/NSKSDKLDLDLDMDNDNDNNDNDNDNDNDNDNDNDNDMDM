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
Los dos ejemplos normal/public-key aportados son el mismo archivo v6; falta
otro archivo normal distinto. No se modifica el lector v4 `NPVTUNNEL.py`.

Método original: `docs/NPVS_V5_INVESTIGATION_HANDOFF.md`. Extensión, hashes,
límites y pendientes: `docs/NPVS_PROTECTED_FILES.md`. Herramientas y recuperación
en `scripts/apk_analysis/`. Pendiente actualizar la VPS; sin APK/UI/catálogo nuevos.
