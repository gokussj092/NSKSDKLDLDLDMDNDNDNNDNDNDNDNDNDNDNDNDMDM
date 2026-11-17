# M Light 3.1.55 — RESULTS

Fecha de verificación: 2026-11-17. Entorno: Python 3.12.3, venv de
verificación con `pycryptodome` 4.5.0 (también probado el fallback
AES puro sin `pycryptodome` en el análisis original: 5/5).

## Self-tests (sin red)

- `M_Light.py --self-test`: **5/5 OK**
  - vector FIPS-197 AES-256 (backend pycryptodome)
  - derivación de clave SHA-256(hex)
  - round-trip cifrado baybayin/AES
  - asset bundled iusacel.png v1.0.0
  - muestra viva v1.0.115 / 117 servidores
- `M_Light_archivos.py --self-test`: **6/6 OK**
  - round-trip .pausa baybayin (export app)
  - round-trip .pausa base64
  - round-trip JSON plano cifrado
  - round-trip enlace pausa://
  - parser java.util.Properties (escapes)
  - contraseña incorrecta rechaza

## Re-corrida en vivo (2026-11-17)

- Comando: `M_Light.py --download -o catalogo.json`
- Resultado: catálogo **v1.0.115, 117 servidores**, 40 MyServer
  distintos, 3.814 campos (1.984 no vacíos). Duración total ~1,2 s.
- Comparación: **byte-idéntica** a la muestra entregada
  (`catalogo_vivo.json`, 137.766 B, SHA-256
  `7e61c89fc62cb9fd162df2aabd5260b608e262e2ba6f6ef3840d40dae4cc0cd1`).
- El resultado JSON NO contiene las URLs/endpoints de descarga
  (verificado: sin `raw.githubusercontent`, `github.com`,
  `PausaStudio` ni `pausada258` en el JSON).

## Asset empaquetado

- `assets/flags/iusacel.png` (config ofuscado v1.0.0): abre con el
  script operativo (check incluido en el self-test 5/5).

## Tests del expediente

- `tests/test_method.py`: round-trip baybayin con clave de prueba
  sintética + vector de la construcción (ver RESULTS del test al
  ejecutarlo). Sin red, sin claves reales.

## Negativos / pendientes

- Sin archivo `.pausa` real: el decodificador de archivos no está
  verificado de extremo a extremo (solo round-trip sintético 6/6).
- Sin enlace `pausa://` real compartido por la app.
- `messages-config.json` verificado en vivo (JsonVersion 1.0.26) pero
  no cableado como segunda fuente.
