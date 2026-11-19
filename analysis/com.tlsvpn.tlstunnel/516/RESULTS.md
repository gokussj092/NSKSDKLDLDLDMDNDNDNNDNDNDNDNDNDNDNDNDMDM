# RESULTS — TLS Tunnel (com.tlsvpn.tlstunnel, versionCode 516) — OFFLINE

Observado 2026-11-19. Entorno del expediente: Python 3.12.3, g++ 13.3.0,
CMake 3.28.3, PyCryptodome 4.4.0, Mbed TLS 3.6.7 (SHA-256 verificado),
nlohmann/json 3.11.3 (paquete de sistema), Linux x86_64. Sin red salvo la
descarga fijada de Mbed TLS para el harness.

## 1. Estado por ruta

- **files (.tls)**: VERIFIED_SYNTHETIC — el decodificador nativo abre los 6
  perfiles sintéticos y el JSON coincide exactamente con el oráculo Python
  (13/13 MATCH, ver §3). Sin muestra real `.tls` en este expediente.
- **text (tls://)**: VERIFIED_SYNTHETIC — el enlace sintético abre con
  perfil 1; mismo contenedor que el archivo. Sin enlace `tls://` real
  observado.
- **catalog**: OUT_OF_SCOPE — la app offline no descarga catálogos.
- **export**: PENDING — falta un `.tls` real exportado por TLS Tunnel
  8.5.0 o 8.5.2 (o la APK 8.5.2) para elevar el puerto nativo a
  VERIFIED_REAL y confirmar los 6 perfiles en 518.

Etiquetas: VERIFIED_REAL = verificado con muestra real; VERIFIED_SYNTHETIC
= verificado con fixtures sellados por el script (prueba la lógica, no la
compatibilidad con la app real); PENDING = falta una muestra.

## 2. Evidencia de versión en vivo (2026-11-19)

- Google Play (texto rastreado 2026-11-19 03:45 UTC): "TLS Tunnel: Fast
  Secure VPN", rating 4.42 (216 163 valoraciones), gratis; el texto no
  expone el número de versión.
- APKFab: última versión **8.5.2**, actualizada **2026-11-05**, 18.38 MB,
  SHA1 `7318326872c9d7cd0f045a27cceeb229ec840742`, arm64-v8a + armeabi-v7a,
  Android 7.0+. Changelog 8.5.2: "Lib updates".
- La descarga de la APK 8.5.2 fue imposible en esta VM (APKPure/APKMirror/
  APKFab: 403; APKCombo: dominio aparcado; Uptodown: 404; APKMonk: sin
  respuesta). Base y splits de 518 **no revisados**; no se afirma nada
  sobre sus librerías nativas.

## 3. Comparación C++ vs oráculo (harness host)

`tools/run_harness.py` — **13/13 MATCH**. Informe legible por máquina:
`RESULTS_harness.json`. Harness: `/tmp/tls-harness-build/tls_harness`
(SHA-256 `823909ca7a1f5447668df5312233c807382b2beece8c2eb9d8aea97b54a1d11c`).

| Fixture | Resultado |
|---|---|
| tls-profile1.tls | MATCH (perfil 1) |
| tls-profile2.tls | MATCH (perfil 2, plaintext de longitud impar) |
| tls-profile3.tls | MATCH (perfil 3) |
| tls-profile4.tls | MATCH (perfil 4) |
| tls-profile5.tls | MATCH (perfil 5) |
| tls-profile6-legacy.tls | MATCH (perfil 6, nombres DNS antiguos) |
| tls-link.txt | MATCH (tls://, perfil 1) |
| tls-short.tls | MATCH (5 campos, resto por defecto) |
| tls-profile3-bad-inner-b64.tls | MATCH (Base64 interior inválido conservado) |
| tls-tampered.tls | MATCH (ambos rechazan; C++: TLS_AUTH_FAILED) |
| tls-truncated.tls | MATCH (C++: TLS_CONTAINER_TOO_SHORT) |
| tls-garbage.tls | MATCH (C++: TLS_INVALID_BASE64) |
| tls-empty.tls | MATCH (C++: TLS_EMPTY_INPUT) |

"MATCH" = el JSON decodificado por el C++ es idéntico (tras parsear) al
del oráculo Python, incluido `_tls.key_profile`, `_tls.fields` y los
nombres de campo antiguos solo en el perfil 6.

## 4. Tests ejecutados en esta sesión

- `python -m unittest tests.test_tls_decoder -v` (suite del repo):
  **6 passed, 1 skipped** (muestra real privada, `TLS_REAL_SAMPLE` no
  definido; SHA-256 registrado en el test).
- `python -m unittest tests.test_method -v` (este expediente):
  **Ran 7 tests — OK** (6 perfiles, legacy, enlace, corto, Base64
  interior inválido, 4 negativos, esquema + hashes de fixtures).
- `tools/run_harness.py`: **13/13 MATCH** (ver §3).

## 5. Qué abre y qué rechaza

Abre: cualquier `.tls` / `tls://` sellado con uno de los 6 perfiles
conocidos de 8.5.0, con o sin sufijo `:::::`, con o sin prefijo `tls://`,
plaintext de cualquier longitud de campo (incluida la paridad impar del
split C1/C2), y con campos Base64 interiores inválidos (se conservan).

Rechaza limpiamente (sin plaintext parcial): Base64 exterior inválido,
contenedor < 148 B, etiqueta GCM inválida (archivo manipulado o sellado
con una clave desconocida / perfil nuevo de una versión futura),
plaintext no UTF-8, entrada vacía.

## 6. Pendientes

1. Muestra real `.tls` exportada por 8.5.0 o 8.5.2 → elevar a
   VERIFIED_REAL (comparar oráculo vs harness con esa muestra).
2. APK 8.5.2 (518) → confirmar que los 6 perfiles siguen vigentes;
   si hay un perfil 7, abrir expediente `analysis/com.tlsvpn.tlstunnel/518/`.
3. Compilación del APK offline en CI + prueba en teléfono real (esta VM
   no tiene Android SDK).
