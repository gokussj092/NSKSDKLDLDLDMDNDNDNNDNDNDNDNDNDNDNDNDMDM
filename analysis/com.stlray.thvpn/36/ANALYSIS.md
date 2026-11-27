# ANALYSIS — STLRAY 1.1.36 (`com.stlray.thvpn`, code 36)

- **App:** STLRAY 1.1.36 (versionCode 36)
- **APK analizado:** `STLRAY_1.1.36_1_0c8r.apks` (35,599,563 bytes);
  base.apk extraído, SHA-256
  `1f921dc82f3e79d41ff21fa2f80eafec233a304171b557ecb4f2cf3f2052d9e7`
  (7,489,126 bytes). El hash del bundle `.apks` original no se
  conservó: `null`, no inventado.
- **Fecha:** 2026-11-27
- **Alcance:** catálogo en vivo (3 fuentes) + archivos TVC + textos
  TVC. Sin push, sin despliegue desde este trabajo.
- **Veredicto: EL CATÁLOGO ABRE EN VIVO. Los archivos/enlaces son
  VERIFIED_SYNTHETIC** (round-trip sobre un perfil real del
  catálogo; falta un archivo/enlace real exportado por la app).

> STLRAY es un fork ThaiVPN (`io/thaivpn/runtime/libbox`, núcleo
> sing-box). Su catálogo usa el sobre THAIVPN2 (5 capas); sus
> perfiles usan el codec TVC (`oa0.java`). No es de la familia
> strongteam (Katiba/Fat/IRFAN): no hay Argon2id ni `strongteam.co`.

## 1. Catálogo en vivo — THAIVPN2 (5 capas)

- **Observación:** `assets/initial-config.json` trae el catálogo
  semilla más `updates.configLocator` (sobre `THAIVPN2L`, sin
  firma) que descifra a la URL en vivo. Tres GET planos, sin
  headers especiales, sin autenticación:
  `https://stallionray.my.id/sray_v2x6w9c4/` + `config.json` /
  `modes.json` / `policy.json`.
- **Sobre:** `{"format":"THAIVPN2","layers":5,"data":b64,
  "signature":b64}`. Firma ECDSA P-256 / SHA-256 sobre
  `b"THAIVPN2/config/5" + data`; clave pública en
  `assets/catalog-keys.json` (SPKI DER base64).
- **Master key:** `encryptionKey` si existe; si no, XOR de 5 filas
  de 32 ints en `l1l10lOI` (`I110l1O.java`).
- **Capas, i=4..0:** clave = HMAC-SHA256(master,
  `"THAIVPN2/<scope>/key/<i>"`); AES-256-GCM, nonce = primeros 12
  bytes, AAD = `"THAIVPN2:<scope>:<i>"`. Scopes: config / modes /
  policy / locator. Texto plano gzip (`1f 8b`) o JSON crudo.
- **Verificación:** config rev 150086 / 15.86 (el bundled era
  150073 / 15.73), firma válida; modes rev 10009 / 1.9 (14 modos);
  policy rev 10007 / 1.7. 76 servidores (71 free: 60 VLESS, 5
  OPENVPN, 5 UDP Hysteria1, 1 SSH; 5 premium UNIFIED), 38
  payloads, 6 certificados. Notas: "Added UMO ULTRA 5G servers."
- **Hipótesis descartada:** el locator no es un endpoint aparte a
  integrar — es solo el puntero a las 3 URLs fijas, y el bloque
  `updates` se excluye del resultado por la regla de Pedro.

## 2. Archivos y enlaces — codec TVC (`oa0.java`)

- **Observación:** esquemas con clave propia (32 bytes = XOR de 3
  filas de 32 ints): `sray://`, `tvc://`, `uv://`, `gv://`,
  `gpx://`, `insan://`, `opq://`, `test://`. `hyb://` no tiene
  clave — la app usa la de `sray`.
- **Enlace:** `<esquema>` + base64url-sin-pad (`salt || MASK(
  capas-GCM( prefijo-aleatorio || rawDeflate(perfilJSON) ) )`).
- **Archivo:** mismos bytes crudos que el cuerpo del enlace; el
  decodificador también acepta el archivo como texto base64url.
- **KDF:** HMAC encadenado con etiqueta (`TVC-KDF-INIT` /
  `TVC-LOCK-KDF`); máscara por bloques HMAC `TVC-MASK`; capas
  AES-256-GCM.
- **Variantes, en orden:** locked (salt 16, 7 capas, 128 rondas,
  prefijo 8), normal (salt 12, 1 capa, 64 rondas, prefijo 4),
  legacy (salt 16, 7 capas, 64 rondas, prefijo 4).
- **Verificación:** round-trip con el perfil VLESS real del
  servidor `CELCOM BASIC 01` (15 campos): `sray://` normal MATCH,
  `sray://` locked MATCH, `tvc://` MATCH, `decode-file` con bytes
  crudos MATCH, con texto base64url MATCH.

## 3. Colisión `.gv` — análisis y resolución

- **Observación:** `.gv` ya existe como "Generic AES-GCM /
  PBKDF2" (`decoders/Python/generic_aes.py`, C0): el archivo es
  texto con exactamente 3 segmentos Base64 separados por puntos
  (`salt.nonce.ciphertext+tag`), con una contraseña fija en
  `generic_profiles.py`.
- **Observación:** un `.gv` STLRAY es bytes TVC crudos (salt
  aleatorio + capas GCM enmascaradas) o un solo token base64url
  (sin puntos). Un token base64url nunca tiene puntos; unos bytes
  crudos solo podrían parecer genéricos si, por azar, se partieran
  en exactamente 3 segmentos Base64 válidos — probabilidad
  despreciable y el mismo tipo de heurística que el repo ya usa
  para `.ost` / `.bee` / `.eut`.
- **Decisión:** dispatch por contenido (predicado negativo, solo
  bytes, nunca descifrado): si el contenido NO tiene forma
  genérica de 3 segmentos, va a STLRAY; si la tiene, conserva la
  ruta genérica congelada. La entrada `_C8_FILE_ENGINES["gv"]`
  apunta a STLRAY con nombre combinado
  `STLRAY 1.1.36 / Generic AES-GCM / PBKDF2`, así el
  `file-formats.json` regenerado sigue listando ambas rutas y
  `offlineSupported` sigue `true` (`.gv` está en el asset
  nativo Android).
- **Otros sufijos:** `.sray` `.tvc` `.uv` `.gpx` `.test` `.insan`
  `.opq` no existen en `file-formats.json` ni en
  `C0_FORMAT_MATRIX.csv` (verificado por búsqueda 2026-11-27).
  Prefijos de texto `sray://` … `hyb://` no existen en
  `text-formats.json`; `vless://` ya está registrado (estándar).

## 4. Auditoría HMAC (sección 2.2 de la política)

| Ámbito | Estado | Evidencia |
|---|---|---|
| Archivo/catálogo | HMAC-SHA256 confirmado como derivación de claves + AAD/máscara (THAIVPN2 y TVC); ECDSA P-256 verifica la firma del catálogo | `stlray.py`: `_hmac` en `thaivpn2_unwrap`, `_tvc_kdf`, `_tvc_mask`, `_tvc_unwrap_layers`; `thaivpn2_verify` |
| Transporte VPN | No observado | Los protocolos (VLESS/SSH/OpenVPN/Hysteria1) se describen en el catálogo; no se trazó ningún handshake |
| Autenticación de conexión | NOT_OBSERVED | Ningún HMAC autoriza el establecimiento de la conexión; las credenciales son usuario/contraseña/UUID/`auth_str` del catálogo. No se intentó ningún login en vivo |

La presencia de HMAC prueba integridad/derivación local, no
autenticación de conexión. No se guardan claves de sesión, tokens
ni credenciales reales en este expediente.

## 5. Herramientas

jadx (DEX → `I110l1O.java`, `o30.java`, `l0OIIlOI1.java`,
`oa0.java`); Python 3.12 + `cryptography` + `pycryptodome` para
reproducir el descifrado. El núcleo nativo `libstlraytcore.so`
(67 MB, en `split_config.arm64_v8a.apk`) no se necesitó para el
catálogo ni para TVC. Detalle y comandos en REPRODUCE.md.
