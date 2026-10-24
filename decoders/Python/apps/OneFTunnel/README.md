# 1FTunnel 0.6.99 (125)

Lector offline de archivos `.1ftnl` y textos exportados por `com.oneftunnel.app`.
La muestra real aportada se autentica y devuelve el documento completo, con
configuración Xray VLESS, sin secciones omitidas ni bytes sobrantes.

```bash
python -m pip install -r decoders/Python/apps/OneFTunnel/requirements.txt
python decoders/Python/apps/OneFTunnel/file_decoder.py perfil.1ftnl > resultado.json
cat perfil.1ftnl | python decoders/Python/apps/OneFTunnel/file_decoder.py -
# Perfil con contraseña: objeto JSON por stdin, sin contraseña en argumentos.
python decoders/Python/apps/OneFTunnel/file_decoder.py perfil.1ftnl --password-stdin < credenciales.json
```

API: `run(data: bytes, *, password: str | None = None) -> str` y
`codec.decode(...) -> dict`. No requiere APK, SO, Java ni conexión en producción;
solo Python 3.10+ y PyCryptodome. Las herramientas de investigación sí tienen
dependencias adicionales, indicadas en `scripts/apk_analysis/requirements.txt`.

## Formatos y resultados

- Contenedor binario `1FT1`, versiones 1–3; AES-256-GCM y HKDF-SHA256.
- Prefijos exactos `1FTnl.`, `1FT1.`, `1ftunnel://1FTnl/`,
  `1ftunnel://1FT1/`; Base64 URL-safe con o sin padding válido.
- Documento `CFG1`, versiones 1–5: ID, nombre, fechas, mensaje, máscara de campos,
  SSH, inyección, DNS y Xray. Incluye VMess/VLESS/Trojan, TLS/NONE/REALITY,
  WS/GRPC/RAW/XHTTP/HTTPUPGRADE y todos los campos de las revisiones 3–5.
- Conserva tipos, listas de opciones codificadas como enums, vacíos, `null`,
  fechas, campos de bloqueo, firma, mínimo de build y política de root.
  Los valores inexistentes en versiones antiguas se explicitan con `null` o el
  valor predeterminado del modelo, junto con `payloadVersion`.
- Salida completa bajo `metadata` y `config`, `authenticated:true`,
  `isPartial:false`. No traduce el perfil a un archivo Xray ejecutable.
- Modos 0/1 sin contraseña criptográfica, modo 2 con contraseña real UTF-16BE.
  Nunca busca contraseñas. Errores seguros: `PASSWORD_REQUIRED`, `AUTH_FAILED`,
  `INVALID_FORMAT`, versiones/identidad no soportadas. No devuelve texto parcial
  ante un tag incorrecto, campos incompatibles o datos restantes.

El lector verifica integridad y vinculación del formato; conserva caducidad,
mínimo de versión y restricciones del cliente como metadatos de una lectura
offline. No certifica elegibilidad de uso ni inicia conexiones VPN.

## Rutas integradas

Worker Cloud `.1ftnl`, dispatcher de los cuatro prefijos y registro Python del
bot. Contraseñas del worker solo por stdin, con límite de 4096 bytes UTF-8;
sin argumentos, variables de entorno o logs con credenciales. Gateway permite
solo `password`; HWID no es un parámetro de este formato.

Android añade únicamente detección para remitir al servidor existente; no
incluye criptografía local ni cambia el diseño. No se compiló/publicó una APK.
Inventario C0 congelado en 240; C8 efectivo pasa de 247 a 248 rutas. La
disponibilidad en producción requiere actualizar la VPS y, para esa detección,
el cliente. El registro Server VPN y C11 permanecen intactos.

## Catálogo

No se identificó un catálogo incorporado ni un actualizador de servidores en
esta versión: assets limitados a perfiles de optimización DEX; las URLs de
aplicación observadas corresponden a ayuda/Telegram e IP pública. Se deja
pendiente cualquier fuente de catálogo no identificada. No se crea proveedor,
ficha remota o descargador ficticio. AM continúa pendiente por separado.

Evidencia reproducible, hashes y límites en [ANALYSIS.md](ANALYSIS.md) y
[TESTING.md](TESTING.md). Herramientas versionadas en `scripts/apk_analysis/`,
referencia independiente y vectores exclusivamente sintéticos en `tests/golden/`.
