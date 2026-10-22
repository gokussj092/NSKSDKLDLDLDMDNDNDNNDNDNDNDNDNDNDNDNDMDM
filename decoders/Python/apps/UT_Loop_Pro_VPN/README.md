# UT Loop Pro VPN — 22.10.26 (65)

Paquete `loop.uchetechs.vpn.pro`. Proveedor estable `ut-loop-pro-vpn`.
Análisis e integración de backend en la rama del PR #96; no requiere APK,
bibliotecas nativas ni Android para ejecutar los lectores. Python >=3.10 y
`pip install -r requirements.txt`.

## Métodos recuperados

| Entrada | Lector | Tratamiento confirmado |
| --- | --- | --- |
| Actualización OTA o respuesta premium firmada | `server_catalog_decoder.py` | Sobre JSON `data`/`sig`, RSA PKCS#1 v1.5 SHA-256 sobre el texto exacto de `data`; Base64, nonce de 12 bytes, AES-256-GCM y tag de 16 bytes. Clave SHA-256/esquema XOR máscara del APK. |
| Copia local del catálogo inicial o caché SQLite | mismo lector | Mismo AES-GCM; copia Base64 sin envoltura RSA. Solo entrada offline explícita; las descargas siempre exigen firma. |
| Banner SSH moderno | `banner_decoder.py` | GCM, AAD `utloop-banner-v1`; material de ambos certificados admitidos, expansión SHA-256 y máscaras originales. |
| Banner SSH heredado | mismo auxiliar | XXTEA little-endian, delta propio `-1704280`, clave `uchehacks`, longitud al final y portador entre comillas. |

La firma o el tag de un catálogo inválido rechazan la entrada completa, sin
fallback a un documento parcial. El banner conserva el fallback heredado del
APK porque ambos usan el mismo portador HTML; XXTEA no proporciona autenticación.
Este auxiliar no se registra como formato de perfil o proveedor adicional.

El JSON descifrado se devuelve íntegro: servidores, Tweaks, datos SSH/SSL/DNS,
UDP/HUDP/OpenVPN/V2Ray/Trojan/VLESS/WireGuard cuando estén presentes, tipos,
listas, duplicados, valores vacíos y campos desconocidos. No se aplican filtros
de interfaz, no se generan credenciales y no se activan sesiones VPN. El catálogo
inicial real contiene **un servidor y un tweak, versión 1.0**; el documento completo
coincide con la referencia independiente JDK, CLI y worker aislado.

## Uso offline

```bash
python server_catalog_decoder.py copia-cifrada.txt
python server_catalog_decoder.py --stdin < copia-cifrada.txt
python banner_decoder.py banner-ssh.txt
```

API reproducible: `run(data: bytes) -> str`. El catálogo se registra en el bridge
fijo y la allowlist del worker privado de Cloud. No se identificó un formato de
archivo exportado/importado en este build; no se inventa una extensión ni se
modifican rutas históricas de archivos.

## Acceso remoto pendiente

Fuente del APK: `https://api.utloop.xyz/v1/ota/config?package=loop.uchetechs.vpn.pro`.
El código del APK usa `X-Api-Key`, `X-Ota-Access` y `X-Ota-Iid`. El acceso OTA se
obtiene con Play Integrity oficial; el lector no lo fabrica. Consulta autorizada
del 2026-10-22 desde este entorno: **HTTP 200, text/html, 195 bytes**, página
`Site Unavailable`, sin documento firmado. Esto no permite atribuir una caída
general al proveedor, afirmar error de token ni contar servidores remotos.

La fuente premium separada del APK es un POST fijo a
`https://api.utloop.xyz/v1/premium/config` con `packageName` y `entitlement` oficial.
Su firma y cifrado son los mismos; no se proporcionó una respuesta premium real
ni un entitlement válido. No se fusiona el catálogo premium con placeholders,
se rellenan stubs ni se afirma recuperar contenido de una suscripción.

El CLI admite `--download` con `UT_LOOP_OTA_ACCESS` y `UT_LOOP_OTA_IID`, y
`--premium` con `UT_LOOP_ENTITLEMENT` suministrados expresamente por el operador.
Solo URLs fijas, límites de 8 MiB, TLS del sistema y ninguna redirección; antes de
aceptar una descarga exige la firma RSA real y GCM. Estas ramas de solicitud se
verificaron con transporte controlado, **no con una sesión remota válida**.

La ficha pública conserva el **PNG original exacto, 601×601, 74425 bytes**, y
`remote:null`: descifrado remoto desactivado incluso con una disponibilidad
forzada. No se añade el proveedor a la allowlist pública ni al control de
activación remota hasta verificar un catálogo oficial completo y su acceso.
Catálogo mínimo **31**, **33 fichas**, versión persistente monotónica existente.

Las comprobaciones adicionales de las rutas de acceso fueron bloqueadas por
revisión automática al considerarse sondeo de API con una clave extraída fuera
de la lectura de catálogo autorizada. No se reintentaron ni se utilizan sus
resultados como evidencia. El acceso OTA/premium sigue pendiente.

El almacenamiento local de preferencias usa Android Keystore y migración XXTEA;
no constituye un feed o formato exportado. No se extraen claves de dispositivos
ni se presenta ese almacenamiento como un lector de perfiles.

## Evidencia y herramientas

- `TESTING.md`, `manifest.json` y `tests/golden/ut_loop_pro_*`.
- APK: `util.r`, `db.a`, `core.h`, `util.h`, `util.OtaAccess`, `util.t`,
  `util.c/n/d` y consumidores de `MainActivity` / `SSHTunnelService`.
- Herramientas existentes de `scripts/apk_analysis/` más el nuevo
  `stringfog_strings.py`: 2438 llamadas literales resueltas en 71 archivos.
- JADX finalizó con 21 errores generales; las rutas criptográficas indicadas se
  inspeccionaron y contrastaron con JCA. No se afirma descompilación perfecta.
- Sin APK/SO, catálogo real, datos descifrados, tokens o inventarios privados en
  Git. No se fusiona, despliega, publica APK o anuncia novedades automáticamente.
