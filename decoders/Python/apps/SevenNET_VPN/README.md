# 7NET VPN — 5.6 (56)

Paquete `xyz.sevennetvpn.org`; proveedor fijo `7net-vpn`, integrado en PR #96.
Python >=3.10 y `pycryptodome==3.23.0`. Reutiliza las primitivas y la ruta de
archivos de `../../renz.py`; no necesita APK, SO, Android ni cuenta en runtime.

## Métodos confirmados

| Entrada | Cadena recuperada del APK | Salida |
| --- | --- | --- |
| Catálogo y campos tipo 0 | Base64 → AES-128-CBC, SHA-256(seed)[:16] e IV fijo → XXTEA de delta propio → restar 2 a cada byte | JSON exterior, nombres, puertos, banderas, DNS, certificados, UUID y opciones |
| Campos tipo 1 | Base64 → Threefish-256 con HKDF-SHA256 de 16/32 bytes y tweak `(índice, 0)` → AES-128-CBC | Hosts, SNI, paths, payloads, UDPv4Port y configuración V2Ray completa |
| Campos tipo 2 | Base64 → XXTEA → AES-256-CBC con IV prefijado de 16 bytes; PBKDF2-HMAC-SHA256, 100000 iteraciones | Usuarios y contraseñas globales y por servidor |
| Archivos `.7net` y `7netvpn://` | Ruta RENZ canónica y los métodos anteriores | Perfil exportado; conserva envoltura de compatibilidad |

La muestra usa Base64 para los campos sensibles. El esquema explícito se obtuvo
de `SEVENNETVPNMain.O0`, selectores y wrappers `fr1.b/c`. Incluye `UDPSSLPort`,
`UDPv4Port`, SlowDNS, ProxySettings, UDPOptions y V2Ray cuando están presentes.
El tipo nativo 3 abre un DEX auxiliar (`res/ae/frlb`) que se carga con
`InMemoryDexClassLoader`; no es otro formato de catálogo o configuración.

Se conserva el ciphertext hasta el siguiente límite CBC antes de validar
PKCS#7. El recorte nativo de ceros byte a byte cortaría seis campos de cada
catálogo real analizado. Los flujos Threefish afectados coinciden con la
primitiva ARM64 original y los valores recuperados con JDK independiente.
La corrección se aplica también al perfil RENZ `7net`, sin cambiar sus claves,
extensiones ni aliases; Xhypher y los demás perfiles mantienen sus métodos.

**Estos formatos no autentican criptográficamente el ciphertext.** Padding,
longitud y estructura validan el formato, no su autenticidad. Si falla un campo
cifrado conocido, el lector rechaza el catálogo completo.

## Fuentes comprobadas

Única URL del updater de este build:

`https://raw.githubusercontent.com/MAKE-MONEY-MILLION-DOLLAR-PER-DAY/7net-Team/refs/heads/main/7net%2BAll_Team.js`

Lectura pública autorizada del 2026-10-22: **HTTP 200, 758848 bytes, Version
40.19, 76 servidores y 619 redes/payloads**. Se procesaron **6025 campos
conocidos / 4750 no vacíos**, todos iguales a JDK independiente.
CLI HTTPS real, CLI stdin fuera del repositorio y worker aislado entregan el
mismo documento completo: **502968 bytes**, `isPartial:false`.

Catálogo inicial `res/ae/g.js`, recurso `2131820552`: **857240 bytes, Version
1.0, 92 servidores / 634 redes**, **6347 campos / 4982 no vacíos**, también
igual íntegro a JDK. Son observaciones de las muestras, no cantidades fijas.
Se preservan orden, duplicados, opciones, metadatos, listas, valores vacíos,
nulos y tipos desconocidos. Los JSON internos permanecen como texto exacto.
No se eligen hosts, sustituyen marcadores ni inician conexiones VPN.

## Uso

```bash
python server_catalog_decoder.py --download
python server_catalog_decoder.py copia-catalogo.txt
python server_catalog_decoder.py --stdin < copia-catalogo.txt
python file_decoder.py perfil.7net
```

Los dos lectores exponen `run(data: bytes) -> str`. El exportador observado
escribe `7netvpn://` seguido del sobre cifrado de una red y sus metadatos de
bloqueo/caducidad. No se aportó una exportación real independiente; las rutas
`.7net`, `7netvpn://` y el alias histórico `7net://` se comprueban con fixtures
JDK sintéticos. No se certifica un roundtrip de exportador Android.

## Cloud y herramientas conservadas

- Bridge privado, worker aislado, contrato de documento completo y control
  administrativo individual. Una URL HTTPS fija, DNS IPv4 público validado,
  TLS y ninguna redirección; el cliente no puede elegir destinos.
- PNG original exacto `res/h/cr.png`: **190×190, 13258 bytes**.
- Catálogo mínimo **33**, **35 fichas**; conserva switches y versión persistente.
  La entrega deja código en el PR, pendiente de actualización de la VPS.
- Herramientas recuperables en `scripts/apk_analysis/`, incluyendo
  `sevennet_verify.py`; referencias JDK/ARM64 y generador en
  `tests/golden/sevennet*`. [Recuperación](../../../../scripts/apk_analysis/RESTORE.md)
  y [pruebas](TESTING.md) explican cómo repetir el análisis en un entorno nuevo.

JADX terminó sin errores para el DEX 3 de la aplicación; DEX 1/2 reportaron
errores generales. Se inspeccionaron por separado los caminos documentados;
no se afirma una descompilación perfecta. LSParanoid resolvió **2089 literales
en 72 archivos / 2280 cadenas de inventario**. No se guardan APK/SO, inventarios,
catálogos reales ni credenciales descifradas en Git. No se fusiona, despliega,
publica APK ni actualiza novedades C11 como parte de esta integración.
