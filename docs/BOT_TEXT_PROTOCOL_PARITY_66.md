# SP-DECODE — Paridad de protocolos de texto de `66.py`

## Alcance

**Solo Telegram / mensajes de texto.** No cambia `decoders.json`,
`spdecode/registry.py`, los 239 formatos de archivo, APK/Kotlin,
credenciales administrativas, keystore ni publicación de Releases.

El archivo de referencia de esta auditoría es `66.py` (24 350 líneas),
especialmente su `PROTOCOL_MAP` y `universal_decrypt_attempt`, junto
a las funciones de descifrado de cada familia. El objetivo es conservar
los algoritmos correctos y el contenido íntegro del resultado.

Se crean dos motores reutilizables sin acceso a Internet:

- `decoders/Python/text_legacy_protocols.py`: AES-ECB NetMod y AR,
  AES-CBC XrayPB, Howdy/Mark/N7pr y ZIVPN.
- `decoders/Python/text_structured_protocols.py`: formatos Base64/JSON
  Creeb, VMess, SlipNet; importaciones FlexNet, NPVS v5, V2Box y
  Kivu VPN reutilizando los decodificadores existentes.
- `spdecode/handlers/extra_text_protocols.py`: despachador con validación
  de prefijos, autorización central, salida HTML escapada y respuestas
  divididas por tamaño.

En `main.py` se carga el nuevo despachador **antes** de los handlers
heredados. Evita que un manejador antiguo de NetMod, Howdy o V2Box
capture la petición y aplique un algoritmo incompleto. No se cambia el
orden ni el comportamiento de SSC, TLS, RENZ, IZPH, HAPP ni los motores
preexistentes que no forman parte de esta fase.

## Prefijos atendidos por esta fase

| Familia | Prefijos aceptados | Proceso |
|---|---|---|
| NetMod | `nm-dns://`, `nm-vless://`, `nm-vmess://`, `nm-trojan://`, `nm-socks://`, `nm-ss://`, `nm-ssr://`, `nm-ssh://`, `nm-xray-json://`, `nm-wireguard://`, `nm-trojan-go://` | AES-128-ECB PKCS7, 3 claves históricas |
| AR | `ar-dns://`, `ar-vless://`, `ar-vmess://`, `ar-trojan://`, `ar-ssr://`, `ar-socks://`, `ar-trojan-go://`, `ar-ssh://`, `ar-ss://` | AES-128-ECB PKCS7 |
| XrayPB | `pb-ssh://`, `pb-vless://`, `pb-vmess://`, `pb-trojan://`, `pb-socks://`, `pb-ss://` | AES-CBC, clave/IV históricos, relleno NUL |
| Howdy | `howdy://`, `N7pr://`, `Mark://` | JSON Base64 + campos `server`/`sni` AES-CBC o JSON completo cifrado |
| ZI VPN | `zivpn://` | AES-CBC con clave SHA256 de contraseña histórica |
| FlexNet | `flex://`, `flexnet://` | Base64 binario `FLXCFG`, motor autenticado ya integrado |
| NPVS | `npvs://`, `vpvs://` | Base64 binario NPVS v5, firma + AEAD existentes |
| V2Box | `v2box://` | Variante `locked=` Base64 URL o exportación AES-GCM |
| Kivu VPN | `kivuvpn://` | Motor Dark Tunnel existente |
| SlipNet antiguo | `slipnet://` | Base64 UTF-8 sin AES (distinto de `slipnet-enc://`) |
| VMess | `vmess://` | Decodificación Base64 de JSON, no descifrado criptográfico |
| Creeb | JSON raíz `{"type":"creeb_profile_bundle",...}` | Extrae enlaces y conserva todo el bundle |

**38 prefijos explícitos y una detección JSON** están dirigidos por
este módulo. Algunos ya existían en el bot pero sus implementaciones
eran parciales: la cifra no debe interpretarse como 38 métodos nuevos.

## Protocolos ya existentes que no se duplicaron

- **RENZ/7NET:** 23 esquemas, incluidos
  `7net://`, `tcx://`, `ihome://`, `actunnel://`, `gcpvpn://`.
- **IZPH:** `izph://` y `izphvpnpro://`.
- **XOR VPN:** `apnalite://`, `bdnet://`, `hxt://`,
  `fnf://`, `4ulite://` y los demás alias de esa familia.
- **HAPP:** `happ://crypt/` hasta `happ://crypt4/`, por clave RSA
  configurada exclusivamente en el servidor mediante variable local.
- **SSC, TLS, Dark Tunnel, JuanScript, EUT, WyrLite, WyrVPN, IntVPN,
  SlipNet-ENC, HTTP Tweak y Falcon Tunnel:** mantienen sus manejadores.
- **`npvt-ssh://`, `dns://` y `npvs1:`:** ya son atendidos por
  `npvt_links.py`. `npvs1:` es Base64 de campos históricos, **no** es
  el cifrado NPVS v5.

## Precauciones para actualizaciones y compatibilidad

1. Los prefijos de texto no modifican la selección de archivos. Se
   reconocen únicamente al principio de un mensaje, ignorando mayúsculas.
2. **PB VMess** tiene una segunda envoltura Base64 después de AES-CBC;
   los demás PB utilizan el contenido descifrado directamente.
3. **Howdy** puede incluir un JSON Base64 con `server` y `sni`
   cifrados de forma independiente; los otros campos se conservan,
   incluidos valores `false`, `0` y cadenas vacías.
4. **SlipNet** `slipnet://` representa Base64 de texto y
   `slipnet-enc://` utiliza AES-GCM con etiqueta. No se deben mezclar.
5. **NPVS v5** solo acepta el archivo NPVS autenticado que el motor
   actual soporta. Variantes protegidas por contraseña u otros formatos
   ajenos a ese motor no se declaran compatibles por el prefijo.
6. **V2Box** protegido necesita una contraseña. La gestión ya existente
   pregunta en el chat y el tema del original, con vencimiento y límite de intentos.
   Nunca guardar contraseñas de usuarios en el repositorio ni enviarlas
   mediante mensajes de grupo.
7. **Creeb, VMess y SlipNet simple** son representaciones
   estructuradas/Base64, no algoritmos de cifrado autenticado.
8. **Maya, JEZ, XTP, Tik y Royal** tienen en el archivo original
   enlaces de descarga remota de configuraciones. No son
   necesariamente textos cifrados autónomos. No se agregan descargas
   automáticas de direcciones no verificadas ni se afirma compatibilidad
   sin comprobar sus respuestas y permisos.
9. **DES/AES genéricos:** se conservan cerrados en su fase anterior,
   sin nuevos alias ni cambios de prioridades.
10. Se respeta la autorización central: el bot procesa textos solo
    para administradores y chats/grupos autorizados.

## Verificación

```bash
python -m unittest tests.test_text_extra_legacy -v
python -m unittest tests.test_text_extra_structured -v
python -m unittest tests.test_text_extra_dispatcher -v
python -m unittest discover -s tests -v
```

Las pruebas incluyen cifrado sintético AES para **todos los prefijos
NetMod, AR y PB**, Howdy/N7pr/Mark, ZIVPN; además, FlexNet auténtico
GCM con contenedor de prueba, V2Box libre/protegido, SlipNet Base64,
VMess, Creeb, Kivu y NPVS por el motor v5. Se revisan selección de
handler, prioridad, autorización y escapado HTML.

**Alcance de los resultados:** una prueba sintética positiva demuestra
el algoritmo y el enrutamiento; no garantiza compatibilidad con
exportaciones actuales de terceros. Para cerrar esa validación hacen
falta muestras reales autorizadas y comparación exacta de campos.
