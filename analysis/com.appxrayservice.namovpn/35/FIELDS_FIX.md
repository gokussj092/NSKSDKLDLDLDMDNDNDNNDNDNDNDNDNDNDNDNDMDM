# Corrección de campos internos — 2026-11-04

Se reproduce el fallo comunicado por el propietario sobre la base
`a1b6721e39657d9e6e5360de88dede30d772f764`: el método abría Base64/XXTEA,
pero devolvía los campos internos todavía codificados. Se retira expresamente
la afirmación previa «el interior viene en texto». El oráculo anterior solo
probaba la primera capa; su igualdad con Python no cubría el consumo final.

## Observado en la misma build 35

Se vuelve a descargar el XAPK exacto de APKPure y se comprueban sus hashes y
los de la base contra MANIFEST. Identidad `com.appxrayservice.namovpn`,
3.5-namo/code35. JADX 1.5.6 vuelve a terminar 3/40 errores; las rutas relevantes
son legibles. Las cadenas se resuelven con el script compartido, sin ejecutar
APK, SO ni servicios VPN.

`sd0.v()` copia los valores de Servers/Networks a preferencias. `f60.m()`
aplica `Base64.decode(...,0)` y construye UTF-8. Se trazan sus consumidores:

| Campos del JSON | Consumidor |
| --- | --- |
| Servers.ServerIP, Cloudfront | SERVER_HOST → x93.t |
| Servers.ProxyIP; Networks.SquidProxy | PROXY_HOST → x93.A |
| Servers.Username, Password | x93.C / x93.y |
| Servers.NameServer, PublicKey | bo / x93.r |
| Servers.ServerDNS; Networks.ServerDNS | DNSTT_DNS → x93.p |
| Servers.setOpenVPN y raíz.setOpenVPN | OPENVPN_CINFIG → x93.w |
| Servers.OvpnCertificate | alias observado en so0.a → setOpenVPN |
| Servers.V2Ray | MainActivity → V2RayConfigManager |
| Servers.UDPConfig | UDP_HYSTERIA → d81.b |
| Networks.Payload, Sni | r10 / SSHCoreService / p02 |

El arreglo usa exclusivamente estas claves, una sola vez. Conserva claves,
filas, tipos string, puertos, nombres, flags, metadatos y campos desconocidos.
Un valor Base64 dentro del texto ya decodificado no se abre recursivamente.
OpenVPN, V2Ray y UDP siguen siendo strings; no se cambian por objetos ni se
extraen conexiones individuales. Faltantes permanecen faltantes, vacíos vacíos.
No se incorpora normalización destructiva de la UI ni valores por defecto.

## Verificación y límites

Dos GET reales originales recuperan el mismo catálogo 22.3/14 Servers/13 Networks,
72881 bytes y SHA256 del expediente. La referencia Java de XXTEA seguida de
la referencia Java Base64/UTF-8 coincide en todo el objeto con Python, CLI y
worker aislado. Cambian 87 valores no vacíos de filas; no se publican sus datos.
El fixture previo usaba campos en texto y se sustituye por uno ficticio con
ambas capas generadas por Java. Incluye todos los campos, alias, raíz,
Unicode, CRLF y claves desconocidas de apariencia Base64.

El backend es más estricto que Android ante datos inválidos: rechaza tipos
incorrectos, alfabeto/padding Base64 inválido y UTF-8 inválido en campos
documentados, sin devolver éxito parcial. Acepta LF/espacios y padding omitido.
XXTEA no autentica; no se promete detectar toda modificación válida.

La descarga Python es real. Replay Node usa HTTP simulado con esos bytes y la
respuesta real del worker. Node HTTP real devuelve REMOTE_NETWORK_DENIED en
este entorno y queda pendiente en VPS. No se prueban cuentas o conexiones VPN.
No hay nuevos secretos, dependencias runtime, cambios Android ni despliegue.
El piso del catálogo pasa 70→71, conservando versiones configuradas mayores,
65 fichas y 256 formatos.
