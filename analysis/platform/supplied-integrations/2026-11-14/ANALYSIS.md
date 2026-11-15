# Revisión de conexión de las 57 aplicaciones aportadas

Se revisan entradas, transporte y adaptación del resultado; no se reconstruyen métodos ni se modifican scripts de decoders/Python/apps. Las afirmaciones históricas de los README son evidencia heredada, no nuevas verificaciones remotas.

Los scripts con run() de consola, salida de resumen o descarga implícita reciben adaptadores offline por API. DNS público, IP fijada, TLS, límites, credenciales privadas y rechazo de redirecciones permanecen en el broker. Se conserva JSON completo y compatibilidad de .hexcm/.tgv/.hxt, 1FTunnel, MM y prefijos RENZ existentes.

Argon2id de los scripts autónomos usa argon2-cffi 25.1.0 ya fijado en el proyecto; cada primitiva se compara con su implementación original con vector sintético pequeño. No se copian claves ni se cambian fuentes originales. No se afirma autenticación HMAC de conexiones VPN.

| Aplicación | ID | Resultado / limitación |
|---|---|---|
| 24clan VPN Lite | `24clan-vpn-lite` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| APNA Tunnel Lite | `apna-tunnel-lite` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| AR PRO VPN | `ar-pro-vpn` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| AT NET VPN | `at-net-vpn` | Ruta conectada y muestra local descifrada. |
| Binke Volt | `binke-volt` | Ruta conectada y muestra local descifrada. |
| CATNET VPN | `catnet-vpn` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| DTunnel Mod | `dtunnel-mod` | Muestra completa de 49 perfiles OK. Descarga autenticada conectada; falta configurar user_id privado en el VPS. |
| DocNet VPN | `docnet-vpn` | Listado accesible; campos config cifrados sin clave. Respuesta marcada parcial. |
| EDOZ Tunnel | `edoz-tunnel` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| EDOZ Tunnel Pro | `edoz-tunnel-pro` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| E-SAN VPN | `e-san-vpn` | Ruta conectada y muestra local descifrada. |
| Fat Tunnel Lite | `fat-tunnel-lite` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| Guruz Tunnel | `guruz-tunnel` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| Guruz VPN | `guruz-vpn` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| HAMARA TUNNEL LITE | `hamara-tunnel-lite` | Ruta conectada y muestra local descifrada. |
| HX Tunnel VPN | `hx-tunnel` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| Handsome Fast | `handsome-fast` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| Hex Custom | `hex-custom` | Solo archivos: no tiene catálogo público propio. |
| Rev Hunter | `rev-hunter` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| IGNIX VPN MAX | `ignix-vpn-max` | El propio descifrador declara cifrado pendiente. |
| IP Tunnel | `ip-tunnel` | Ruta conectada y muestra local descifrada. |
| JetRoi | `jetroi` | LIVE_DECRYPT_FAILED en la muestra aportada; limitación documentada por su script. |
| Lets VPN Go | `lets-vpn-go` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| LinkLayer VPN | `linklayer` | Ruta conectada y muestra local descifrada. |
| LITRON VPN | `litron-vpn` | Ruta conectada y muestra local descifrada. |
| MM Tunnel | `mm-tunnel` | Muestra incluida completa en 69.09 s. El README documenta 37 campos fallidos en otro catálogo remoto; se conservan como parciales con ubicaciones. |
| Marvs SSH / T20-VPN | `marvs-ssh` | DECODE_FAILED en la muestra de catálogo aportada; archivos .t20 conectados. |
| NetMx VPN | `netmx-vpn` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| OSP Tunnel | `osp-tunnel` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| 1FTunnel | `oneftunnel` | Archivos y enlaces de usuario; no tiene catálogo público propio. |
| PNT VPN | `pnt-vpn` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| PUKANG VPN | `pukang-vpn` | Ruta conectada y muestra local descifrada. |
| Peru VPN | `peru-vpn` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| RA Tunnel Lite | `ra-tunnel` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| REG Tunnel VPN | `reg-tunnel` | DECODE_FAILED en la muestra de catálogo aportada; archivos .reg conectados. |
| RJC Tunnel VPN | `rjc-tunnel-vpn` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| RNV Tunnel VPN | `rnv-tunnel-vpn` | Ruta conectada y muestra local descifrada. |
| RoVPN | `rovpn` | Ruta conectada y muestra local descifrada. |
| SLOW DNS | `slow-dns` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| SNI Tunnel | `sni-tunnel` | Suscripciones del usuario: no hay catálogo público fijo. |
| SN VPN | `sn-vpn` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| S Tunnel | `s-tunnel` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| Shield Tunnel / One Shield Tunnel | `shield-tunnel` | Ruta conectada y muestra local descifrada. |
| Shield VPN | `shield-vpn` | Ruta conectada y muestra local descifrada. |
| Siam VPN | `siam-vpn` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| TRM Tunnel | `trm-tunnel` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| TRP Tunnel | `trp-tunnel` | Ruta conectada y muestra local descifrada. |
| UDP Thunder VPN | `udp-thunder-vpn` | Ruta conectada y muestra local descifrada. |
| V2Box | `v2box` | Suscripciones del usuario: no hay catálogo público fijo. |
| V2OVPN | `v2ovpn` | Ruta conectada y muestra local descifrada. |
| VC VPN | `vc-vpn` | Ruta conectada y muestra local descifrada. |
| VertexSnipher | `vertexsnipher` | El proveedor exige identidad/integridad autorizada no suministrada. |
| XJ VPN | `xj-vpn` | El proveedor exige Play Integrity; no hay token genuino suministrado. |
| XUI Tunnel VPN | `xui-tunnel` | Ruta conectada; sin prueba remota nueva en esta entrega. |
| XtraVPN | `xtravpn` | Necesita una URL custom code; falta entrada de usuario para ese flujo remoto. |
| YLA VPN | `yla-vpn` | La fórmula de firma del proveedor está pendiente en el código aportado. |
| Zam VIP NET / Free VIP Net | `zam-vip-net` | Ruta conectada; sin prueba remota nueva en esta entrega. |
