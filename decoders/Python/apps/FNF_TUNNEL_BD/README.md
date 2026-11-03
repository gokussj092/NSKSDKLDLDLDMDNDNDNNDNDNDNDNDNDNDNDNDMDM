# FNF TUNNEL BD — catálogo Cloud

Paquete `dastan.prince.myvpnksa`, muestra PrinceBuild35 / versionCode35.
Catálogo remoto real82.0: **28 servidores y1193 payloads**. JSON completo
contrastado con Java independiente, CLI y worker aislado el2026-11-03.
Catálogo incluido49.9:22 servidores/1025 payloads, también contrastado.

Desde la raíz del repositorio:

```sh
python decoders/Python/apps/FNF_TUNNEL_BD/server_catalog_decoder.py catalogo.enc > catalogo.json
python decoders/Python/apps/FNF_TUNNEL_BD/server_catalog_decoder.py --stdin < catalogo.enc
python decoders/Python/apps/FNF_TUNNEL_BD/server_catalog_decoder.py > catalogo-remoto.json
```

Sin argumentos se descarga exclusivamente el updater público fijo de la APK.
`run(bytes)` es offline. Solo biblioteca estándar; se reutiliza la primitiva
externa Base64/XXTEA modificado de BD_NET_VPN sin modificarla. **Los campos del
catálogo ya son texto: no aplicar la heurística hexadecimal/XOR de BD NET.**
El JSON se conserva entero, incluidas claves desconocidas. Entradas inválidas,
duplicados, números no finitos y catálogos vacíos se rechazan.

Proveedor `fnf-tunnel-bd`, icono PNG original500×500 sin recodificar. El broker
acepta solamente GET al destino fijo con TLS/DNS público, sin redirecciones ni
URL elegida por el cliente. El agente identifica al broker y no simula un
header especial de la APK. El switch conserva las decisiones del operador.

No se añaden extensiones, enlaces de texto o exportadores. No se modifica
Android, no se esperan compilaciones y no se despliega al VPS. Transporte real
Node del ejecutor: `REMOTE_NETWORK_DENIED`; replay de bytes reales y contrato
completo: aprobado con HTTP explícitamente simulado.

[Expediente obligatorio y scripts](../../../../analysis/dastan.prince.myvpnksa/35/MANIFEST.json),
[reproducción](../../../../analysis/dastan.prince.myvpnksa/35/REPRODUCE.md),
[dependencias](../../../../analysis/dastan.prince.myvpnksa/35/DEPENDENCIES.md).
