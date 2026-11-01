# Enaa y Zig Tunnel: continuidad — 2026-11-01

Orden del propietario: terminar Enaa antes de comenzar Zig.
Goku, rama `fix/http-jireh-current-method`, base160738537d33006e96a2b4f96e980aac3ab25130.
Main sigue5a1c93a4, rama sin fusionar. Sin deploy, Actions ni build Android.

## Enaa Tunnel: método e integración terminados en código

`com.enaa.tunnel`, Enna-1.07/7, original Play/APK confirmado. Fuente nativa
GET `https://strongteam.co/api/wolftunnellite/enaav1.txt`, User-Agent Enaa Tunnel.
**HTTP200 real,4.26,45 servidores/515 redes**. Incluido3.20,28/465.
Método Argon2id v19,3/8192KiB/1/32 y AES256-GCM con salt16 como AAD,
nonce12/tag16; extraer letra índice3 en remoto/.enaa, no en campos EO/DO.
No requiere API key, sesión ni secreto de descarga adicional.

Documentos completos iguales a libsodium/JDK independientes;3555 campos
remotos y3303 incluidos. Worker completo y CLI `--download` real iguales.
9 Python /160 Node aprobadas; transporte Node y HTTP interno simulados.
Egress Node real, Android/VPN física y export .enaa independiente no comprobados.
No writer certificado. Ruta .enaa C8 confirmada por exportador/importador del APK;
C0 sigue240, C8 efectivo255/29 overrides. Catálogo fuente59/56 fichas.
Los cambios de catálogo deben publicarse con aumento de versión efectiva en
el despliegue autorizado; no asumir que editar la fuente invalida cachés del VPS.

Original duradero: **Enaa-Tunnel-Enna-1.07-build7.xapk**,
ID `libfile_ad5ca39c2e2c819184def3a2b6faf031`,53323023bytes, SHA256
`105f5447988349d93c7214e430c13d8a725cbeae6aaf6e74bf1e5d56a6571b5f`.
Catálogo cifrado duradero: Enaa-Tunnel-remote-4.26.enc,
ID `libfile_632a0f92eb0881919291311917b18906`,810149bytes, SHA256
`981ce266f94f10eaed2489401d71ce4ce9415d86bc48a6076e1f0284c4bd37b2`.

Extraer com.enaa.tunnel.apk yconfig.arm64_v8a.apk, luego assets/configfile.json
y lib/arm64-v8a/libgojni.so. Verificar hashes del manifest antes de reanalizar.
No se necesita conservar el entorno temporal para recuperar este método.

Detalles, hashes, campos y pruebas en `decoders/Python/apps/Enaa_Tunnel/`;
verificador `scripts/apk_analysis/enaa_verify.py`, referencias `tests/golden/enaa_*`.
JADX1.5.6:58 errores generales; símbolos y constantes recuperados del Go nativo,
sin ejecutar Android ni JNI. No hay catálogos reales descifrados ni SO en Git.

## Zig Tunnel: siguiente

Paquete solicitado `com.zigtunnel`. Aún no se ha comenzado su investigación
en el punto de cierre de Enaa. No anunciarlo como integrado por esta ficha.
Continuar con original actual, petición completa, descarga real, comparación
independiente e integración, según SERVER_VPN_NEXT_CHAT_GUIDE.md.
90NET permanece pospuesto; las10 reinvestigaciones no se activan por esta entrega.
