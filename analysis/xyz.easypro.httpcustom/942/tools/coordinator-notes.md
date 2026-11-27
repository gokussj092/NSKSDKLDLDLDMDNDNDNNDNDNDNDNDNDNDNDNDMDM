# Coordinador — HTTP Custom 8.1.5 (build 942) — notas de verificación

## Verificado por el coordinador (2026-11-23 ~18:00 Tijuana)

### APK
- HTTP_Custom_8.1.5_3_gnhh.apks SHA-256 8d1c0af4b0b442b4d2d291f6a5d0da1d32f43407cded9e54700ef3062ea17ffa (coincide con lo dado por Pedro).
- base.apk 13,316,047 B + split_config.arm64_v8a.apk 29,074,396 B + split_config.xhdpi.apk 40,815 B.
- Manifest (androguard): package xyz.easypro.httpcustom, versionName 8.1.5, versionCode 942, minSdk 32, targetSdk 36, 5 dex.
- Nativas en split arm64: libaio, libandroidx.graphics.path, libcodec (109,872 B), libdatastore_shared_counter, libf2c.so (16,117,312 B), libhev-socks5-tunnel, liblitevpn, libruntime.so (6,927,912 B), libsqlcipher, libtun2socks. Base.apk sin .so.

### Nativo — subagente diff VERIFICADO independientemente
- CORRECCIÓN a mi nota inicial: el salto ~2× de libruntime.so fue 884→934 (3,077,608 → 6,797,136 B). 934→8.1.5 es modesto: libruntime 6,797,136 → 6,927,912 B (+1,92 %, SHA-256 f6a65f69cbb2296e…), libf2c 15,562,432 → 16,117,312 B (+3,57 %, SHA-256 6b65bd27…).
- Etiquetas v12 en libruntime.so: `hc-config-content-v12` y `hc-local-key-capsule-v2` DESAPARECIDAS en 8.1.5 (strings count 0, verificado); solo sobrevive `hc-config-part-v12` (0x277d4). No hay etiquetas v13/v14, ni HCCFG, app-config, n15–n19, libSRPatch, frida ni ro.* en ningún .so (verificado).
- Prestates 899 INNER/OUTER ausentes en 8.1.5 (igual que 934). Tabla K SHA-256 intacta byte a byte (934 0x2a6f8 → 815 0x2a3b0). Blob .rodata en torno al HMAC probable de 934 (0x263e38) reescrito por completo, sin ancla estática.
- Trampa 0x88c: sin equivalente estático visible en 8.1.5 — pero el mismo escaneo da 0 en 934 (donde existe vía despachador VM), así que su ausencia no prueba que haya desaparecido.
- 6 librerías sin cambio (mismo SHA-256): litevpn, hev-socks5, sqlcipher, tun2socks, androidx.path, datastore. libaio.so sí cambia (+220 KB). libcodec/libpolicy se reducen ligeramente.
- Crecimiento explicado por secciones: libruntime casi todo .text (+131,936 B); libf2c repartido .text/.rodata/.bss — VM/datos ofuscados regenerados.
- Implicación: la construcción interior cambió de nuevo vs 934; la rejilla probe_v12* (288 combos con esas etiquetas) queda obsoleta para 8.1.5. Re-localizar HMAC y trampa requiere emulación.
- Entregable subagente C: hc815/work/native-diff.md + .so nuevas en hc815/work/native/.

### Archivos .hc — subagente inventario VERIFICADO independientemente
- Los 3 son HCCFG **b=14 / n19, build 942**, c=s1, d=h1, f=["ssh","profiles"].
  - test_bloqueo_normal_con_contrase_a_0_m46a.hc (4,981 B): h=1 (contraseña Argon2id k=a1, l=2, m=67108864).
  - test_bloqueo_normal_1_aflj.hc (4,935 B): h=0 (sin contraseña pese al nombre "bloqueo"; longitudes de ct idénticas al archivo 1 → mismo perfil con/sin contraseña, observación de longitudes).
  - test_open_2_7xqg.hc (4,529 B): h=0 (open).
- Sobre exterior HCX4-v4 autentica en los 3 (verificado: codec.py::open_envelope abre los 3). Sin cápsula `p`, sin slots HWID `o` en ninguno.
- Decodificador actual (decoders/Python/HTTPCUSTOM.py) rechaza los 3 con `HTTP Custom HCCFG: UNSUPPORTED_SCHEMA` (verificado en test_open_2_7xqg.hc). Solo implementa b=12/n15 y b=10/n11/n12.
- Corrección metodológica (subagente, verificada en su entregable): el método exterior de hc884_decode.py (HKDF-v1/clave V3) solo abre build 884; 934 y 815 autentican con HCX4-v4 del codec del repo (native_fold sello v4).
- Entregables subagente A: hc815/work/hc-inventory.md + hc-inventory.json (incluye inventario de referencia de los 14 archivos 934 de drive/).

### Pendiente (subagentes en curso al 2026-11-23 ~18:00)
- Subagente Java/DEX: jadx de base.apk + diff vs jadx-out 934 (¿nuevo esquema en Java? ¿cambios en HcrNativeCodec/transform?).
- Subagente nativo: diff libruntime.so/libf2c.so nuevas vs 934 (strings, tamaños, hashes, etiquetas hc-config-*-v*).
- Después de ambos: veredicto sobre la KDF interior n19 (¿recuperable por vía estática o bloqueada como n15–n18?) y, si es posible, decodificador actualizado + dossier analysis/xyz.easypro.httpcustom/942/ + notas en http-custom-update/. Sin push ni integración al repo (necesita autorización aparte de Pedro).
- PENDING conocido: contraseña del archivo 1 (no proporcionada por Pedro, no adivinada).
