# Diff nativo HTTP Custom 8.1.5 vs 8.0.22 Patch 2 (build 934) — análisis estático

- Fecha: 2026-11-23. Solo lectura / análisis estático. Sin modificaciones al repo, sin push, sin emulación Unicorn.
- Nueva APK: `~/workspace/http-custom-update/hc815/work/apks/split_config.arm64_v8a.apk`
  (versión `8.1.5` confirmada en `base.apk` → `AndroidManifest.xml`, strings UTF-16).
- Baseline 934: `.so` extraídos en `~/workspace/http-custom-update/apk/arm64/lib/arm64-v8a/`
  (verificado: los 11 `.so` están presentes; baseline completa, no hizo falta recurrir al `.apks` original).
- Nuevas `.so` extraídas a: `~/workspace/http-custom-update/hc815/work/native/`
- Herramientas: `strings -a`, `readelf`, Python (`~/workspace/http-custom-update/venv/bin/python`, capstone).

## 1. Tabla de tamaños y SHA-256

| Librería | 934 tamaño (B) | 8.1.5 tamaño (B) | Δ | SHA-256 934 | SHA-256 8.1.5 |
|---|---|---|---|---|---|
| `libruntime.so` | 6 797 136 | 6 927 912 | **+130 776 (+1,92 %)** | `06cf083434ca2df73b00940faecd1053605222566fb6dac8fbe3ee6ce4665785` | `f6a65f69cbb2296ec74d56e75a14a5e46b4bf8ca6db9e2081526919793c9568c` |
| `libf2c.so` | 15 562 432 | 16 117 312 | **+554 880 (+3,57 %)** | `bc2262ec53b4f4312341bc2eca3dbe1ec826834fc98768c1e2b1acbc34d15308` | `6b65bd2785395af8cd78130e2f54367314fe7aa49a0ea76252e44850de6f7e10` |
| `libcodec.so` | 114 504 | 109 872 | −4 632 (−4,05 %) | `f0ea17c7f0885c3f125dc6cbd11502d318db6ecc76dd91c672bfab0312f21737` | `9631ae440271335c6cd9049f55ecd06f9888a780a496a890ab5e29f8dd3755d4` |
| `libpolicy.so` | 236 696 | 230 648 | −6 048 (−2,56 %) | `ab87a6dc104834005bbf1273eccc3bfef64d0b6c7d9e1c7e90d614e190d90361` | `1f4b838a224ca388429ac913c7256b9d4c752e6f01b7ff9dda1ccda9c5d4efac` |
| `liblitevpn.so` | 6 775 184 | 6 775 184 | 0 | `f11f2b0c0e6d6c70a631e466da3a6016184910ffd64764526809ccb04602cabe` | idéntico (mismo hash) |
| `libhev-socks5-tunnel.so` | 333 320 | 333 320 | 0 | `b0cf8b2bfe34f23c8c0bbd231ee5eb864c541880edfa329612a91a2f152a1ead` | idéntico |
| `libsqlcipher.so` | 2 275 368 | 2 275 368 | 0 | `ca99ae45fa24be140a77c7bfd1728b282f4f2b8798fde4ed51821f89022b15ee` | idéntico |
| `libtun2socks.so` | 203 584 | 203 584 | 0 | `fe2e9d5ab7671996b28d481236791ad3c5d55fb8580cad322f723716693ef131` | idéntico |
| `libaio.so` | 42 633 928 | 42 854 056 | +220 128 (+0,52 %) | `28f0452a88d0e92619bce6ff83da9e87e11a954243311b6497e705ae8e5cfa0e` | `feb0204ca94a2e74220629ed362a76e54dd0b975ea9d2de9f22b35ac6bc6ae6a` |
| `libandroidx.graphics.path.so` | 10 096 | 10 096 | 0 | `41e9a793c43a0f4fddb19e33f346bace464f30f888ba7b9eaf96294ea115bfb6` | idéntico |
| `libdatastore_shared_counter.so` | 7 784 | 7 784 | 0 | `178f89a2c6c9234ddf980dd4cd1f3616186a46b2b932aafa6707abd04c5fd76a` | idéntico |

**Corrección a la premisa de la tarea:** el salto ~2× de `libruntime.so` NO es de 8.1.5.
Verificado: 884 = 3 077 608 B (`hc884/work/native/lib/arm64-v8a/libruntime.so`),
934 = 6 797 136 B, 8.1.5 = 6 927 912 B. El crecimiento ~2,2× ocurrió entre 884 y 934;
entre 934 y 8.1.5 el crecimiento es modesto (+1,92 % en `libruntime.so`, +3,57 % en `libf2c.so`).

## 2. Strings: etiquetas cripto/config

Búsqueda `strings -a` (mín. 4 caracteres) con patrones
`hc-config`, `hc-local-key`, `HCCFG`, `app-config`, `n15`–`n20`, `v13`/`v14`,
`libSRPatch`, `frida`, `ro.*`, `HKDF`/`HMAC`/`ChaCha`/`AES`, `capsule`,
`dev/epro`, `transform`, `HcrNativeCodec`, `JNI_OnLoad`.

### 2.1 `libruntime.so` — el hallazgo principal

| Etiqueta | 934 (offset) | 8.1.5 (offset) | Estado |
|---|---|---|---|
| `hc-config-content-v12` | `0x27ae0` | — | **DESAPARECIDA** |
| `hc-config-part-v12` | `0x27af6` | `0x277d4` | presente (desplazada −0x322) |
| `hc-local-key-capsule-v2` | `0x27b09` | — | **DESAPARECIDA** |
| `hc-config-*-v13` / `v14` | — | — | **NO EXISTEN** en ninguna de las dos |
| `HCCFG` / `app-config` / `n15`–`n19` | — | — | ausentes en ambas |
| `libSRPatch` / `frida` / `ro.*` | — | — | ausentes en ambas |

- En 8.1.5 la zona `0x27ae0` (donde estaba `hc-config-content-v12` en 934) ya no
  contiene texto: son bytes sin estructura legible (p. ej. `00 b7 8c 46 00…`,
  `00 3b e1 fe 00…`), y lo mismo ocurre en todo el entorno `0x27700–0x27b20`.
  La región `.rodata` que alojaba las tres etiquetas fue reescrita/re-cifrada,
  no solo desplazada.
- En 934 las tres etiquetas estaban contiguas (`0x27ae0`, `0x27af6`, `0x27b09`);
  en 8.1.5 solo sobrevive `hc-config-part-v12` en `0x277d4`, rodeada de bytes
  sin estructura (`0x277b4: 'W2]p'`, `0x277cf: '%O{]'`, `0x27804: '<a#d'`, …).
- No hay ninguna referencia por puntero a estas etiquetas en el fichero
  (búsqueda de su dirección como u32/u64 LE: 0 ocurrencias en ambas versiones),
  igual que en 934 — se resuelven por índice/VM, no por xref estático.
- Totales de strings: 934 = 12 983, 8.1.5 = 12 512 (2 941 nuevas / 3 070 desaparecidas
  por valor, pero casi todas son fragmentos aleatorios de datos ofuscados; las únicas
  con significado cripto son las dos etiquetas desaparecidas de la tabla).

### 2.2 `libf2c.so`

- Sin etiquetas `hc-*`, `HCCFG`, `n15`–`n19`, `frida`, `libSRPatch` ni `ro.*` en
  ninguna de las dos versiones. Únicos aciertos de palabra clave en ambas:
  `JNI_OnLoad` (offset `0x957` en las dos) y el nombre RTTI
  `N10__cxxabiv120__si_class_type_infoE` (934 `0x89c47d` → 8.1.5 `0x8e3a6d`).
- Churn enorme de strings (37 533 nuevas / 25 822 desaparecidas por valor) pero
  son fragmentos aleatorios de un blob ofuscado/cifrado, no texto semántico:
  el diff de strings no aporta señal cripto en este `.so`.

### 2.3 `libcodec.so` y `libpolicy.so`

- Sin aciertos de palabra clave salvo `JNI_OnLoad` (`0x48f` en `libcodec.so`,
  `0x633` en `libpolicy.so`, mismo offset en ambas versiones).
- Las strings nuevas/desaparecidas con longitud ≥ 8 son todas basura ofuscada
  (p. ej. `libcodec.so` nueva `0x32ca: '@98 @95$@97(@94,@9>0@9:4@9$8@9h.'`,
  desaparecida `0x331a` casi idéntica; `libpolicy.so` nueva `0x788e` /
  desaparecida `0x7a3a` con el mismo patrón `@9…`). Sin señal semántica.

## 3. Estructura ELF y símbolos

- Ambas versiones, en los 4 `.so`: `stripped`, sin `.symtab`. El único símbolo
  definido en `.dynsym` es `JNI_OnLoad` (el resto son `UND` de libc); `.dynsym`
  y `.dynstr` tienen tamaño idéntico entre versiones en cada `.so`.
- `JNI_OnLoad` (`libruntime.so`): 934 en `0x966dc`, tamaño `0x3eb4c` (257 356 B)
  → 8.1.5 en `0x97428`, tamaño `0x45164` (282 980 B): **+26 136 B (+10,2 %)**.
- `JNI_OnLoad` (`libf2c.so`): 934 en `0xdccc3c`, tamaño 58 696 B
  → 8.1.5 en `0xe57a58`, tamaño 43 584 B: **−15 112 B** (a pesar de que el `.text`
  total de `libf2c.so` crece; los límites de función se desplazaron).
- `libf2c.so` Build ID (`.note.gnu.build-id`): 934 `bab40d0eaed1e65610cd95841ead9d49d704f056`
  → 8.1.5 `c4ce7626a3d0645e62140256a21267bb4b5cddce` (build distinto, como era de esperar).
- `.note.android.ident` idéntica en ambas versiones y en ambos `.so`
  (misma huella de toolchain/NDK: datos `…3134323036383635` = `"14206865"`).
- Lista de natives registrados (`dev/epro/r0/V3304767868710853915`, `transform`,
  `fold`, firmas `([B[B[B[B)[B`, `([B[BIJ)[B`): **no extraíble estáticamente en
  ninguna de las dos versiones** — búsqueda raw de `V3304767868710853915`,
  `dev/epro`, `transform`, `fold` y las firmas: AUSENTE en 934 y en 8.1.5.
  (En 884 esa lista solo se obtuvo por emulación de `JNI_OnLoad`, no por strings.)

## 4. Prestates 899 (INNER/OUTER)

Forma conocida (`spdecode/decoders/Python/apps/HTTP_Custom/crypto.py`):
`INNER_STATE = (0x82515a9a, 0xf6ec05fc, 0xf650b6cd, 0x523f8ce6, 0xedf419ec, 0x1d6d6573, 0x66ff1b89, 0xf40a0181)`,
`OUTER_STATE = (0x82185b01, 0x35cb48be, 0xdb6c3846, 0xbd714ec5, 0x627728af, 0xdbaae4db, 0x463fbf8d, 0x88a24381)`.

- Búsqueda de los 32 B completos, little-endian y big-endian, en `libruntime.so`
  y `libf2c.so`, 934 y 8.1.5: **AUSENTE en los 4 casos** (igual que en 934).
- Búsqueda de la primera palabra de cada estado (LE y BE): 0 ocurrencias en los 4 casos.
- Conclusión: los prestates 899 siguen sin estar presentes como constantes
  en el binario de 8.1.5; si existen, están derivados en runtime o cifrados
  (igual que en 934).

## 5. Trampa 0x88c / pánico

- Desensamblado completo de `.text` con capstone (rango correcto verificado
  con `readelf -SW`): **0 instrucciones con el inmediato `0x88c` en
  `libruntime.so` de 934 y 0 en 8.1.5**.
- Búsqueda raw de la codificación `MOVZ`/`MOVK` con inmediato `0x88c` para
  cualquier registro (w/x, `0xD2800000`/`0x92800000`/`0xF2800000` base):
  **0 ocurrencias en ambas versiones**.
- El valor u32 LE `0x0000088c` aparece 1 vez en el fichero 934 (offset `0x3339`)
  y 0 veces en 8.1.5; la ocurrencia de 934 cae en zona de `udf`/relleno
  (`0x3330: udf #0x403`, `0x3334: udf #0`), no es un inmediato real.
- **No hay equivalente estático visible de la trampa 0x88c en 8.1.5.**
  Nota: el mismo escaneo da 0 en 934, donde la trampa está documentada como
  bloque `0x1d4444` alcanzado vía el despachador VM en emulación — es decir,
  la trampa no es visible como inmediato estático ni siquiera en 934, así que
  su ausencia estática en 8.1.5 **no** prueba que haya desaparecido; solo que
  no se puede localizar sin emulación. No se afirma equivalencia.

## 6. HMAC / hash prominente

- Tabla de constantes SHA-256 (K, primer word LE `0x428a2f98`): presente en
  ambas versiones, **256 B idénticos byte a byte** — 934 en `0x2a6f8`,
  8.1.5 en `0x2a3b0` (desplazamiento −0x348). El motor SHA-256 sigue ahí.
- Región del HMAC probable de 934 (`libruntime.so` `0x263e38`, en `.rodata`):
  los bytes **difieren por completo** entre versiones (934 `ab031db82b394039…`
  vs 8.1.5 `ae835ab84a010c4a…`; primer byte distinto ya en `0x263e00`).
  La zona es un blob ofuscado/cifrado con patrones repetidos distintos
  (934 repite `0394`, 8.1.5 repite `0b`/`094a`), compatible con re-cifrado
  por build con keystream distinto. **No se puede afirmar que el HMAC se
  haya movido ni que siga en `0x263e38`**: sin emulación no hay ancla
  (no hay llamadores directos ni símbolo). Ningún HMAC/hash nuevo
  prominente y nombrable aparece en strings.

## 7. Explicación del crecimiento (secciones)

### `libruntime.so` (+130 776 B total)

| Sección | 934 (B) | 8.1.5 (B) | Δ |
|---|---|---|---|
| `.text` | 6 552 832 | 6 684 768 | **+131 936 (+2,01 %)** |
| `.rodata` | 18 344 | 18 720 | +376 |
| `.data` | 11 392 | 11 467 | +75 |
| `.data.rel.ro` | 47 288 | 46 888 | −400 |
| `.init_array` | 3 232 | 3 248 | +16 (2 entradas más) |
| `.rela.dyn` | 150 024 | 148 800 | −1 224 |
| `.bss` | 4 440 | 4 664 | +224 |

El crecimiento es **casi íntegramente código** (`.text` +131 936 B ≈ el Δ total);
`.rodata`/`.data` apenas cambian. No hay datos embebidos nuevos de tamaño
relevante: es más código nativo (o código re-generado/ofuscado más grande),
no un blob nuevo.

### `libf2c.so` (+554 880 B total)

| Sección | 934 (B) | 8.1.5 (B) | Δ |
|---|---|---|---|
| `.text` | 4 858 284 | 5 047 268 | **+188 984** |
| `.rodata` | 8 469 420 | 8 738 316 | **+268 896** |
| `.eh_frame` | 1 081 828 | 1 129 832 | +48 004 |
| `.eh_frame_hdr` | 173 236 | 180 996 | +7 760 |
| `.data.rel.ro` | 334 440 | 349 104 | +14 664 |
| `.rela.dyn` | 561 312 | 584 760 | +23 448 |
| `.init_array` | 11 000 | 11 400 | +400 (50 entradas más) |
| `.data` | 62 960 | 65 712 | +2 752 |
| `.bss` | 4 699 024 | 4 883 200 | +184 176 |

Aquí el crecimiento se reparte entre código (`.text` +189 KB) y datos
embebidos (`.rodata` +269 KB, `.bss` +184 KB): coherente con una VM/datos
ofuscados regenerados y más grandes, no con un cambio puntual.

### `libcodec.so` / `libpolicy.so`

`.text` −4 528 B / −5 744 B respectivamente; `.rodata` −8 B / −1 B.
Rebuild menor, sin señal cripto.

## 8. Conclusiones

1. **Propuesto → verificado:** el salto ~2× de `libruntime.so` es 884→934,
   no 934→8.1.5. Entre 934 y 8.1.5 el nativo crece poco (+1,9 % / +3,6 %).
2. **Cambio cripto real y verificable:** en `libruntime.so` desaparecen dos
   de las tres etiquetas v12 — `hc-config-content-v12` (`0x27ae0`) y
   `hc-local-key-capsule-v2` (`0x27b09`) — y solo sobrevive
   `hc-config-part-v12` (`0x277d4`). No aparece ninguna etiqueta `v13`/`v14`
   ni `n15`–`n19` en ningún `.so`.
3. **Implicación para la KDF interior:** la construcción interior cambió de
   nuevo respecto a 934. Si en 934 la KDF usaba (o referenciaba) las etiquetas
   de contenido y cápsula, en 8.1.5 esas etiquetas ya no existen como
   literales: o la KDF interior usa otras etiquetas (no literales / cifradas),
   o el esquema de cápsula/contenido fue sustituido. La rejilla de 934
   (`probe_v12*.py`, 288 combinaciones con esas etiquetas) queda obsoleta
   como hipótesis para 8.1.5: hay que re-derivar el transcript/semilla desde
   cero y no asumir que `hc-config-content-v12` / `hc-local-key-capsule-v2`
   participen. Lo único que se conserva literalmente es `hc-config-part-v12`.
4. Los prestates 899 siguen ausentes (LE/BE, 32 B completos y primera palabra)
   en `libruntime.so` y `libf2c.so` de 8.1.5, como en 934.
5. La tabla K de SHA-256 está intacta (256 B idénticos); el blob `.rodata`
   en torno al HMAC probable de 934 (`0x263e38`) está completamente reescrito,
   sin ancla estática para re-localizar el HMAC.
6. La trampa 0x88c no es localizable estáticamente en 8.1.5 (tampoco lo era
   en 934 por este método); no se puede afirmar que siga o que haya desaparecido.
7. `JNI_OnLoad` de `libruntime.so` crece un 10,2 % (+26 136 B); el de
   `libf2c.so` se reduce (−15 112 B). La lista de natives no es extraíble
   estáticamente en ninguna versión.
8. Seis librerías no cambian en absoluto (mismo SHA-256): `liblitevpn.so`,
   `libhev-socks5-tunnel.so`, `libsqlcipher.so`, `libtun2socks.so`,
   `libandroidx.graphics.path.so`, `libdatastore_shared_counter.so`.
   `libaio.so` sí cambia (+220 128 B, hash distinto).

## 9. Pendiente (fuera del alcance estático)

- Re-localizar el HMAC y la trampa equivalente requiere emulación de
  `JNI_OnLoad` + `transform`/`fold` (camino del expediente 934/884), que
  coordina otro trabajo; estáticamente no hay ancla.
- Verificar si los `.hc` de 8.1.5 siguen en esquema n15–n18 o suben de
  versión, y si el sobre exterior sigue autenticando con `native_fold` de 899.
