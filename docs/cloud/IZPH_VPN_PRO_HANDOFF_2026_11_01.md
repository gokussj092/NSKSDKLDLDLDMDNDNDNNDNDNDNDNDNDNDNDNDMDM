# IZPH VPN PRO: recuperación y estado de integración

Fecha **2026-11-01**, cuenta Goku, repo
`gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`.
Rama `fix/http-jireh-current-method`, base **799a523b**. Main sigue 5a1c93a4;
la rama no se ha fusionado. Mantener revisión fuente **59**, ahora **54 fichas**,
por la instrucción del propietario para el lote sin desplegar. No fusionar,
desplegar, compilar Android ni lanzar Actions; commit `[skip ci]`.

## Regla incorporada a la guía

`SERVER_VPN_NEXT_CHAT_GUIDE.md` ahora exige reproducir la petición completa de
la app, incluidas cabeceras, autorización, claves o firmas necesarias, en código
o secretos del backend. Una descarga real correcta y descifrado completo son
obligatorios antes de validar una integración. Mocks/assets no bastan.
Si una app descarga y el script no, investigar la diferencia; no declarar una
fuente caída por un404 anónimo. Documentar y probar la provisión de secretos
para el despliegue, manteniendo sus valores fuera de Git/logs/clientes.
El README de herramientas enlaza la regla y el prompt reutilizable usa Goku.

## Resultado actual

IZPH VPN PRO `com.izphprov2.net`, **6.0 /build60**, versión vigente del HTML
de Google Play y del APK descargado. Las páginas indexadas de 5.9 eran antiguas.
Firma SHA1 b54eb2646f84cafdab35d6c55bd7e01608cdd43d.

Actualizador **`IZPHPROMain.V()`**:
`https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/izph49`.
StringRequest GET sin cabeceras personalizadas ni Authorization; no requiere
secreto de descarga. Se reutiliza esa URL exacta aunque termine49.
HTTP200 real: **3234 /84 servidores /303 redes**,480620bytes,
SHA256 **40e2155da7be0d23bf54fedc239b4cb3adfd2f4dd103dffa3bb8944c0241269e**.
CLI descarga real adicional igual al documento completo.

Incluido `R.raw.g`/servers/0x7f110006 → ARSC `res/ae/e.rj`:
**1000.0.1208 /60 servidores /110 redes**,279596bytes.
Ambos JSON completos iguales a JCA, Python, CLI y worker aislado.
**6 casos nativos por muestra**, más uno sintético de cero final,13 en total.
Respuesta real completa del worker validada por gateway con HTTP interno
simulado; no se afirma egress Node real ni sesión VPN Android.

## Método y código

Carpeta `decoders/Python/apps/IZPH_VPN_PRO/`; reutiliza `izph.py`.
AES128CBC/XXTEA/restar2, Threefish256(tweak i,64*i)/AES128CBC,
PBKDF2/XXTEA/AES256CBC con IV prefijado. Constantes históricas confirmadas
en el SO; AES1 HKDF salt16, Threefish HKDF salt32, PBKDF2 100000.
Seed0x27d878,IV0x27d898,salt0x27d858/0x27d9d0.
Dispatch JNI0x4beb8c; special0x4bdf6c; sensitive0x4be414.
XXTEA0x4c0d68, ThreefishSetKey0x4c408c, decryptWords0x4c4350.

Se corrigió el orden inverso Threefish histórico (permutar antes de MIX),
el recorte de ceros legítimos de ciphertext y se añadió SSCommand al mapa
histórico de red. Sin modificar Android ni inventar formatos.
El nuevo lector solo abre campos confirmados y rechaza todo el documento si
falla uno conocido; conserva desconocidos, estructuras y placeholders.
No autentica cambios intencionales: estos formatos no tienen MAC.

Broker fijo `izph-vpn-pro`, ficha, icono original y switch persistente.
DNS/TLS y redirecciones restringidos; no URLs/credenciales del cliente, ni
secreto de VIP enviado a IZPH. Worker offline por allowlist y contrato C3.
C0 **240**, C8 **254**, overrides **28** intactos. Rutas históricas
`.izph`/`izph://` conservadas; no export real del build 60 certificado.

## Pruebas y originales duraderos

**22 Python /152 Node aprobadas, sin skips**,13 casos nativos. Grupos,
métricas/hashes y límites en README/TESTING/manifest de la app.
JADX1.5.6 fijado:33 errores generales; LSParanoid `fo.a`, campo a,
estado c1.q:2070 literales/95 fuentes/2280 cadenas.

- **IZPH-VPN-PRO-6.0-build60.xapk**, ID
  **`libfile_a15ccafb31208191a0160f6bbcbbc6d0`**,70977739bytes,
  SHA256 **202e41a764200958803af9ef95a62f6d0737bad7848c09fb116a449025e87b64**.
- **remote.enc**, ID **`libfile_7adc7c99a8c08191afcdd165d30c128d`**,
  480620bytes,SHA256 remoto indicado arriba. Solo copia cifrada duradera.
- APK base SHA256127e4124714108d56b1eb20d9cc61ea69eb5f3cf01ac9f76ca8c8f8c27d8d4c7.
- SO SHA2563c6ad15db5484317c557ae1c1935b102f264c86420552cd53d449045a09ca8c5.
- PNG `res/h/cd.png`,512×512,156041bytes,
  SHA25666ba9cb37ebf9c2ec8ea71bff78be16b886c794b2c13c9f6d40d9c36bb1442cb;
  copias exactas en app e icono público, sin conversión.

Tras limpieza recuperar la rama y los originales por esos IDs. Extraer el APK
base y config.arm64_v8a.apk del XAPK; luego catálogo, PNG y libovpn3.so por
sus rutas. Verificar hashes antes de analizar. Recrear requirements/JDK.
`decompile.py` y `paranoid_strings.py` con
`--chunk-field a --method a --call-class fo --inventory` recuperan las cadenas.
`izph_verify.py incluido.enc remoto.enc --native libovpn3.so --runtime`
compara todo el documento e imprime solo métricas/hashes.
Referencias: `tests/golden/izph_oracle.java`, `izph_native_oracle.py`,
`izph_vectors.json`. Fuentes y vectores sintéticos en Git; binarios, inventarios
y catálogos reales fuera de Git. Ninguna copia descifrada duradera.
90NET permanece pospuesto por instrucción del usuario.
