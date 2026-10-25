# Evidencia MNR TUNNEL PLUS

APKS aportado por el usuario; análisis 2026-10-24, PR #99 sobre `b8168cc`.
Identidad: `com.hamo.vpn`, versionName 3.1, versionCode 31. JADX 1.5.6 fijado
por checksum: **49 errores generales**, sin afirmar descompilación total.
No se ejecutó el APK, Pairip o bibliotecas nativas para abrir los formatos.

| Entrada | Bytes | SHA-256 |
|---|---:|---|
| MNR TUNNEL PLUS_3.1.apks | 42674652 | `2d90fd6bae6ddc4e669593a48718b25c2e3afb14d6c3d0ec0b67f0770a4d67ff` |
| base.apk | 20240223 | `6e567895ed16fc934de8457316fa4df4cafae44ca1fe8e7c434fecce58fb9330` |
| classes.dex | 8684812 | `9ef7d3a9591cc5a3f6050b380e80a54812e9d0880c54595bcdc7f5c42d3bea90` |
| assets/config/config.json | 1239212 | `3be5ee04c92498d674112929d00b4f77303e7a5c06635eac47e52670ba65d885` |
| GET plusfast | 1394761 | `02e1fa450980e693dc4a858433908dd0bb8f2d3ece026549972e55de0b4585ac` |
| res/drawable/logo.png | 72125 | `ed99d8abdfbbcdd58c0a016d54299440d64c39608dd225674c0291f85d219b1a` |

Icono original 225×225, inspeccionado y copiado sin recomprimir. Dice MNR
TUNNEL PRO aunque el nombre declarado sea PLUS; no se rediseña ni sustituye.
Binarios, catálogos y resultados reales fuera de Git.

## Catálogos

`F5.b.b()` lee Config.json privado o assets/config/config.json y llama a
`F5.a.b("devpro", ...)`; listas Servers/Networks. `vagol.Updater` fija el GET
plusfast. `p165x5.P.onUpdateListener` abre el mismo método, compara Version y
guarda Config.json. plusfastapp es el actualizador APK, no este catálogo.
GET real HTTP 200 con agente descriptivo del broker `MNR TUNNEL PLUS/3.1`;
no se presenta ese agente como una constante recuperada del actualizador.

`F5.a` recupera el alfabeto Base64 literal que produce
`¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′`. Pares de índices nibbles → bytes Base64 → AES-CBC,
IV 16 ceros y PKCS7. La clave SHA256 recibe el hexadecimal mayúsculo UTF-8
de la constante, no la constante directamente ni su MD5. Métodos b/c son
descifrado/cifrado. Mismo exterior para perfiles, constante `demondevs`.

`F5.g`: alfabeto de p072k4.c(3).toString y clave de G4.f(4).toString.
Cada byte sale de `(int >>> shift) & 255`. `A.i.e` convierte bytes truncados
822→54 y 4791865→57 en "69"; desplazamiento Java **69 & 31 = 5**.
48 bytes UTF-8 producen U+2000..U+200F; 31 bytes producen
`❤️🧑‍💻Bøbõ⁰⁰!!`. `mnr_constants.py` reproduce exactamente esa recuperación.
No descartar ni normalizar el whitespace del alfabeto.

Consumidores MainActivity (selección de servidor/red, `w` para MNR DNS) y
p165x5.C2684y identifican nueve campos de Servers y doce opcionales de
Networks, enumerados en codec.py y de forma independiente en mnr_verify.py.
Incluyen PREFIX, DNS_RESOLVER_MANUAL, v2Address/v2Host/v2SNI y udpIP/Obfs/Auth.
No confundir los booleanos wsPayload/wsProxyPayload con campos cifrados.

Asset **1.0, 9/112, 537 campos** y remoto **14.4, 14/119, 612 campos**.
Ambos JSON completos son iguales a JDK y worker, incluidas estructuras
desconocidas. Salidas normalizadas 69267 y 76580 bytes. La CLI autónoma hizo
otro GET y guardó exactamente el documento remoto capturado en archivo 0600.

## Archivo, portapapeles y contraseña

Manifiesto de MainActivity admite `.stp`; ExportActivity.e escribe ese sufijo.
G5.f.onClick crea el JSON moderno, F5.a.c("demondevs", ...), y permite archivo
o copiar el mismo ciphertext al portapapeles, sin prefijo añadido. MainActivity
onActivityResult, intención y menú clipboard llaman a F(ciphertext).

Dalvik conservado en privado con dex_method.py: **G5.f.onClick 200
instrucciones**, **MainActivity.F 151**, **G5.k.onClick 168**. F descifra antes
de JSONObject/optBoolean(isPassON) y del diálogo. p165x5.J compara la entrada
con MyPass del objeto ya abierto. Fecha/HWID también posteriores. Se conservan
restricciones y password; no se modifica el importador original ni se evita
su validación al conectar. Dos perfiles sintéticos local/cloud completos
contrastados con JDK, worker archivo/texto, CLI y script fuera del repo.

ConfigParser conserva otro código `.sft`, Properties XML y Cryptor con
fubvx788b46v/PBKDF2/GCM, y la constante MAFFIAH no usada en ese decodeInput.
No se identificó una llamada de interfaz hacia ese import/export en este APK;
no se registra `.sft` ni se extrapola el DES por la constante inerte.

## Online

ExportActivity.d crea mnrtunneludp:// + diez caracteres de [0-9A-Za-z], y llama
FirebaseStorage.child(reference + ".sky"). G5.h cifra JSON con nombres de
campos diferentes a G5.f; se retiene su forma, sin renombrar credenciales.
G5.k.onClick recibe el texto y consulta getDownloadUrl. El callback p165x5.D
entrega su URL a F5.e, que hace GET y llama MainActivity.F sobre la respuesta.

Recurso google_storage_bucket: `hamovpn.firebasestorage.app`. SDK
com.google.firebase.storage.e.a → p124r4.u0.l quita segmentos vacíos entre
slashes: objeto **mnrtunneludp:/ID.sky**, no // ni ID.sky a secas. W2.e genera
`https://firebasestorage.googleapis.com/v0/b/<bucket>/o/<objeto codificado>`.
C2.b obtiene downloadTokens, usa el primer token separado por coma y añade
alt=media/token. Broker y CLI reproducen esos dos GET, sin listado ni subida.
Aceptar un ID solo en la API dedicada/CLI es una normalización explícita al
prefijo del exportador; texto genérico exige el enlace completo.

Se reutiliza transporte C3.5 con destino/path/query estrictos, sesión, cuota,
DNS pública fijada, TLS y ningún redirect. POST /decode/import/mnr exige
reference/consent:true; POST /decode/text resuelve el enlace como acción de
importación. Interruptor mnr-tunnel-plus gobierna catálogo/online; archivo y
clipboard locales no requieren red. Worker no recibe URLs ni hace red.
Bot usa el mismo normalizador/lector y evita registrar excepciones HTTP que
pudieran contener un token. Métricas guardan solo formato/recuentos/latencia.

**No se aportó referencia online real ni export `.stp` real.** Código original
y pruebas sintéticas verifican el flujo completo del broker, pero acceso
Firebase/permisos actuales siguen pendientes. No se prueban IDs inventados,
no se lista almacenamiento ni se obtienen claves Firebase de autenticación.
Los flujos de autorización del túnel/temporizador no son importación de perfil
y no se contactan. No se modifican firma o comprobaciones JNI.

CloudTextFormats en Android incorpora solamente reconocimiento del enlace
ID10 y del alfabeto clipboard: sin claves, URL de bucket o descifrado local.
MainActivity conserva su flujo existente, diseño e inventario offline.
Se añadió caso instrumentado; ejecución en dispositivo pendiente. Los cuatro
gates Python de enrutamiento cliente aprobaron; no equivalen a prueba en móvil.

Registro: C0 240 intacto, C8 254 / 26 overrides, mínimo 46 / 46 fichas. STP
Cloud, sin nuevo soporte offline Android. Sin fusión, despliegue, APK o C11.
