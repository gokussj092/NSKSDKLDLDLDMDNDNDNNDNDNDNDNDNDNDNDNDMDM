# AM TUNNEL LITE VPN — AM, build 63

**Estado: integración pendiente. No hay un decodificador completo de catálogo
ni un proveedor Cloud habilitado para esta muestra.** La ficha conserva el PNG
original, con `remote:null` y `decodeEnabled:false`. Un auxiliar de campos no
sustituye la lectura del catálogo.

Paquete `app.vpn.amtunnellite`; PR #96, misma rama de las demás integraciones.
Catálogo público mínimo **34 / 36 fichas**, respetando la versión persistente y
los switches. La entrega no fusiona ni despliega ni publica novedades C11.

## Qué está comprobado

- `libputils.so`: `PUtils.pDecrypt` convierte hexadecimal a bytes y aplica
  `xorWithKey` con una clave cíclica de 12 bytes; construye el resultado con
  JNI `NewStringUTF`. `field_decoder.py` reproduce ese formato y su UTF-8
  modificado (unidades UTF-16, NUL `C0 80`, pares sustitutos para emoji).
- **8 vectores sintéticos** coinciden con JDK independiente y con la primitiva
  XOR ARM64 original. **4 pruebas Python y 43 web** aprobadas. La comparación
  nativa ejecuta solo XOR y modela la copia de `std::string`; no ejecuta JNI,
  inicio de aplicación, controles de firma, Android ni llamadas al sistema.
- Icono PNG original exacto: `res/drawable/ic_app_icon.png`, **479×440,
  30105 bytes**. No se redibuja ni redimensiona.
- `assets/pdrv2.json`: **156216 bytes**, Base64 estricto de **117160 bytes**.
  La capa exterior sigue sin recuperar; no se conoce aún el número de
  servidores, redes o campos del documento. No se inventan esos recuentos.
- Hay **1000 recursos `assets/wg/am*.conf`**, 132570 bytes en total. Son textos
  con `Endpoint`, `Hash1` y `Hash2`; no son un catálogo remoto validado y no se
  incorporan sus valores al repositorio.
- LSParanoid: **203 literales resueltos en 21 archivos / 1039 cadenas de
  inventario** del DEX 2. El núcleo de la aplicación permanece protegido por
  LIAPP. JADX reportó 30 errores en DEX 1 y terminó con éxito en DEX 2.

## Alcance del auxiliar

```bash
python field_decoder.py campo-hexadecimal.txt
python field_decoder.py < campo-hexadecimal.txt
```

Expone `run(data: bytes) -> str` y devuelve `{"field":"valor"}`. Su entrada
es un campo PUtils explícito, no el APKS, un perfil exportado o `pdrv2.json`.
No recorre un JSON con heurísticas ni atribuye a campos desconocidos un método
sin inspeccionar sus consumidores. La clave es material del formato de esta
muestra, no una credencial de acceso a servicios.

No se ha confirmado una extensión exportada ni un esquema de enlace. No se
registra `.am`, no se modifica el inventario C0 ni se añade una ruta de worker
que devuelva un éxito parcial. `requirements.txt` indica el runtime del auxiliar;
las dependencias de análisis son independientes.

## Fuente remota y pendiente real

El inventario del APK contiene dos veces el enlace:

`https://freedomnavigate.com/updater/8112011e98856d3ca814d0f8ce3231`

La consulta HTTPS GET del 2026-10-22, con TLS y redirecciones rechazadas, agotó
el tiempo de espera. No se obtuvo un status HTTP ni un cuerpo validado. El
camino Java que lo consume sigue protegido: es un enlace extraído del APK,
no una fuente habilitada en el broker. No se probaron destinos alternativos,
cuentas, sesiones ni credenciales de servicio.

Falta recuperar la clase que abre el sobre exterior, contrastar todos los
campos y su esquema con una referencia independiente, y validar una respuesta
remota completa. Solo después corresponde conectar worker/broker/control y
habilitar `remote`. **No usar la ficha como anuncio de soporte terminado.**

## Herramientas conservadas

- `scripts/apk_analysis/`: preparación, JADX fijado por checksum, LSParanoid,
  ELF y emulación limitada; `liapp_wrapper.py` recupera exclusivamente la
  primera capa nativa del wrapper de este build.
- `tests/golden/am_tunnel_lite*`: fuente JDK, generador, vectores sintéticos y
  oracle de la primitiva XOR original.
- [ANALYSIS.md](ANALYSIS.md): hashes, direcciones y puntos concretos para
  continuar. [TESTING.md](TESTING.md): resultados y comandos.
- `scripts/apk_analysis/RESTORE.md`: recuperación del entorno desde el PR.

El wrapper recuperado sigue siendo el protector, no el DEX original ni el
lector de catálogo. APK/SO, inventarios de cadenas, textos de WireGuard,
catálogos reales y resultados privados permanecen fuera de Git.
