# IZPH VPN PRO 6.0 (60)

Paquete `com.izphprov2.net`. Catálogo completo, broker remoto fijo, worker
privado, ficha e icono original. **Catálogo fuente 59 /54 fichas**: se conserva
59 por instrucción del propietario para este lote aún sin desplegar.
No modifica Android ni crea extensiones.

## Fuente y descarga real

`https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/izph49`

Es la URL literal del actualizador activo `IZPHPROMain.V()`, aunque el nombre
del archivo termine49. El APK6.0 usa Volley `StringRequest` GET sin cabeceras
personalizadas ni Authorization. No necesita la credencial de VIP Snipher.
`IZPH VPN PRO/6.0` identifica a la herramienta; no se presenta como un agente
personalizado del APK.

GET real **HTTP200**, **480620 bytes**, SHA256
`40e2155da7be0d23bf54fedc239b4cb3adfd2f4dd103dffa3bb8944c0241269e`.
Catálogo remoto **3234 /84 servidores /303 redes**. La CLI `--download`
repitió la descarga y entregó el mismo documento completo. No se sustituye
por el asset incluido, que es **1000.0.1208 /60 servidores /110 redes**.

Broker: DNS público, conexión HTTPS fijada a una IPv4 validada, TLS verificado,
límite 8MiB y rechazo de todas las redirecciones, incluso del mismo host.
No acepta URLs ni cabeceras del cliente; no transmite secretos de otros
proveedores. Requiere el interruptor global y el control individual persistente.
No hay un secreto específico de descarga que provisionar para este build.

## Método y corrección histórica

Se reutilizan las constantes y primitivas de `../../izph.py`, confirmadas en
el SO del build 60, sin copiar el motor histórico:

| Selector JNI | Receta |
| --- | --- |
| 0 | Base64 → AES128-CBC/PKCS7 → XXTEA delta2052510689 → restar2 a cada byte |
| 1 | Base64 → Threefish256 con tweak (i,64*i) por bloque → AES128-CBC/PKCS7 |
| 2 | Base64 → XXTEA → AES256-CBC/PKCS7 con IV prefijado de16bytes |

AES0 usa SHA256(seed)[:16]; AES1 usa HKDF-SHA256 con salt de16bytes y
Threefish usa HKDF con los32bytes de salt; info vacía. Modo2 usa
PBKDF2-HMAC-SHA256,100000 iteraciones, salt completo y salida32bytes.
No pide contraseña/HWID personal.

El lector histórico invertía MIX antes de la permutación de cada ronda
Threefish; el orden inverso correcto es **permutación y después MIX**.
Se corrigió en `izph.py` y se contrastó con Java independiente y las
primitivas ARM64 originales. Se conserva además un cero legítimo final del
ciphertext AES hasta su límite de bloque; vector sintético JCA y nativo
comprobado. El lector histórico incorpora también el campo `SSCommand`.

El lector de catálogo usa mapas explícitos confirmados por los consumidores
del build 60: campos de servidores/redes, SlowDNS, V2Ray y ProxySettings.
Solo abre esos campos; conserva desconocidos, tipos, listas, vacíos, nulls,
flags, duplicados y metadatos. `ServerHTTP` y `DNSServerHost`, sin consumo
criptográfico confirmado y vacíos en ambas muestras, se preservan.
No elige un servidor aleatorio ni sustituye placeholders. El JSON V2Ray
interno permanece como texto original. Un campo cifrado conocido inválido
rechaza todo el catálogo. CBC/XXTEA/Threefish no ofrecen MAC.

## Uso y dependencias

```sh
python -m pip install -r requirements.txt
python server_catalog_decoder.py --download
python server_catalog_decoder.py copia-catalogo.enc
python server_catalog_decoder.py --stdin < copia-catalogo.enc
```

`run(data: bytes) -> str` no usa red. La descarga explícita tiene límite 8MiB,
25 segundos y no sigue redirecciones. Python>=3.10 y PyCryptodome3.23.0.
Para usar la carpeta fuera del checkout conservar `../../izph.py`,
`../HTTP_FenixVPN/codec.py` y `field_names.json`; no necesita APK ni SO en runtime.

## Evidencia y alcance

Los dos JSON reales completos coinciden en Java, Python, CLI stdin y worker
aislado. Remoto: **3692 campos /2560 no vacíos**, stdout CLI **322051 bytes**,
`isPartial:false`. Incluido:1598/1224. **6 casos nativos por muestra**, más un
caso sintético que confirma el borde de cero final. El gateway valida la
respuesta real completa del worker con HTTP interno simulado; no se afirma
transporte Node real al proveedor ni sesión VPN Android.

Las rutas históricas `.izph` y `izph://` se conservan. La corrección de
Threefish afecta también a su primitiva Python, pero no se certifica un
perfil exportado real del build 60 que no se aportó. No registrar .rj/.json
globalmente. C0 **240**, C8 **254**, overrides **28** intactos.

PNG exacto de `res/h/cd.png`:512×512,156041bytes, SHA256
`66ba9cb37ebf9c2ec8ea71bff78be16b886c794b2c13c9f6d40d9c36bb1442cb`.
Sin redibujar, convertir ni redimensionar. Ver TESTING.md, manifest.json y el
handoff de recuperación.
