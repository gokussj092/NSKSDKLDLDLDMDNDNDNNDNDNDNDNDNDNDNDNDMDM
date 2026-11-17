# STR VIP Proxy — catálogo y archivos

App: STR VIP Proxy, paquete `app.isvsoft.strvipproxy`, versionCode 1,
versionName 1.42.5. APK verificado: `base.apk` (23.434.405 B, SHA-256
`2cf49ca1e7870a0d1ff54e3204258380afe518e233d93990178a30cad0915174`) +
`split_config.arm64_v8a.apk` (SHA-256
`3bc84757914457d7108d52b0ed44de772d303bb5e896c38172bd1025242415cb`).

## Catálogo (`STR_VIP_Proxy.py`, solo stdlib)

- Descarga: `GET https://isvsoft-vpn-worker.isvsoft.workers.dev/api/app?json=04a486d15a5045278fa8c8516329be04&type=full`
  con `User-Agent: ISVSOFT-CloudSync/2.0` y cabeceras App-Proof
  `X-ISV-Timestamp` / `X-ISV-Nonce` / `X-ISV-Signature`
  (`HMAC-SHA256(clave, "timestamp:nonce:path")`, path SIN query).
  El servidor rechaza otros User-Agent y peticiones sin prueba (403).
- Respuesta: JSON plano (gzip en transporte). Cada valor sensible es un
  token `enc:` (AES-256-GCM, misma clave de 32 bytes que la firma;
  implementación AES-GCM en Python puro, solo stdlib, verificada contra
  la librería nativa emulada y contra `cryptography` en 1.951 valores).
- En vivo (2026-11-17, re-corrido byte por byte): v1.0.31, 21 servidores,
  686 tweaks, 1.888/1.888 valores `enc:` descifrados, 0 fallos.
- El JSON de resultado NO incluye las APIs de descarga (regla del proyecto).

**Límite de integración (importante):** la petición exacta NO puede
expresarse en `supplied-integrations.json` `requests[]`: el esquema solo
admite cabeceras estáticas (+ un `secretHeader` estático y las
`sessionHeaders` genéricas) y no hay ningún camino HMAC en
`supplied-integrations.mjs` ni en `server-vpn-provider.mjs`. Ver
`REPORT.md` y el expediente: el catálogo queda pendiente de una
decisión (extender el esquema con firma HMAC por env, o broker
dedicado). La entrada supplied propuesta es `FILE_ONLY` (`requests:[]`)
hasta que eso se resuelva. El fallback a `curl --http2` del script NO
existe en la imagen del worker (Dockerfile sin curl): solo afecta al
CLI standalone, no al `run()`/`decode()` del worker.

## Archivos (`.isc`) y texto (`STR_VIP_Proxy_archivos.py`, solo stdlib)

- `.isc`: texto UTF-8 / JSON `SharedConfig` / token `enc:` / enlace
  `isv-config://`. `.ovpn`/`.conf`: texto plano OpenVPN (genérico, no se
  registra como formato propio). Códigos de nube `ISV-`: marcador sin
  descargar (solo verificado el 404); `--cloud` los descarga.
- Enlaces `vmess://`/`vless://`/`trojan://`/`ss://` y texto WireGuard:
  ya cubiertos por los formatos genéricos; no se re-registran.
- **Probado:** `--self-test` 12/12. **Sin archivo real:** no existe
  ningún `.isc`/`.ovpn`/`isv-config://` real exportado por la app;
  la confirmación extremo a extremo sigue pendiente.

## Uso

```sh
python3 STR_VIP_Proxy.py --url --summary
python3 STR_VIP_Proxy.py --url -o catalogo.json
python3 STR_VIP_Proxy_archivos.py --self-test
python3 STR_VIP_Proxy_archivos.py perfil.isc -o perfil.json
python3 STR_VIP_Proxy_archivos.py --text 'isv-config://...' -o perfil.json
```

Solo biblioteca estándar (Python 3.10+). Estado de integración:
pendiente de subida (staging, sin deploy, sin merge).
