"""Only original fixed HTTPS endpoints; no arbitrary URL input or redirects."""
from __future__ import annotations
import re
from urllib.request import Request, HTTPRedirectHandler, build_opener
if __package__:
    from .codec import DecodeError, MAX_BYTES, _password
else:
    from codec import DecodeError, MAX_BYTES, _password

CATALOG_URL = "https://tunneltweak.com/api/servers"
CLOUD_BASE_URL = "https://tunneltweak.com/api/cloudconfig/"
CATALOG_HEADERS = {"User-Agent": "TunnelTweak/1.0 (Android)", "ngrok-skip-browser-warning": "true", "x-app-version": "53", "x-cfg-keyed": "1"}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise DecodeError("El proveedor intentó redirigir la descarga.")


def download(*, cloud_id: str | None = None, api_key: str | None = None) -> bytes:
    if cloud_id is not None:
        if not isinstance(cloud_id, str) or not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", cloud_id):
            raise DecodeError("Se requiere un UUID válido de configuración Cloud.")
        url, headers = CLOUD_BASE_URL + cloud_id, {}
    else:
        url, headers = CATALOG_URL, dict(CATALOG_HEADERS)
        if api_key is not None:
            _password(api_key)
            if any(ord(c) < 33 or ord(c) > 126 for c in api_key):
                raise DecodeError("Clave de API incompatible con una cabecera HTTP.")
            headers["x-api-key"] = api_key
    headers["Accept-Encoding"] = "identity"
    try:
        with build_opener(_NoRedirect()).open(Request(url, headers=headers), timeout=25) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise DecodeError("Respuesta remota inválida.")
            data = response.read(MAX_BYTES + 1)
    except OSError as exc:
        raise DecodeError("No se pudo descargar el recurso autorizado de Tunneltweak.") from exc
    if not data or len(data) > MAX_BYTES or data.lstrip().startswith(b"<"):
        raise DecodeError("Respuesta vacía, incompatible o superior a 8 MiB.")
    return data

