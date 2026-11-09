"""Only original fixed HTTPS endpoints; no arbitrary URL input or redirects."""
from __future__ import annotations
import re
import time
from urllib.error import HTTPError
from urllib.request import Request, HTTPRedirectHandler, build_opener
if __package__:
    from .codec import DecodeError, MAX_BYTES, _password
    from . import build_history as builds
else:
    from codec import DecodeError, MAX_BYTES, _password
    import build_history as builds

CATALOG_URL = "https://tunneltweak.com/api/servers"
CLOUD_BASE_URL = "https://tunneltweak.com/api/cloudconfig/"
CATALOG_HEADERS = {"User-Agent": "TunnelTweak/1.0 (Android)", "ngrok-skip-browser-warning": "true", "x-app-version": str(builds.seed()['auto']['build']), "x-cfg-keyed": "1"}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise DecodeError("El proveedor intentó redirigir la descarga.")


def download(*, cloud_id: str | None = None, api_key: str | None = None, state_path=None) -> bytes:
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
    path=builds.state_path() if state_path is None else state_path
    build=builds.load(path)['auto']['build'] if cloud_id is None else None
    deadline=time.monotonic()+25
    try:
        opener=build_opener(_NoRedirect())
        for attempt in range(3):
            if build is not None:headers['x-app-version']=str(build)
            remaining=deadline-time.monotonic()
            if remaining<=0:raise OSError('deadline')
            try:response=opener.open(Request(url,headers=headers),timeout=remaining)
            except HTTPError as e:
                if e.code!=426 or build is None:raise
                response=e
            with response:
                status=response.status
                if status not in (200,426) or response.headers.get('Content-Encoding','identity')!='identity':
                    raise DecodeError('Respuesta remota inválida.')
                data=response.read((65536 if status==426 else MAX_BYTES)+1)
            if build is not None and status==426:
                if not builds.update_required(data):
                    builds.safe_record(path,build,status,'RESPONSE_INVALID');raise DecodeError('Respuesta de actualización inválida.')
                next_build=builds.next_build(data,build)
                builds.safe_record(path,build,status,'UPDATE_REQUIRED',next_build)
                if next_build is None or attempt==2:raise DecodeError('No se pudo resolver el build público de Tunneltweak.')
                build=next_build;continue
            if not data or len(data)>MAX_BYTES or data.lstrip().startswith(b'<'):
                if build is not None:builds.safe_record(path,build,status,'RESPONSE_INVALID')
                raise DecodeError('Respuesta vacía, incompatible o superior a 8 MiB.')
            if build is not None:
                if not builds.valid_download(data):
                    builds.safe_record(path,build,status,'RESPONSE_INVALID');raise DecodeError('Respuesta remota inválida.')
                builds.safe_record(path,build,status,'DOWNLOAD_OK')
            return data
    except OSError as exc:
        if build is not None:builds.safe_record(path,build,getattr(exc,'code',None) if isinstance(exc,HTTPError) else None,'TEMPORARY_FAILURE')
        raise DecodeError('No se pudo descargar el recurso autorizado de Tunneltweak.') from exc

