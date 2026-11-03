"""ALSAHER VIP 1.1/build2: audited MTK XXTEA/UTF16 catalog using the existing family."""
from pathlib import Path
import sys
if __package__ and '.' in __package__:
    from ..ZiG_Tunnel import codec as family
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
    from ZiG_Tunnel import codec as family

DecodeError=family.DecodeError
MAX_BYTES=family.MAX_BYTES
render=family.render

def decode_catalog(data: bytes) -> dict:
    doc=family.decode_catalog(data)
    # Preserve the cloud_* names observed in the supplied catalogs as well as
    # the upload_* aliases read by this APK. Empty/null fields remain unchanged.
    for key in ('cloud_get_api','cloud_post_api'):
        value=doc.get(key)
        if value is None or value=='':continue
        if not isinstance(value,str):raise DecodeError('Campo de catálogo ALSAHER incompatible.')
        doc[key]=family.decrypt(value)
    for name in ('HTTPNetworks','SSLNetworks','JSONsettings'):
        if not isinstance(doc.get(name),list) or any(not isinstance(v,dict) for v in doc[name]):
            raise DecodeError('Catálogo ALSAHER incompleto.')
    if not (doc['HTTPNetworks'] or doc['SSLNetworks']):
        raise DecodeError('Catálogo ALSAHER sin perfiles de red.')
    family.shared._validate(doc)
    render(doc)
    return doc
