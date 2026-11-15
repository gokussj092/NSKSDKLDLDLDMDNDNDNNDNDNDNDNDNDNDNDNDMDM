"""SpeiGo build159: two separately authenticated SV5C v2/release112 catalogs."""
from decoders.Python.apps.SuperFlash_VPN import codec as wire
DecodeError=wire.DecodeError
MAX_BYTES=wire.MAX_BYTES
render=wire.render
SIGNATURE_PUBLIC_KEY=bytes.fromhex('4733a5521e426f82a124adc047e68e486579da747944cfe8d80081b3e2fc92ce')
ROOT_KEY=bytes.fromhex('e973cfb02d8a0fc2102cd8a0351c199c1cba7c04a507d082fa68231bea2f4fb3')
CONTEXT=bytes.fromhex('af9d380863dc5c05851192e82d6fda880ce0346f877ab0c093000c7dbe372194')
def decode_catalog(data,purpose):
    try:
        if purpose not in (1,2) or not isinstance(data,bytes) or len(data)<84 or data[5]!=purpose:raise DecodeError('Wrong SpeiGo source')
        return wire.decode_sv5c(data,release_code=112,signature_key=SIGNATURE_PUBLIC_KEY,root_key=ROOT_KEY,context=CONTEXT)
    except (ValueError,TypeError,RecursionError):raise DecodeError('Catálogo SpeiGo VPN inválido o incompatible con la sección elegida.') from None
