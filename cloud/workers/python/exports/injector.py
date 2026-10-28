"""Use only the EHI open + HTML path accepted in the owner's Android test."""
import base64
import hashlib
import re
from decoders.Python.HTTPINJECTOR import EHIConstants
from .ehi import open_profile, reseal, observed_open_access_edits, encode_message
from .notes import html_note

# Public fingerprint of the signing certificate from the hash-pinned audited
# APK. This is not a private signing key, user credential or profile key.
SIGNER_CERTIFICATE_SHA1 = '1d0b44fbedb3a550bffa94d4a344448ad4a6b063'
AUDITED_APK_SHA256 = '5dc3976ad0d90c14b79f5848109296998f930c9d36be88fba9115c078f60dfe3'


def carrier_key():
    signature = base64.b64encode(bytes.fromhex(SIGNER_CERTIFICATE_SHA1)).decode('ascii')
    label = 'HTTP Injector'
    salt = re.sub(r'[-=+/\s]', '', label+'寫程戲師外'+signature+label[3:9]).encode('utf-8')
    raw = hashlib.pbkdf2_hmac('sha1', b'com.evozi.injector', salt, 5000, 48)
    if raw[:16] != EHIConstants.L2_KEY_STATIC: raise ValueError('SIGNER_MATERIAL_MISMATCH')
    return raw[16:]


def export(raw, credentials, language='es'):
    if credentials: raise ValueError('UNSUPPORTED_EHI_CREDENTIALS')
    key = carrier_key()
    original = open_profile(raw, carrier_mac_key=key, require_carrier_mac=True)
    outer, inner = observed_open_access_edits(original)
    inner['configMessage'] = encode_message(html_note(language).replace('\r','').replace('\n',''))
    output = reseal(original, outer_edits=outer, inner_edits=inner)
    checked = open_profile(output, carrier_mac_key=key, require_carrier_mac=True)
    if checked.inner.get('isConfigLock') is not False or checked.outer.get('lockModes') != '["none"]':
        raise ValueError('EHI_STILL_LOCKED')
    return output
