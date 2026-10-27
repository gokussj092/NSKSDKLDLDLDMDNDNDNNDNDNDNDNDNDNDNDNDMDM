"""APK-bound carrier key derivation recovered from HTTP Injector 6.5.0/244.

No configuration-specific keys, APK certificate bytes or derived key literals
are stored here. The validated APK supplies its public signing certificate.
"""
import base64
import hashlib
import io
import re
import zipfile
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding

APK_SHA256 = '5dc3976ad0d90c14b79f5848109296998f930c9d36be88fba9115c078f60dfe3'


def derive_carrier_keys(apk):
    if hashlib.sha256(apk).hexdigest() != APK_SHA256:
        raise ValueError('AUDITED_HTTP_INJECTOR_APK_REQUIRED')
    certificates = []
    with zipfile.ZipFile(io.BytesIO(apk)) as archive:
        for entry in archive.infolist():
            if entry.filename.startswith('META-INF/') and entry.filename.endswith(('.RSA', '.DSA', '.EC')):
                if entry.file_size > 262144:
                    raise ValueError('CERTIFICATE_CONTAINER_TOO_LARGE')
                certificates.extend(pkcs7.load_der_pkcs7_certificates(archive.read(entry)))
    if len(certificates) != 1:
        raise ValueError('SINGLE_OBSERVED_SIGNING_CERTIFICATE_REQUIRED')
    certificate = certificates[0].public_bytes(Encoding.DER)
    signature = base64.b64encode(hashlib.sha1(certificate).digest()).decode('ascii')
    # Resource 0x7f120036 and the original string-decoder result. Base64 encode
    # followed by decode in the Java call chain cancels out; this is UTF-8 salt.
    label = 'HTTP Injector'
    salt = re.sub(r'[-=+/\s]', '', label + '寫程戲師外' + signature + label[3:9]).encode('utf-8')
    derived = hashlib.pbkdf2_hmac('sha1', b'com.evozi.injector', salt, 5000, 48)
    # The first 16 bytes must reproduce the already-supported CBC key. The
    # remaining 32 bytes authenticate IV2 || ciphertext2, not plaintext JSON.
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from decoders.Python.HTTPINJECTOR import EHIConstants
    if derived[:16] != EHIConstants.L2_KEY_STATIC:
        raise ValueError('DERIVED_CBC_KEY_DISAGREES_WITH_EXISTING_READER')
    return derived
