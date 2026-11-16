"""Reproduce a narrowly scoped revision of the supplied script; retain its credits.

The supplied script is not vendored: its redistribution license is unknown.
This recipe requires the owner's original file, identified by SHA-256.
"""
import argparse,hashlib
from pathlib import Path

EXPECTED='91a775ec1aedf0e896c6f52bc1483dee32ce8e3a59f373e7958bf9895c814be3'

def replace_once(source,old,new):
    if source.count(old)!=1:raise ValueError('Unexpected supplied script revision')
    return source.replace(old,new,1)

def revise(raw):
    if hashlib.sha256(raw).hexdigest()!=EXPECTED:raise ValueError('Unexpected source SHA-256')
    source=raw.decode()
    source=replace_once(source,'def _derive_n15(salt: bytes, aad: bytes) -> bytes:',
        'def _derive_n15(salt: bytes, aad: bytes, password_key: bytes = b"") -> bytes:')
    source=replace_once(source,'return _hkdf_sha256(outer, salt, b"hc-config-content-v12")',
        'return _hkdf_sha256(outer + password_key, salt, b"hc-config-content-v12")')
    old='''    if schema == 12:
        contact_key = _derive_n15(ekey, aad_base)
        section_key = None
        if protected:
            try:
                ops, mem = int(env["l"]), int(env["m"])
            except (KeyError, TypeError, ValueError) as exc:
                raise HCDecryptError("V4 password KDF parameters are invalid") from exc
            contact_key = _hkdf_sha256(
                contact_key + _argon2id13(password.encode("utf-8"), ekey[:16], ops, mem),
                ekey,
                info,
            )
        return contact_key, aad_base, schema'''
    new='''    if schema == 12:
        password_key = b""
        if protected:
            try:
                ops, mem = int(env["l"]), int(env["m"])
            except (KeyError, TypeError, ValueError) as exc:
                raise HCDecryptError("V4 password KDF parameters are invalid") from exc
            if not (1 <= ops <= 10 and 8192 <= mem <= 256 * 1024 * 1024):
                raise HCDecryptError("V4 password KDF resource limit exceeded")
            password_key = _argon2id13(password.encode("utf-8"), ekey[:16], ops, mem)
        contact_key = _derive_n15(ekey, aad_base, password_key)
        return contact_key, aad_base, schema'''
    source=replace_once(source,old,new)
    # Report requirements explicitly, instead of an empty response or a false
    # assertion that the owner's password is wrong for an unsupported schedule.
    source=replace_once(source,'                    if b in (11, 13) or str(env.get("e")) == "n13" or "p" in env:',
        '''                    if b == 9:
                        raise HCDecryptError("ACCESS_ID_PRIVATE_KEY_REQUIRED: recipient wrapper")
                    if b == 12 and str(env.get("e")) == "n16":
                        raise HCDecryptError("UNSUPPORTED_HWID_SCHEDULE_N16: supplied credentials are not disproved")
                    if b in (11, 13) or str(env.get("e")) == "n13" or "p" in env:''')
    source=replace_once(source,'                if "Extra Protection" in str(exc) or "unsupported V4" in str(exc):',
        '                if any(marker in str(exc) for marker in ("Extra Protection", "unsupported V4", "ACCESS_ID_PRIVATE_KEY_REQUIRED", "UNSUPPORTED_HWID_SCHEDULE_N16")):')
    source=replace_once(source,'MSG_WRONG_TYPE = (\n    ""\n)',
        'MSG_WRONG_TYPE = "INVALID_INPUT: expected nonempty HC file bytes"')
    source=replace_once(source,'MSG_V4_EXTRA_PROTECTION = (\n    ""\n)',
        'MSG_V4_EXTRA_PROTECTION = "EXTRA_PROTECTION_REQUIRED: original authorized activation material is missing"')
    source=replace_once(source,'"V4 Extra Protection (schema n13) requires the app\'s "',
        '"V4 Extra Protection requires the original app\'s "')
    source=replace_once(source,'            if "extra protection" in lower or "n13" in lower:',
        '''            if "access_id_private_key_required" in lower:
                return "ACCESS_ID_PRIVATE_KEY_REQUIRED: the public ID is not the recipient private key"
            if "unsupported_hwid_schedule_n16" in lower:
                return "UNSUPPORTED_HWID_SCHEDULE_N16: not implemented; no conclusion about the credentials"
            if "extra protection" in lower or "n13" in lower:''')
    return '# Research revision: HC build 934 n15 password composition fixed; original credits retained.\n'+source

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    a.output.write_text(revise(a.source.read_bytes()))
    print('Revised reader SHA-256:',hashlib.sha256(a.output.read_bytes()).hexdigest())

if __name__=='__main__':main()
