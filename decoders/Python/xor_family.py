#!/usr/bin/env python3
"""SP-DECODE XOR VPN family — one shared Python file for nine suffixes."""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

FILE_EXTENSIONS = (
    ".apnalite", ".apnatnl", ".bdnet", ".hxt", ".fnf",
    ".4ulite", ".omanova", ".ursa", ".hsome",
)
SCHEMES = tuple(ext[1:] + "://" for ext in FILE_EXTENSIONS) + ("hamaratnl://",)
HEX = re.compile(r"^[0-9a-fA-F]+$")
class XORDecoder:
    """
    فك تشفير الملفات المشفرة بـ XOR (apnalite, bdnet, hxt, fnf, 4ulite)
    """
    XOR_KEY = b"4%PdXch>fkP]"

    @staticmethod
    def decrypt_xor_links(data: str) -> str:
        """
        فك تشفير رابط XOR مشفر (نص سداسي عشري)
        """
        if "://" in data:
            data = data.split("://", 1)[1]
        data = data.strip()
        try:
            raw = bytes.fromhex(data)
            result = bytes(b ^ XORDecoder.XOR_KEY[i % len(XORDecoder.XOR_KEY)] for i, b in enumerate(raw))
            return result.decode("utf-8", errors="ignore")
        except Exception:
            return data

    @staticmethod
    def deep_decrypt(obj):
        """
        فك تشفير جميع الحقول النصية التي تبدو سداسية عشرية داخل الكائن
        """
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if isinstance(v, str) and len(v) > 4 and len(v) % 2 == 0:
                    if all(c in "0123456789abcdefABCDEF" for c in v):
                        try:
                            obj[k] = XORDecoder.decrypt_xor_links(v)
                        except:
                            pass
                elif isinstance(v, (dict, list)):
                    XORDecoder.deep_decrypt(v)
        elif isinstance(obj, list):
            for item in obj:
                XORDecoder.deep_decrypt(item)

    @classmethod
    def decrypt(cls, encrypted_data: bytes) -> dict | None:
        """
        فك تشفير ملف XOR بالكامل
        المدخل: bytes (محتوى الملف)
        المخرج: قاموس Python أو None في حالة الفشل
        """
        try:
            content = encrypted_data.decode('utf-8', errors='ignore').strip()
            # إزالة البروتوكول إذا كان موجوداً
            for proto in ['apnalite://', 'bdnet://', 'apnatnl://', 'hxt://', 'fnf://', '4ulite://', '. omanova://', '.ursa://', '. hsome://']:
                if content.startswith(proto):
                    content = content.split('://', 1)[1]
                    break
            decrypted_text = cls.decrypt_xor_links(content)
            try:
                obj = json.loads(decrypted_text)
                cls.deep_decrypt(obj)
                return obj
            except json.JSONDecodeError:
                # إذا لم يكن JSON، نعيد النص كقاموس raw
                return {"raw": decrypted_text}
        except Exception:
            return None
def decode_text(text: str) -> str | None:
    if not isinstance(text,str) or not text or len(text)>2*1024*1024:
        return None
    if text.lower().startswith("bdnet://"):
        from decoders.Python.apps.BD_NET_VPN.file_decoder import run as bd_run
        try:
            return bd_run(text.encode("utf-8"))
        except (ValueError, UnicodeError):
            return None
    prefix=next((p for p in SCHEMES if text.lower().startswith(p)),None)
    if prefix is None:
        return None
    encoded=text[len(prefix):].strip()
    if not encoded or len(encoded)%2 or HEX.fullmatch(encoded) is None:
        return None
    clear=XORDecoder.decrypt_xor_links(encoded)
    if not clear or clear==encoded:
        return None
    try:
        parsed=json.loads(clear)
        XORDecoder.deep_decrypt(parsed)
        return json.dumps(parsed,ensure_ascii=False,indent=2)
    except (json.JSONDecodeError,UnicodeError):
        return clear if clear.isprintable() else None

def run(data: bytes) -> str | None:
    if not data or len(data)>2*1024*1024:
        return None
    try:
        raw=data.decode("ascii").strip()
    except UnicodeError:
        return None
    if "://" in raw:
        prefix,raw=raw.split("://",1)
        if (prefix.lower()+"://") not in SCHEMES:
            return None
    if len(raw)%2 or HEX.fullmatch(raw) is None:
        return None
    clear=XORDecoder.decrypt_xor_links(raw)
    if not clear or clear==raw:
        return None
    try:
        parsed=json.loads(clear)
        XORDecoder.deep_decrypt(parsed)
        return json.dumps(parsed,ensure_ascii=False,indent=2)
    except (ValueError,UnicodeError):
        return clear if clear.isprintable() else None

def main():
    if len(sys.argv)!=2:
        print("Usage: python xor_family.py <file>",file=sys.stderr)
        return 2
    path=Path(sys.argv[1])
    if path.suffix.lower() not in FILE_EXTENSIONS:
        print("Unsupported extension",file=sys.stderr)
        return 2
    if path.suffix.lower() == ".bdnet":
        if not __package__:
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from decoders.Python.apps.BD_NET_VPN.file_decoder import run as bd_run
        try:
            result=bd_run(path.read_bytes())
        except (ValueError, UnicodeError):
            result=None
    else:
        result=run(path.read_bytes())
    if result is None:
        print("Unable to decode XOR configuration",file=sys.stderr)
        return 1
    print(result)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
