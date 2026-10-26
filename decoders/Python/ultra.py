#!/usr/bin/env python3
"""SP-DECODE bot: Ultra/Sandok VPN family (42 file suffixes).

Extracted from the owner's authorized 66.py reference. All app-specific
password profiles, Argon2id parameters, key ordering and two-stage AES-GCM
decryption are maintained in one independently importable Python engine.
No network access, Telegram handlers, subprocesses or third-party API requests.
The source's remote URL and user-agent entries are inert historical metadata.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from Crypto.Cipher import AES

try:
    from argon2.low_level import Type, hash_secret_raw
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

VPNS_SD = {
    "ultratunnel": {
        "url": "https://strongteam.co/api/ultrasystem/ultrav3.txt",
        "ua": "Ultra Tunnel",
        "password": b"/4ssU0OjjtKH8AheiAxnc3DwSGDzsy+8",
        "password2": b"NurChickenPowder",
        "name": "Ultra Tunnel",
        "mem": 0x2000
    },
    "mtv2raypro": {
        "url": "https://strongteam.co/api/mtv2raypro/mtconfig.txt",
        "ua": "MT V2ray PRO",
        "password": b"VYyG4WjHWINewWLnLziOZPoX27OJWsTF",
        "password2": b"tJEoBeQNPcAebH6TG5Yri9m1yjtfwCbc",
        "name": "MT V2ray PRO",
        "mem": 0x2000
    },
    "mdproxy": {
        "url": "https://strongteam.co/api/ultrasystem/ultrav3.txt",
        "ua": "MD Proxy VPN",
        "password": b"/4ssU0OjjtKH8AheiAxnc3DwSGDzsy+8",
        "password2": b"NurChickenPowder",
        "name": "MD Proxy VPN",
        "mem": 0x2000
    },
    "beevpn": {
        "url": "https://strongteam.co/api/bee/bee2/",
        "ua": "Bee VPN",
        "password": b"BinkeVPNTeam",
        "password2": b"BinkeVPNTeam",
        "name": "Bee VPN",
        "mem": 0x2000
    },
    "vlxtunnelvpn": {
        "url": "https://strongteam.co/api/vlx/v1/",
        "ua": "VLX Tunnel VPN",
        "password": b"VLXTeamTunnelVPNP@SSII",
        "password2": b"VLXTeamTunnelVPNP@SS",
        "name": "VLX Tunnel VPN",
        "mem": 0x2000
    },
    "mmtunnel": {
        "url": "https://strongteam.co/api/kidvpn/v6/",
        "ua": "ML Tunnel",
        "password": b"NewDecryptLibPasswordIICore",
        "password2": b"NewDecryptLibPassword",
        "name": "MM Tunnel",
        "mem": 0x4000
    },
    "txtunnel": {
        "url": "https://strongteam.co/api/bee/bee2/",
        "ua": "TX Tunnel",
        "password": b"TXTunnel2026@Pass",
        "password2": b"TXTunnel2026@Pass",
        "name": "TX Tunnel",
        "mem": 0x4000
    },
    "wolfcustom": {
        "url": "https://strongteam.co/api/wolf/",
        "ua": "Wolf Custom VPN",
        "password": b"WolfTunnelStrongTeam2026!II",
        "password2": b"WolfTunnelStrongTeam2026!",
        "name": "Wolf Custom VPN",
        "mem": 0x2000
    },
    "velmoravpn": {
        "url": "https://strongteam.co/api/velmora/",
        "ua": "Velmora VPN",
        "password": b"VElMORAVPNP@ssword2026!II",
        "password2": b"VElMORAVPNP@ssword2026!",
        "name": "Velmora VPN",
        "mem": 0x2000
    },
    "auranetvpn": {
        "url": "https://strongteam.co/api/auranet/v1/",
        "ua": "Aura Net VPN",
        "password": b"AuraNETXRPTeam",
        "password2": b"AuraNETXRPTeam",
        "name": "Aura Net VPN",
        "mem": 0x2000
    },
    "tiktunnelvpn": {
        "url": "https://strongteam.co/api/tiktunnel/",
        "ua": "Tik Tunnel VPN",
        "password": b"TikTunnelVPNP@ss",
        "password2": b"TikTunnelVPNP@ss",
        "name": "Tik Tunnel VPN",
        "mem": 0x2000
    },
    "t20vpn": {
        "url": "https://strongteam.co/api/tiktunnel/",
        "ua": "Tik Tunnel VPN",
        "password": b"NewDecryptLibPasswordT20VPNII",
        "password2": b"NewDecryptLibPasswordT20VPN",
        "name": "Tik Tunnel VPN",
        "mem": 0x1000
    },
    "luckyproxy": {
        "url": "https://strongteam.co/api/tiktunnel/",
        "ua": "Lucky Proxy VPN",
        "password": b"LuckyVIPProxyP@ssword2026!II",
        "password2": b"LuckyVIPProxyP@ssword2026!",
        "name": "Lucky Proxy VPN",
        "mem": 8192
    },
    "greattunnel": {
        "url": "https://strongteam.co/api/great/greatv1.txt",
        "ua": "Great Tunnel",
        "password": b"1Ww5UyGSWiH73F9d38a5AxZTg0Ah+YhM",
        "password2": b"kco7GLf4LAuO4JGjVuOFvLIXqy59S4kR",
        "name": "Great Tunnel",
        "mem": 0x2000
    },
    "flynetvpn": {
        "url": "https://strongteam.co/api/flynet/v1/",
        "ua": "FLY NET VPN",
        "password": b"FLYNet@VPNConfig@II",
        "password2": b"FLYNet@VPNConfig@",
        "name": "FLY NET VPN",
        "mem": 0x2000,
    },
}
ULTRA_CONFIGS = {
    **VPNS_SD,
    "nurtunnel": {
        "url": None, "ua": "NUR Tunnel",
        "password": b"NurChickenPowder", "password2": b"NurChickenPowder",
        "name": "NUR Tunnel", "mem": 8192
    },
    "mehafvpn": {
        "url": None, "ua": "Mehaf VPN",
        "password": b"MehafVPN@Pass2026!II", "password2": b"MehafVPN@Pass2026!",
        "name": "Mehaf VPN", "mem": 8192
    },
    "deepvpn": {
        "url": None, "ua": "Deep VPN",
        "password": b"DeepVPN@Secure2026!II", "password2": b"DeepVPN@Secure2026!",
        "name": "Deep VPN", "mem": 8192
    },
    "default": {
        "url": None, "ua": "Sandok VPN",
        "password": b"NurChickenPowder", "password2": b"NurChickenPowder",
        "name": "Sandok VPN", "mem": 8192
    }
}
ULTRA_EXTS = {
    # الأساسية
    '.aura', '.bcl', '.bee', '.btv', '.ena', '.vel', '.eta', '.fix', '.glory',
    '.marvs', '.nur', '.mdvpn', '.md', '.ost', '.osv', '.ry', '.t20', '.tik',
    '.tsm', '.tx', '.ulti', '.ultra', '.vlx', '.wolf', '.mmt', '.mehaf', '.deep',
    '.great',
    # إضافات قديمة
    '.lucky', '.t10', '.mm', '.ultratunnel', '.ut',
    '.nurtunnel', '.tiktunnel', '.wolftunnel',
    # إضافات جديدة
    '.mdproxy', '.mdp',
    '.mtv2ray', '.mtv2raypro',
    # ═══ إضافات 2026 ═══
    '.flynet', '.flynetvpn',
}
ULTRA_NAMES = {
    '.aura': 'AURA TUNNEL', '.bcl': 'BCL TUNNEL', '.bee': 'BEE TUNNEL', '.btv': 'BTV TUNNEL',
    '.ena': 'ENA TUNNEL', '.vel': 'VEL TUNNEL', '.eta': 'ETA TUNNEL', '.fix': 'FIX TUNNEL',
    '.glory': 'GLORY TUNNEL', '.marvs': 'MARVS TUNNEL', '.nur': 'NUR TUNNEL', '.mdvpn': 'MD VPN',
    '.md': 'MD TUNNEL', '.ost': 'OST TUNNEL', '.osv': 'OSV TUNNEL', '.ry': 'RY TUNNEL',
    '.t20': 'T20 TUNNEL', '.tik': 'TIK TUNNEL', '.tsm': 'TSM TUNNEL', '.tx': 'TX TUNNEL',
    '.ulti': 'ULTI TUNNEL', '.ultra': 'ULTRA TUNNEL', '.vlx': 'VLX TUNNEL', '.wolf': 'WOLF TUNNEL',
    '.mmt': 'MMT TUNNEL', '.mehaf': 'MEHAF TUNNEL', '.deep': 'DEEP TUNNEL',
    '.great': 'GREAT TUNNEL',
    '.lucky': 'LUCKY PROXY', '.t10': 'T10 TUNNEL', '.mm': 'MM TUNNEL',
    '.ultratunnel': 'ULTRA TUNNEL', '.ut': 'ULTRA TUNNEL',
    '.nurtunnel': 'NUR TUNNEL', '.tiktunnel': 'TIK TUNNEL',
    '.wolftunnel': 'WOLF TUNNEL',
    '.mdproxy': 'MD PROXY VPN', '.mdp': 'MD PROXY VPN',
    '.mtv2ray': 'MT V2RAY',
    '.mtv2raypro': 'MT V2RAY PRO',
    # ═══ إضافات 2026 ═══
    '.flynet': 'FLY NET VPN', '.flynetvpn': 'FLY NET VPN',
}
EXT_TO_KEY = {
    '.great': 'greattunnel',
    '.ultra': 'ultratunnel', '.ulti': 'ultratunnel',
    '.bee': 'beevpn', '.bcl': 'beevpn',
    '.vlx': 'vlxtunnelvpn',
    '.mmt': 'mmtunnel', '.md': 'mmtunnel', '.mdvpn': 'mmtunnel',
    '.tx': 'txtunnel', '.tsm': 'txtunnel',
    '.wolf': 'wolfcustom',
    '.vel': 'velmoravpn',
    '.aura': 'auranetvpn',
    '.tik': 'tiktunnelvpn',
    '.t20': 't20vpn',
    '.nur': 'nurtunnel',
    '.mehaf': 'mehafvpn',
    '.deep': 'deepvpn',
    '.lucky': 'luckyproxy',
    '.t10': 't20vpn',
    '.mm': 'mmtunnel',
    '.ultratunnel': 'ultratunnel',
    '.ut': 'ultratunnel',
    '.nurtunnel': 'nurtunnel',
    '.tiktunnel': 'tiktunnelvpn',
    '.wolftunnel': 'wolfcustom',
    '.mdproxy': 'mdproxy',
    '.mdp': 'mdproxy',
    '.mtv2ray': 'mtv2raypro',        # ← يشير لنفس المفتاح
    '.mtv2raypro': 'mtv2raypro',
    '.btv': 'default',
    '.ena': 'default',
    # ═══ إضافات 2026 ═══
    '.flynet': 'flynetvpn',
    '.flynetvpn': 'flynetvpn',
    # اختياري:
    '.glory': 'default', '.marvs': 'default', '.ost': 'default',
    '.osv': 'default', '.ry': 'default', '.fix': 'default', '.eta': 'default',
}
def ultra_derive_key(salt: bytes, password: bytes, mem: int = 8192) -> bytes:
    """اشتقاق مفتاح باستخدام Argon2id"""
    if not ARGON2_AVAILABLE:
        return None
    try:
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=3,
            memory_cost=mem,
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )
    except Exception:
        return None


# ══════════════════════════════════════════════════════════
# [9] فك تشفير حقل واحد (الطبقة الثانية)
# ══════════════════════════════════════════════════════════
def decrypt_ultra_field(value, password=b"NurChickenPowder", mem=8192):
    """فك تشفير حقل واحد"""
    if not value or not isinstance(value, str) or len(value) < 44:
        return value
    try:
        data = base64.b64decode(value)
        if len(data) < 44:
            return value
        key = ultra_derive_key(data[:16], password, mem)
        if not key:
            return value
        # The newer Ultra Tunnel exporter authenticates nested fields with
        # AAD=salt, while historical exports use no AAD. Authenticate both
        # variants; do not silently strip bytes or accept invalid GCM tags.
        for aad in (data[:16], None):
            try:
                cipher = AES.new(key, AES.MODE_GCM, nonce=data[16:28])
                if aad is not None:
                    cipher.update(aad)
                clear = cipher.decrypt_and_verify(data[28:-16], data[-16:])
                return clear.decode('utf-8')
            except (ValueError, UnicodeDecodeError):
                continue
        return value
    except Exception:
        return value


# ══════════════════════════════════════════════════════════
# [10] كشف نوع التطبيق
# ══════════════════════════════════════════════════════════
def detect_ultra_type(content: str) -> str:
    """كشف نوع التطبيق من محتوى الملف"""
    if not content:
        return 'default'

    c = content.lower()

    if 'greattunnel' in c or 'great' in c:                     return 'greattunnel'
    if 'newdecryptlibpasswordiicore' in c or 'mmtunnel' in c:  return 'mmtunnel'
    if 'vlxteam' in c or 'vlxtunnel' in c:                     return 'vlxtunnelvpn'
    if 'wolftunnel' in c or 'wolfcustom' in c:                 return 'wolfcustom'
    if 'tiktunnel' in c:                                       return 'tiktunnelvpn'
    if 'binkevpn' in c or 'beevpn' in c:                       return 'beevpn'
    if 'txtunnel' in c:                                        return 'txtunnel'
    if 't20vpn' in c or 'newdecryptlibpasswordt20' in c:       return 't20vpn'
    if 'luckyproxy' in c or 'luckyvip' in c:                   return 'luckyproxy'
    if 'auranet' in c:                                         return 'auranetvpn'
    if 'velmora' in c:                                         return 'velmoravpn'
    if 'mehaf' in c:                                           return 'mehafvpn'
    if 'deep' in c:                                            return 'deepvpn'
    if 'nurchickenpowder' in c or 'ultra' in c:                return 'ultratunnel'
    return 'default'


# ══════════════════════════════════════════════════════════
# [11] مولّد المرشّحات (Multi-Candidate)
# ══════════════════════════════════════════════════════════
def encrypted_candidates(text: str):
    """
    يولّد عدّة صيغ Base64 محتملة:
      1. النص النظيف كما هو
      2. مع padding مطابق
      3. بحذف حرف واحد (إن كان الباقي = 1)
    """
    base64_alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/="
    )

    clean = "".join(
        char for char in text.strip()
        if char in base64_alphabet
    )

    yielded = set()

    def add(value):
        if value and value not in yielded:
            yielded.add(value)
            return value
        return None

    # 1) النص النظيف
    candidate = add(clean)
    if candidate:
        yield candidate

    remainder = len(clean) % 4

    # 2) إضافة padding
    if remainder in (2, 3):
        padded = add(clean + "=" * (4 - remainder))
        if padded:
            yield padded

    # 3) حذف حرف واحد
    elif remainder == 1:
        scan_limit = min(16, len(clean))
        for index in range(scan_limit):
            fixed = add(clean[:index] + clean[index + 1:])
            if fixed:
                yield fixed


# ══════════════════════════════════════════════════════════
# [12] الدالة الرئيسية — Multi-Candidate + AAD
# ══════════════════════════════════════════════════════════
def decrypt_ultra_file(data, ext):
    """
    فك تشفير ملف ULTRA/SANDOK:
      - يولّد عدّة مرشّحات Base64
      - يجرّب كل مفتاح من ULTRA_CONFIGS
      - يجرب AES-GCM مع AAD (salt) ثم بدون AAD
    """
    try:
        # ── تجهيز المحتوى ──
        if isinstance(data, (bytes, bytearray)):
            content = data.decode('utf-8', errors='ignore').strip()
        else:
            content = str(data).strip()

        if '://' in content:
            content = content.split('://', 1)[1]

        content = ''.join(content.split())

        if not content:
            return None

        # ── أولوية المفاتيح حسب الامتداد ──
        priority = []
        if ext in EXT_TO_KEY:
            priority.append(EXT_TO_KEY[ext])

        vpn_type = detect_ultra_type(content)
        if vpn_type not in priority:
            priority.append(vpn_type)

        vpns_to_try = list(dict.fromkeys(
            priority + [
                'greattunnel', 'mmtunnel', 'ultratunnel', 'vlxtunnelvpn',
                'wolfcustom', 'tiktunnelvpn', 'beevpn', 'txtunnel', 't20vpn',
                'luckyproxy', 'auranetvpn', 'velmoravpn', 'mehafvpn',
                'deepvpn', 'nurtunnel', 'default'
            ]
        ))

        # ── تجربة كل مرشّح Base64 ──
        for candidate in encrypted_candidates(content):

            try:
                decoded = base64.b64decode(candidate)
            except Exception:
                continue

            if len(decoded) < 44:
                continue

            salt = decoded[:16]
            nonce = decoded[16:28]
            ciphertext_and_tag = decoded[28:]

            if len(ciphertext_and_tag) < 16:
                continue

            ciphertext = ciphertext_and_tag[:-16]
            tag = ciphertext_and_tag[-16:]

            # ── تجربة كل مفتاح ──
            for vpn_name in vpns_to_try:

                vc = ULTRA_CONFIGS.get(vpn_name, ULTRA_CONFIGS.get('default'))
                if not vc:
                    continue

                password = vc.get("password", b"")
                password2 = vc.get("password2", b"")
                mem = vc.get("mem", 8192)

                key = ultra_derive_key(salt, password, mem)
                if not key:
                    continue

                # ═══ محاولة 1: AES-GCM مع AAD = salt ═══
                plaintext = None
                try:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    cipher.update(salt)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                except Exception:
                    # ═══ محاولة 2: AES-GCM بدون AAD ═══
                    try:
                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    except Exception:
                        continue

                if not plaintext:
                    continue

                try:
                    plain = plaintext.decode('utf-8')
                except UnicodeDecodeError:
                    continue

                if not plain:
                    continue

                start = plain.find('{')
                end = plain.rfind('}')

                if start == -1 or end == -1 or end < start:
                    continue

                try:
                    config = json.loads(plain[start:end + 1])
                except json.JSONDecodeError:
                    continue

                if not isinstance(config, dict):
                    continue

                # ── فك الحقول المشفّرة (الطبقة الثانية) ──
                for field in [
                    'BugDNS', 'CustomProxy', 'Payload', 'SNI',
                    'V2rayAddress', 'V2rayConfig', 'V2rayHost',
                    'V2raySNI', 'Info', 'Host', 'Server'
                ]:
                    if field in config and config[field] and isinstance(config[field], str):
                        try:
                            dec = decrypt_ultra_field(config[field], password2, mem)
                            if dec != config[field]:
                                config[field] = dec
                        except Exception:
                            continue

                # ── إضافة معلومات مساعدة ──
                config['_vpn_type'] = vc.get('name', vpn_name)
                config['_vpn_key'] = vpn_name

                return config

        return None

    except Exception:
        return None

def run(file_bytes: bytes, extension: str = ".ultra") -> str | None:
    """Decode into complete, untruncated JSON; None denotes an unsupported input."""
    ext = "." + extension.lower().lstrip(".")
    if ext not in ULTRA_EXTS:
        return None
    if ext == ".aura":
        if not __package__:
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from decoders.Python.apps.Aura_Net_VPN.file_decoder import run as aura_run
        try:
            return aura_run(file_bytes)
        except (ValueError, RecursionError):
            return None
    if ext == ".tx":
        if not __package__:
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from decoders.Python.apps.Tx_Tunnel.file_decoder import run as tx_run
        try:
            return tx_run(file_bytes)
        except (ValueError, RecursionError):
            return None
    if ext == ".mmt":
        # Build 45 uses a distinct export key and an inserted Base64 letter.
        # The app reader reuses the historical decryptor below as fallback.
        if not __package__:
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from decoders.Python.apps.MM_Tunnel.file_decoder import run as mm_run
        try:
            return mm_run(file_bytes)
        except (ValueError, RecursionError):
            return None
    config = decrypt_ultra_file(file_bytes, ext)
    if config is None:
        return None
    output = {
        "application": ULTRA_NAMES[ext],
        "extension": ext,
        "config": config,
    }
    return json.dumps(output, ensure_ascii=False, indent=2)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python ultra.py <configuration_file>", file=sys.stderr)
        return 2
    if not ARGON2_AVAILABLE:
        print("Missing dependency: pip install argon2-cffi", file=sys.stderr)
        return 2
    path = Path(args[0])
    ext = path.suffix.lower()
    if ext not in ULTRA_EXTS:
        print(f"Unsupported Ultra/Sandok extension: {ext}", file=sys.stderr)
        return 2
    try:
        raw = path.read_bytes()
        result = run(raw, ext)
    except (OSError, ValueError) as exc:
        print(f"Cannot decode Ultra/Sandok file: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Could not decrypt Ultra/Sandok configuration", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
