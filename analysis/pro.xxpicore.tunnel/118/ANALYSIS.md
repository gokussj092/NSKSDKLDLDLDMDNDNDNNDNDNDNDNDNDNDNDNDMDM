# XXPICore Tunnel 1.0.18 / 118 — Cloud catalog

Status: **VERIFIED_REAL**, proposed code only; production human review and Node
egress on VPS pending. Package `pro.xxpicore.tunnel` was checked against the base
manifest, not inferred from a filename. User supplied the Play link and asked
for Cloud integration without Android builds or waiting for artifacts.

## Inputs and observations

The already downloaded public APKPure XAPK is58453953bytes,
SHA256`75ac25296f6a0346163d61496a23541b7abab7abcce3f6fce48e428091a70e65`.
Base SHA256`d2ddad1a78d99f24ba674a2aefe1e1a1ab0a61641725a953defe342e84e1d141`.
The mirror's `latest` URL does not prove the latest Play build. Original inputs
and decoded profiles remain private; only hashes/counts and fictional fixtures
are committed.

1. `prepare.py` inventories base/splits, DEX, assets, ARM64 libraries and original
   launcher PNG. `dex_inventory.py` identifies app code in classes3.dex.
2. Pinned JADX1.5.6 was used first on classes.dex, then classes3.dex. Both exit3
   with partial output; DEX1 contains no relevant app classes. This is not
   accepted as proof of correct decompilation. Relevant build118 app consumers
   are readable and corroborated by native disassembly and independent tests.
3. `qn.a(long)` is LSParanoid arithmetic with chunks field`a` and method`a`.
   The unchanged shared resolver recovers1995 literal calls in89 files and2252
   inventory strings. It parses data and executes only project-owned Java
   arithmetic, not APK code. Resolved sources stay private.
4. `XXPICoreTunnelMain.Q(boolean)` performs a plain Volley StringRequest to the
   fixed public raw-GitHub URL in `tools/probe.py`; no custom headers/auth token
   are specified. Callback`h` opens the outer string through`gf1.a`/`df1.b`,
   native mode0. Unrelated cloud-share/account features are outside this task.
5. Original app loads`ovpn3`. ARM64 libovpn3 SHA256
   `7ead852bccaa5b17f62d145ea97915f7ea04c579891576f8466a22bb48dd2765`.
   `RenzUtils_decrypt` at0x3a6c7c dispatches0/main,1/special,2/sensitive and3/Dex.
   Mode0 reads seed0x20ad38/32bytes and IV0x20ad58/16bytes. HKDF16 uses salt
   0x20ad18/16bytes; FIXED_SALT at0x20add4/32bytes supplies HKDF32/PBKDF2.
   Extracted material exactly matches the existing Xhypher43 profile. No
   extracted authentication secret is needed for the public updater.
6. The5008byte raw resource`res/a_/drlb`, ID0x7f100003, goes through mode3
   `decryptDex` at startup. It is **not certified as an included catalog**.
   The early included-catalog hypothesis was discarded after following this
   dispatch. There is no static fallback or APK execution.

## Confirmed cipher and field mapping

Mode0: Base64 → AES128-CBC/SHA256(seed)[:16], fixed IV, PKCS7 → modified XXTEA
→ UTF8. Mode1: Base64 → Threefish256 with HKDF32 and tweaks[index,index*192]
→ remove zero fill to the AES block boundary → AES128-CBC/HKDF16 → UTF8.
Mode2: invisible U+200B/U+200C bits, U+200D filler, adjacent bit swap/XOR0x5a
→ modified XXTEA/PBKDF2-HMAC-SHA256(100000,32) → IV-prefixed AES256-CBC.
This preserves ciphertext zeros through the AES boundary, rather than the
native bytewise trim which may remove legitimate ciphertext bytes.

The production codec reuses unchanged, independently matched Xhypher cipher
primitives and maintains a separate XXPICore schema. Server names/subnames,
ports, flags, DNS, obfs/certificates and UUID use mode0; server hosts, V2Ray
paths/hosts and network SNI/payload/custom JSON use mode1; usernames/passwords
use mode2. Network proxy, UDP options, Info/DNS/TLS fields and SlowDNS fields
use mode0. `df1.b/c` consumers in Main, selectors/adapters and the field tables
are reproduced independently in `verify.py`. Entire JSON, unknown fields and
optional empty/null values are retained; corruption fails the whole operation.

## Real and synthetic verification

The public GET returned200/text/plain,1404248bytes,
SHA256`5778e674aa2bdf87352070a80d908b4d655c5c6d5aa5b1ba401f68a7b5f7be48`.
Outer JSON2.427 contains64 servers and1240 networks. Independent Java/JCA opens
the outer and all7837 encrypted fields (3094 unique):6047 mode0,1718 mode1,
72 mode2. Full-object equality matches production, real CLI download and the
child-isolated Cloud worker. Rendered output873193bytes, SHA256
`bc9748c31ccad775385f0d7c7aa00220acf2b02e157f9f2b447d0dfde111b2f7`.
Nine real fields also match the original isolated ARM64 XXTEA/Threefish/carrier
primitives against JCA/Python, with no JNI/startup/OS/network executed.

Node live transport returns`REMOTE_NETWORK_DENIED` in this executor; this is
an environment result, not a provider outage. Explicitly simulated HTTP using
the actual encrypted response and actual worker result passes. TLS, DNS,
redirect, size, HTML, complete-result, availability and version contracts are
tested with fictional fixtures; these tests do not substitute real egress.
CBC/XXTEA lack an authenticity tag, so equality verifies compatibility, not an
origin signature. No Android build, workflow/artifact waiting, merge or deploy.
