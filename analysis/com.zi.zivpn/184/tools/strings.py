#!/usr/bin/env python3
"""ZIVPN: dump manifest XML (intent filter data) + dex strings."""
import sys, re
from loguru import logger
logger.remove(); logger.add(sys.stderr, level="ERROR")

from androguard.core.apk import APK
from androguard.core.dex import DEX as Dex
from lxml import etree

APK_PATH = '/home/hatch/workspace/catalogs/zivpn/xapk/com.zi.zivpn.apk'

a = APK(APK_PATH)
xml = a.get_android_manifest_xml()
# print only intent-filter data elements and activity names
for el in xml.iter():
    tag = etree.QName(el).localname
    if tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
        print(f"[{tag}] {el.get('{http://schemas.android.com/apk/res/android}name')}")
    if tag == 'intent-filter':
        parent = el.getparent()
        pname = parent.get('{http://schemas.android.com/apk/res/android}name')
        print(f"  intent-filter of {pname}:")
        for child in el:
            ctag = etree.QName(child).localname
            attrs = {etree.QName(k).localname: v for k, v in child.attrib.items()}
            print(f"    {ctag}: {attrs}")
    if tag == 'meta-data':
        name = el.get('{http://schemas.android.com/apk/res/android}name')
        val = el.get('{http://schemas.android.com/apk/res/android}value')
        if name and ('scheme' in name.lower() or 'host' in name.lower() or 'zivpn' in name.lower() or 'zi' in name.lower()):
            print(f"  meta-data {name} = {val}")

print("\n=== DEX strings (URLs / hosts / schemes) ===")
import zipfile
z = zipfile.ZipFile(APK_PATH)
dex_names = [n for n in z.namelist() if n.endswith('.dex')]
print("dex files:", dex_names)
pat = re.compile(r'^(https?://[^\s"\'<>]{4,200}|[a-z][a-z0-9+.-]{1,20}://[^\s"\'<>]{1,200}|[a-z0-9.-]+\.(com|net|org|xyz|fun|top|site|online|store|io|app|dev|me|cc|info|biz|pro|vip)(/[^\s"\'<>]*)?)$', re.I)
found = set()
for dn in dex_names:
    data = z.read(dn)
    dex = Dex(data)
    for s in dex.get_strings():
        if not isinstance(s, str):
            continue
        if len(s) > 250:
            continue
        if pat.match(s) and (' ' not in s):
            found.add((dn, s))
for dn, s in sorted(found):
    print(f"  [{dn}] {s}")
