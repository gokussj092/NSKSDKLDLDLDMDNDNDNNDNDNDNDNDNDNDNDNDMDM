"""HTTP Door: original JDK crypto/Properties, full worker and Termux bundle."""
from __future__ import annotations
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from decoders.Python.apps.HTTP_Door import codec, file_decoder
from scripts.apk_analysis.http_door_bundle import build

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cloud/workers/python"))
HEADER = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">\n'
XML = [HEADER + '<properties><comment>Archivo de Configuracion</comment><entry key="file.appVersionCode">5</entry><entry key="file.proteger">0</entry><entry key="sshServidor">example.invalid</entry><entry key="file.pedirLogin">1</entry><entry key="sshSenha">synthetic-password</entry></properties>',
       HEADER + '<properties><entry key="file.proteger">1</entry><entry key="file.validade">1</entry><entry key="bloquearRoot">1</entry><entry key="blockHwid">1</entry><entry key="hwidstring">synthetic-device</entry><entry key="onlydata">1</entry><entry key="blockOperator">1</entry><entry key="unknown">keep</entry></properties>',
       HEADER + '<properties><entry key="duplicate">first</entry><entry key="duplicate">last</entry><entry key="empty"/><entry key="emoji">&#xd83d;&#xde00; &#55357;&#56832;</entry><entry key="multiline">uno&#13;\ndos\nñ &amp; 中</entry><entry key="">empty key</entry></properties>']


def oracle(pairs):
    incoming = ''.join(mode + '\t' + base64.b64encode(data).decode() + '\n' for mode, data in pairs)
    result = subprocess.run(['java', str(ROOT / 'tests/golden/http_door_oracle.java')],
                            input=incoming, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise AssertionError(result.stderr)
    return [(base64.b64decode(a), json.loads(base64.b64decode(b)))
            for a, b in (line.split('\t') for line in result.stdout.splitlines())]


class HttpDoorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = oracle([('seal', xml.encode()) for xml in XML])

    def test_all_full_documents_equal_jdk_and_keep_order_duplicates_and_raw_xml(self):
        opened = oracle([('open', cipher) for cipher, _ in self.vectors])
        for xml, (cipher, props), (plain, again) in zip(XML, self.vectors, opened):
            actual = codec.decode(cipher)
            self.assertEqual(actual['format'], 'http-door-des-properties')
            self.assertEqual(actual['properties'], props)
            self.assertEqual(again, props)
            self.assertEqual(actual['raw_xml'], xml)
            self.assertEqual(plain, xml.encode())
            self.assertEqual({e['key']: e['value'] for e in actual['entries']}, props)
            self.assertEqual(json.loads(file_decoder.run(cipher)), actual)
        actual = codec.decode(self.vectors[2][0])
        self.assertEqual([e['value'] for e in actual['entries'] if e['key'] == 'duplicate'], ['first', 'last'])
        self.assertEqual(actual['properties']['emoji'], '😀 😀')
        self.assertEqual(actual['properties']['empty'], '')

    def test_import_restrictions_do_not_require_user_secrets_or_alter_flags(self):
        props = codec.decode(self.vectors[1][0])['properties']
        self.assertEqual(props, self.vectors[1][1])
        self.assertEqual(props['blockHwid'], '1')
        self.assertEqual(props['file.validade'], '1')
        self.assertEqual(codec.decode(self.vectors[0][0])['properties']['sshSenha'], 'synthetic-password')

    def test_invalid_ciphertext_padding_limits_and_other_wire_formats_fail(self):
        cipher = self.vectors[0][0]
        for data in (b'', b'x' * (codec.MAX_BYTES + 1), cipher[:-1], cipher[:-8], bytes(16),
                     base64.b64encode(cipher), b'aa.bb.cc', b'<properties/>', b'{"Version":"1"}'):
            with self.assertRaises(ValueError):
                codec.decode(data)
        with self.assertRaises(ValueError):
            codec.render({'x': 'x' * codec.MAX_BYTES})

    def test_xml_entity_dtd_wrong_root_nested_entries_and_bad_utf8_fail(self):
        for xml in (b'<!DOCTYPE properties [<!ENTITY x "secret">]><properties><entry key="x">&x;</entry></properties>',
                    b'<!DOCTYPE properties SYSTEM "https://attacker.invalid/x"><properties><entry key="x">a</entry></properties>',
                    b'<root><entry key="x">a</entry></root>', b'<properties/>',
                    b'<properties><entry key="x"><child/></entry></properties>',
                    b'<properties><entry key="x">&#xd83d;</entry></properties>',
                    b'<properties><entry key="x">\xff</entry></properties>'):
            cipher = DES.new(b'cinbdf66', DES.MODE_ECB).encrypt(pad(xml, 8))
            with self.assertRaises(ValueError): codec.decode(cipher)

    def test_worker_and_authenticated_http_handler_return_complete_document(self):
        from cloud.workers.python import engine, server
        with patch('socket.create_connection', side_effect=AssertionError('offline')):
            for cipher, _ in self.vectors:
                expected = codec.decode(cipher)
                actual = engine.decode_file('kyz', cipher)
                self.assertEqual(actual['structuredJson'], expected)
                self.assertEqual(json.loads(actual['rawText']), expected)
                self.assertFalse(actual['isPartial'])
                body = json.dumps({'format': 'kyz', 'dataBase64': base64.b64encode(cipher).decode()}).encode()
                replies = []
                fake = SimpleNamespace(path='/internal/v1/decode/file', headers={'Content-Length': str(len(body))},
                    rfile=io.BytesIO(body), _authorized=lambda: True, _json=lambda code, value: replies.append((code, value)))
                server.WorkerHandler.do_POST(fake)
                self.assertEqual(replies[0][0], 200)
                self.assertEqual(replies[0][1]['structuredJson'], expected)

    def test_registry_public_format_and_catalog_do_not_invent_remote_provider(self):
        from spdecode.registry import get_decoder, get_supported_extension
        from cloud.workers.python.engine import load_file_engines, load_runtime_file_engines
        self.assertNotIn('kyz', load_file_engines())
        self.assertEqual(get_supported_extension('synthetic.KYZ'), 'kyz')
        self.assertTrue(get_decoder('kyz').script.endswith('/HTTP_Door/file_decoder.py'))
        self.assertEqual(load_runtime_file_engines()['kyz']['name'], 'HTTP Door 5.0')
        formats = json.loads((ROOT / 'cloud/web/content/file-formats.json').read_text())['formats']
        route = next(row for row in formats if row['suffix'] == 'kyz')
        self.assertFalse(route['offlineSupported'])
        self.assertTrue(route['cloudSupported'])
        self.assertEqual(route['credentialFields'], [])
        for name in ('server-vpn-catalog.mjs', 'server-vpn-provider.mjs'):
            self.assertNotIn('http-door', (ROOT / 'cloud/web/lib' / name).read_text())

    def test_cli_and_standalone_bundle_outside_repository_private_save_no_overwrite(self):
        self.assertEqual((ROOT / 'decoders/Python/apps/HTTP_Door/http_door.py').read_text('utf-8'), build())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            standalone = root / 'http_door.py'
            standalone.write_text(build(), encoding='utf-8')
            profile = root / 'synthetic.kyz'
            env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH'}
            for script in (ROOT / 'decoders/Python/apps/HTTP_Door/file_decoder.py', standalone):
                for cipher, _ in self.vectors:
                    profile.write_bytes(cipher)
                    for argv, incoming in (([str(profile)], None), (['-'], cipher)):
                        result = subprocess.run([sys.executable, str(script), *argv], input=incoming,
                            capture_output=True, cwd=folder, env=env, timeout=20)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(json.loads(result.stdout), codec.decode(cipher))
                result = subprocess.run([sys.executable, str(script), '-'], input=b'private-invalid-input',
                    capture_output=True, cwd=folder, env=env, timeout=20)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b'')
                self.assertNotIn(b'private-invalid-input', result.stderr)
            output = root / 'profile.json'
            argv = [sys.executable, str(standalone), str(profile), '--output', str(output)]
            result = subprocess.run(argv, capture_output=True, cwd=folder, env=env, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            before = output.read_bytes()
            result = subprocess.run(argv, capture_output=True, cwd=folder, env=env, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(output.read_bytes(), before)
            verified = subprocess.run([sys.executable, str(ROOT / 'scripts/apk_analysis/http_door_verify.py'),
                str(profile), '--worker'], capture_output=True, cwd=folder, env=env, timeout=30)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertTrue(json.loads(verified.stdout)['jdkCompleteMatch'])
            self.assertTrue(json.loads(verified.stdout)['workerCompleteMatch'])


if __name__ == '__main__': unittest.main()
