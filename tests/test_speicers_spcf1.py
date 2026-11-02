"""Build123 signed catalog/publication, synthetic fixtures only."""
import base64
import hashlib
import hmac
import json
import unittest
from unittest.mock import patch
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from decoders.Python.apps.Speicers_Pro_VPN import server_catalog_decoder as codec
from tests.test_speicers_pro import catalog


def url64(raw):return base64.urlsafe_b64encode(raw).decode().rstrip('=')


class SpeicersSpcfTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.test_key=RSA.generate(2048)  # Ephemeral test key, never persisted.

    def setUp(self):
        p=patch.object(codec,'SPCF_PUBLIC_KEY',base64.b64encode(self.test_key.public_key().export_key(format='DER')).decode())
        p.start();self.addCleanup(p.stop)

    def signed(self,payload):
        encoded=url64(json.dumps(payload,separators=(',',':')).encode())
        return json.dumps({'alg':'RS256','payload':encoded,'signature':url64(pkcs1_15.new(self.test_key).sign(SHA256.new(encoded.encode())))},separators=(',',':')).encode()

    def fixture(self):
        salt,nonce=bytes(range(32)),bytes(range(12))
        password=url64(hmac.new(codec.SPCF_HMAC_KEY,b'SPEICERS_FILE_PASSWORD_V1\0'+codec.CATALOG_PASSWORD,'sha256').digest()).encode()
        key=hashlib.pbkdf2_hmac('sha256',password,salt,600000,32)
        cipher=AES.new(key,AES.MODE_GCM,nonce=nonce)
        cipher.update(f'SPCF1|netfree.mx.store|servers|a8d4e7d79e33bcb8|600000|{url64(salt)}'.encode())
        source=catalog();source['Version']='1'
        ciphertext,tag=cipher.encrypt_and_digest(json.dumps(source).encode())
        obj={'v':1,'app':'netfree.mx.store','kind':'servers_file','format':'SPCF1','key_id':'a8d4e7d79e33bcb8',
             'kdf':'PBKDF2-HMAC-SHA256','iterations':600000,'salt':url64(salt),'nonce':url64(nonce),'ciphertext':url64(ciphertext+tag)}
        data=b'SPCF1\n'+self.signed(obj);digest=hashlib.sha256(data).hexdigest()
        manifest={'v':1,'app':'netfree.mx.store','kind':'server_update','origin':codec.UPDATE_ORIGIN,'format':'SPCF1',
                  'min_app_code':121,'version':'1','sha256':digest,'size':len(data),'count':2,
                  'url':f'{codec.UPDATE_ORIGIN}/updates/servers/1/{digest}.png'}
        return obj,data,manifest

    def test_complete_signed_catalog_and_gcm_fields(self):
        _,data,_=self.fixture();result=codec.decode_catalog(data)
        self.assertEqual(len(result['Servers']),2)
        self.assertEqual(result['Servers'][0][codec.FIELD_NAMES['sName']],'Servidor A')
        self.assertEqual(result['Servers'][0]['unknown'],{'keep':[True,None,0]})
        self.assertFalse(result['Servers'][0]['enabled'])

    def test_invalid_signature_stops_before_kdf_and_no_legacy_fallback(self):
        _,data,_=self.fixture();outer=json.loads(data[6:]);outer['signature']=url64(bytes(256))
        with patch.object(codec.hashlib,'pbkdf2_hmac',side_effect=AssertionError('KDF before authentication')):
            with self.assertRaises(ValueError):codec.decode_catalog(b'SPCF1\n'+json.dumps(outer).encode())
        with patch.object(codec,'_request_update',return_value=b'{}'),patch.object(codec,'download_legacy',side_effect=AssertionError('fallback')):
            with self.assertRaises(ValueError):codec.download()

    def test_signed_incompatible_parameters_and_invalid_tag_fail(self):
        original,_,_=self.fixture()
        for fields in ({'iterations':True},{'iterations':600001},{'app':'different.app'},{'kind':'users_file'},
                       {'key_id':'unknown'},{'nonce':url64(bytes(13))},{'ciphertext':url64(bytes(32))}):
            with self.subTest(fields=list(fields)),self.assertRaises(ValueError):
                codec.decode_catalog(b'SPCF1\n'+self.signed({**original,**fields}))

    def test_signed_publication_cannot_choose_foreign_or_unbound_path(self):
        _,_,manifest=self.fixture()
        for fields in ({'url':'https://example.invalid/'},{'url':codec.UPDATE_ORIGIN+'/private'},
                       {'min_app_code':123},{'version':'../1'},{'version':'01'},{'version':'2147483648'},{'sha256':'a'*63},{'count':True},{'size':3000001}):
            with self.subTest(fields=list(fields)),self.assertRaises(ValueError):codec.update_manifest(self.signed({**manifest,**fields}))
        self.assertEqual(codec.update_manifest(self.signed(manifest)),manifest)

    def test_download_two_gets_and_signed_size_hash_count_binding(self):
        _,data,manifest=self.fixture()
        with patch.object(codec,'_request_update',side_effect=[self.signed(manifest),data]) as request:
            self.assertEqual(codec.download(),data)
            self.assertEqual(request.call_args_list[0].args,(codec.UPDATE_MANIFEST_URL,16000,'application/json'))
            self.assertEqual(request.call_args_list[1].args,(manifest['url'],3000000,'application/octet-stream'))
        for changed in ({'size':len(data)+1},{'count':1},{'sha256':'a'*64,'url':codec.UPDATE_ORIGIN+'/updates/servers/1/'+'a'*64+'.png'}):
            with patch.object(codec,'_request_update',side_effect=[self.signed({**manifest,**changed}),data]):
                with self.assertRaises(ValueError):codec.download()

    def test_original_update_headers_and_bounds(self):
        class Response:
            status=200;headers={}
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):self.limit=limit;return b'{}'
        response=Response()
        class Opener:
            def open(self,request,timeout):self.request=request;self.timeout=timeout;return response
        opener=Opener()
        with patch.object(codec,'build_opener',return_value=opener):
            self.assertEqual(codec._request_update(codec.UPDATE_MANIFEST_URL,16000,'application/json'),b'{}')
        self.assertEqual(opener.request.get_method(),'GET')
        self.assertEqual(opener.request.get_header('Cache-control'),'no-cache')
        self.assertEqual(opener.request.get_header('Accept'),'application/json')
        self.assertEqual(opener.request.get_header('User-agent'),'Dalvik/2.1.0')
        self.assertEqual(response.limit,16001);self.assertEqual(opener.timeout,20)


if __name__=='__main__':unittest.main()
