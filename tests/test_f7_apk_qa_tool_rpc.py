"""Real local HTTP tests for the isolated F7 tooling worker upload protocol.

Use the same synthetic APK fixture as QA. No real decompiler or third-party
APK is executed; the heavy tool is replaced only after auth/hash/ZIP gate.
"""
from __future__ import annotations
import hashlib
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cloud.apk_analysis import qa_tool_rpc as rpc
from cloud.apk_analysis import qa_tool_worker as worker
from tests.test_f7_apk_qa_service import fake_apk


class ToolWorkerRPC(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.token="A"*48
        self.original=os.environ.copy()
        self.envpatch=patch.dict(os.environ,{
            "SPDECODE_APK_QA_TOOLS_TOKEN":self.token,
            "SPDECODE_APK_QA_TOOLS_SCRATCH":self.tmp.name,
        })
        self.envpatch.start()
        self.addCleanup(self.envpatch.stop)
        self.payload=fake_apk()
        self.path=Path(self.tmp.name)/"test.apk"
        self.path.write_bytes(self.payload)
        self.calls=[]
        def mocked_tooling(source,metadata):
            self.calls.append((source.stat().st_size,source.read_bytes()))
            return {
                "status":"PARTIAL_TOOLS_EXECUTED",
                "jadxExecuted":True,"ghidraExecuted":False,
                "jadx":{"status":"COMPLETED","candidateCallSites":[]},
                "ghidra":{"status":"NOT_INSTALLED_OR_VERIFIED"},
            }
        self.mocked=patch.object(worker,"inspect_tooling",side_effect=mocked_tooling)
        self.mocked.start()
        self.addCleanup(self.mocked.stop)
        self.server=worker.ThreadingHTTPServer(("127.0.0.1",0),worker.Handler)
        self.server.daemon_threads=True
        thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(lambda:(self.server.shutdown(),self.server.server_close(),thread.join(3)))

    def test_authenticated_private_upload_runs_only_after_complete_verified_bytes(self):
        response=rpc.inspect_remote(self.path,host="127.0.0.1",
                                    port=self.server.server_address[1])
        self.assertEqual(response["status"],"PARTIAL_TOOLS_EXECUTED")
        self.assertTrue(response["jadxExecuted"])
        self.assertTrue(response["isolatedWorker"])
        self.assertEqual(self.calls,[(len(self.payload),self.payload)])
        self.assertEqual(list(Path(self.tmp.name).glob("job-*")),[])
        self.assertNotIn(self.token,json.dumps(response))

    def request(self,data,*,correct_hash=None,secret=None,nonce=None):
        digest=correct_hash or hashlib.sha256(data).hexdigest()
        now=int(time.time())
        nonce=nonce or ("a"*32)
        token=secret or self.token
        conn=http.client.HTTPConnection("127.0.0.1",self.server.server_address[1],timeout=4)
        headers={
            "Content-Type":"application/octet-stream",
            "Content-Length":str(len(data)),
            "X-SP-Tool-Hash":digest,
            "X-SP-Tool-Time":str(now),
            "X-SP-Tool-Nonce":nonce,
            "X-SP-Tool-Ext":".apk",
            "X-SP-Tool-Mac":rpc.mac(token,len(data),digest,now,nonce,".apk"),
        }
        try:
            conn.request("POST","/analyze",body=data,headers=headers)
            r=conn.getresponse()
            return r.status,json.loads(r.read())
        finally:conn.close()

    def test_wrong_mac_cannot_upload_or_trigger_analyzer(self):
        code,_=self.request(self.payload,secret="B"*48)
        self.assertEqual(code,401)
        self.assertEqual(self.calls,[])

    def test_authenticated_hash_mismatch_rejected_before_analyzer(self):
        other=b"y"*len(self.payload)
        code,_=self.request(other,correct_hash=hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(code,422)
        self.assertEqual(self.calls,[])

    def test_nonce_replay_rejected(self):
        first,_=self.request(self.payload,nonce="c"*32)
        second,_=self.request(self.payload,nonce="c"*32)
        self.assertEqual((first,second),(200,401))
        self.assertEqual(len(self.calls),1)


if __name__=="__main__":unittest.main()
