"""Real APK QA upload/inspect tests. Uses synthetic structurally valid APKs only."""
from __future__ import annotations
import base64
from io import BytesIO
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile
from cloud.apk_analysis import qa_service as qa
from cloud.apk_analysis.input_gate import inspect_input


def fake_apk() -> bytes:
    manifest=b"\x03\x00\x08\x00"+b"\x08\x00\x00\x00"
    dex=bytearray(112)
    dex[:8]=b"dex\n035\x00"
    struct.pack_into("<I",dex,0x20,len(dex))
    struct.pack_into("<I",dex,0x38,17)
    struct.pack_into("<I",dex,0x58,5)
    struct.pack_into("<I",dex,0x60,3)
    output=BytesIO()
    with zipfile.ZipFile(output,"w",compression=zipfile.ZIP_STORED) as zip:
        zip.writestr("AndroidManifest.xml",manifest)
        zip.writestr("classes.dex",bytes(dex))
        zip.writestr("lib/arm64-v8a/libsample.so",b"\x7fELF"+b"\x00"*128)
        zip.writestr("assets/safe-data.json",b'{"test":1}')
        zip.writestr("res/raw/sample",b"testing")
    return output.getvalue()


class APKQAServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/"jobs"
        self.patcher=patch.object(qa,"ROOT",self.root)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.apk=fake_apk()
        self.owner="e"*64

    def start(self,raw=None,**kwargs):
        raw=self.apk if raw is None else raw
        args={"filename":"sample.apk","totalBytes":len(raw),
              "sha256":hashlib.sha256(raw).hexdigest(),
              "deviceKeyHash":self.owner,"consent":True,"qaFirstPass":True}
        args.update(kwargs)
        return qa.dispatch("start",args)

    def cap(self,started,**extra):
        return {"jobId":started["jobId"],"uploadToken":started["uploadToken"],
                "deviceKeyHash":self.owner,**extra}

    def chunk(self,started,data=None,index=0,**extra):
        data=self.apk if data is None else data
        args=self.cap(started,index=index,dataBase64=base64.b64encode(data).decode(),
                      chunkSha256=hashlib.sha256(data).hexdigest(),**extra)
        return qa.dispatch("chunk",args)

    def finished(self,started):
        state=qa.dispatch("finish",self.cap(started))
        self.assertEqual(state["status"],"PROCESSING")
        for i in range(120):
            status=qa.dispatch("result",self.cap(started))
            if status["status"] in ("COMPLETED","FAILED"):
                return status
            time.sleep(.025)
        self.fail("Worker did not finish bounded synthetic APK inspection")

    def test_actual_bytes_generate_real_static_report_without_executing_code(self):
        started=self.start()
        ack=self.chunk(started)
        self.assertEqual(ack["receivedBytes"],len(self.apk))
        result=self.finished(started)
        self.assertEqual(result["status"],"COMPLETED")
        report=result["report"]
        self.assertEqual(report["reportKind"],"APK_STATIC_QA_FIRST_PASS")
        self.assertEqual(report["input"]["sha256"],hashlib.sha256(self.apk).hexdigest())
        self.assertEqual(report["inventory"]["dexCount"],1)
        self.assertEqual(report["inventory"]["dexHeaders"][0]["classes"],3)
        self.assertEqual(report["inventory"]["dexHeaders"][0]["methods"],5)
        self.assertEqual(report["inventory"]["nativeLibraries"][0]["abi"],"arm64-v8a")
        self.assertEqual(report["analysis"]["codeExecuted"],False)
        self.assertEqual(report["analysis"]["vendorMethodValidated"],False)
        self.assertFalse((self.root/started["jobId"]/"input.apk").exists())
        self.assertFalse((self.root/started["jobId"]/"input.part").exists())

    def test_missing_consent_denied_without_creating_a_job(self):
        with self.assertRaises(qa.ApiError) as cm:self.start(consent=False)
        self.assertEqual(cm.exception.code,"CONSENT_REQUIRED")

    def test_zip_and_xapk_rejected_even_with_valid_archive_content(self):
        for name in ("sample.zip","sample.xapk","../other.apk"):
            with self.subTest(name=name),self.assertRaises(qa.ApiError):
                self.start(filename=name)

    def test_wrong_capability_and_wrong_hardware_owner_are_indistinguishable(self):
        started=self.start()
        with self.assertRaises(qa.ApiError) as cm:
            qa.dispatch("result",self.cap(started,uploadToken="X"*43))
        self.assertEqual(cm.exception.code,"JOB_UNAVAILABLE")
        with self.assertRaises(qa.ApiError) as cm:
            qa.dispatch("result",self.cap(started,deviceKeyHash="a"*64))
        self.assertEqual(cm.exception.code,"JOB_UNAVAILABLE")

    def test_full_sha256_verified_before_any_report(self):
        started=self.start()
        self.chunk(started,data=b"x"*len(self.apk))
        with self.assertRaises(qa.ApiError) as cm:
            qa.dispatch("finish",self.cap(started))
        self.assertEqual(cm.exception.code,"UPLOAD_HASH_MISMATCH")
        self.assertFalse((self.root/started["jobId"]/"input.part").exists())

    def test_cannot_finalize_incomplete_upload(self):
        started=self.start()
        with self.assertRaises(qa.ApiError) as cm:
            qa.dispatch("finish",self.cap(started))
        self.assertEqual(cm.exception.code,"UPLOAD_INCOMPLETE")

    def test_idempotent_retry_and_duplicate_mismatch(self):
        started=self.start()
        first=self.chunk(started)
        replay=self.chunk(started)
        self.assertEqual(first,replay)
        with self.assertRaises(qa.ApiError) as cm:
            self.chunk(started,data=b"wrong",index=0)
        self.assertEqual(cm.exception.code,"CHUNK_REPLAY_MISMATCH")

    def test_out_of_order_chunk_blocked(self):
        started=self.start()
        with self.assertRaises(qa.ApiError) as cm:
            self.chunk(started,index=1)
        self.assertEqual(cm.exception.code,"CHUNK_OUT_OF_ORDER")

    def test_bad_chunk_digest_denied(self):
        started=self.start()
        with self.assertRaises(qa.ApiError) as cm:
            self.chunk(started,chunkSha256="0"*64)
        self.assertEqual(cm.exception.code,"CHUNK_HASH_MISMATCH")

    def test_all_active_jobs_are_quota_bound(self):
        self.start()
        self.start()
        with self.assertRaises(qa.ApiError) as cm:
            self.start()
        self.assertEqual(cm.exception.code,"QA_BUSY")

    def test_missing_or_invalid_archive_does_not_claim_success(self):
        invalid=b"invalid binary apk not a zip"
        started=self.start(raw=invalid)
        self.chunk(started,data=invalid)
        result=self.finished(started)
        self.assertEqual(result["status"],"FAILED")
        self.assertEqual(result["report"]["error"],"STATIC_INSPECTION_FAILED")
        self.assertFalse((self.root/started["jobId"]/"input.apk").exists())

    def test_apks_bundle_accepts_valid_nested_base(self):
        outer=BytesIO()
        with zipfile.ZipFile(outer,"w",compression=zipfile.ZIP_STORED) as z:
            z.writestr("base.apk",self.apk)
        data=outer.getvalue()
        started=self.start(raw=data,filename="bundle.apks")
        self.chunk(started,data=data)
        result=self.finished(started)
        self.assertEqual(result["status"],"COMPLETED")
        self.assertEqual(result["report"]["input"]["format"],"APKS")
        self.assertEqual(result["report"]["input"]["apkCount"],1)

    def test_sensitive_bytes_are_not_in_persisted_state_or_report(self):
        started=self.start()
        self.chunk(started)
        report=self.finished(started)
        self.assertNotIn("uploadToken",json.dumps(report))
        path=self.root/started["jobId"]/"state.json"
        self.assertNotIn(started["uploadToken"],path.read_text("utf-8"))
        self.assertNotIn("APK_APPLICATION_CODE",path.read_text("utf-8"))


if __name__=="__main__":
    unittest.main()
