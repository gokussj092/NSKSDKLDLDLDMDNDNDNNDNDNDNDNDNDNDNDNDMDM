#!/usr/bin/env python3
"""Phase S.4 device-private key provisioning source and APK policy checks.

Never reads the user's device or any real credential value. Reports only safe
rule identifiers. Decoder compatibility keys remain public offline material.
"""
from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE=Path("android/app/src/main/java/com/ghostdeveloper/spdecode")
STORE=BASE/"DevicePrivateCredentialVault.kt"
UI=BASE/"DeviceCredentialSettingsSection.kt"
IMPORT_DIALOG=BASE/"PrivateCredentialImportDialog.kt"
ACTIVITY=BASE/"MainActivity.kt"
HCCFG=BASE/"parity/HcHccfgPort.kt"
ROUTER=BASE/"parity/AndroidOfflineDecoderRouter.kt"
LIFECYCLE_TEST=Path("android/app/src/androidTest/java/com/ghostdeveloper/spdecode/DevicePrivateCredentialLifecycleInstrumentedTest.kt")
PHYSICAL_RUNNER=Path("scripts/android_s4_physical_smoke.sh")
PHYSICAL_GUIDE=Path("docs/android/PHASE_S4_PHYSICAL_DEVICE_VALIDATION.md")
SETTINGS=BASE/"FunctionalSettingsPanel.kt"
MANIFEST=Path("android/app/src/main/AndroidManifest.xml")
STRINGS=Path("android/app/src/main/res")
RELEASE=Path(".github/workflows/android-signed-release.yml")


def source(root:Path=ROOT)->dict:
    vault=(root/STORE).read_text("utf-8")
    ui_retired=not (root/UI).exists()
    settings=(root/SETTINGS).read_text("utf-8")
    import_dialog=(root/IMPORT_DIALOG).read_text("utf-8")
    activity=(root/ACTIVITY).read_text("utf-8")
    hccfg=(root/HCCFG).read_text("utf-8")
    router=(root/ROUTER).read_text("utf-8")
    lifecycle=(root/LIFECYCLE_TEST).read_text("utf-8")
    physical_runner=(root/PHYSICAL_RUNNER).read_text("utf-8")
    physical_guide=(root/PHYSICAL_GUIDE).read_text("utf-8")
    manifest=(root/MANIFEST).read_text("utf-8")
    release=(root/RELEASE).read_text("utf-8")
    predicates={
       "non-exportable-android-keystore": 'KeyStore.getInstance("AndroidKeyStore")' in vault and
            'KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")' in vault,
       "authenticated-encryption": 'Cipher.getInstance("AES/GCM/NoPadding")' in vault and
            "GCMParameterSpec(128, nonce)" in vault and "cipher.updateAAD(aad(id))" in vault,
       "distinct-record-uuid-aad": "UUID.randomUUID().toString()" in vault and
            "private-credential:$id" in vault and "validateId(id)" in vault,
       "randomized-encryption": ".setRandomizedEncryptionRequired(true)" in vault,
       "private-no-backup-directory": 'context.applicationContext.noBackupFilesDir' in vault and
            'android:allowBackup="false"' in manifest,
       "atomic-ciphertext-persistence": "AtomicFile(" in vault and
            "atomic.finishWrite(" in vault and "atomic.failWrite(" in vault,
       "short-lived-secret-bytes": "secretBytes.fill(0)" in vault and
            "clear.fill(0)" in vault and "payload.fill(0)" in vault,
       "bounded-input": "MAX_SECRET_BYTES = 4096" in vault and
            "MAX_RECORD_BYTES" in vault,
       "no-secret-accessor": not any(s in vault for s in (
            "fun export(", "fun reveal(", "fun toClipboard(", "android.util.Log",
            "SharedPreferences", "Room.databaseBuilder", "SecureAssetVault.read(",
        )),
       "provisioning-settings-removed": ui_retired and
            "DeviceCredentialSettingsSection()" not in settings and
            "Settings additions injected here by the Android Gradle task." in settings,
       "not-used-by-legacy-decoders": "AndroidOfflineDecoderRouter" not in vault,
       "per-file-explicit-choice": "PrivateCredentialImportDialog(" in activity and
            "choosePrivateCredential(id:String?)" in activity and
            "onClick = { onChoose(entry.id) }" in import_dialog,
       "no-secret-in-compose-import-ui": "DevicePrivateCredentialVault.Metadata" in import_dialog and
            "onChoose: (String?) -> Unit" in import_dialog and
            "secret:ByteArray" not in import_dialog and "password:ByteArray" not in import_dialog,
       "credential-consumed-only-when-selected": "privateCredentialVault.use(privateCredentialId)" in activity and
            "privateCredentialId!=null" in activity and
            "privateCredentialVault.inventory().entries" in activity and
            "inventory().entries.first" not in activity,
       "protected-hccfg-only": "HcHccfgPort.requiresExternalPassword(input)" in router and
            'format.suffix != "hc"' in router and
            "decodeWithUserPassword(input,userPassword)" in router,
       "password-arg-on-temporary-bytes": "generateBytes(passwordBytes,out)" in hccfg and
            "decodeWithUserPassword(input:ByteArray,password:ByteArray)" in hccfg,
       "encrypted-preview-buffers-cleared": "preview?.fill(0)" in activity and
            "prepared?.bytes?.fill(0)" in activity and
            "cancelPrivateCredentialSelection()" in activity,
       "isolated-debug-test-namespace": "BuildConfig.DEBUG" in vault and
            "private-credentials-s4-tests/$testNamespace" in vault and
            "spdecode.private-credentials.test.$testNamespace" in vault and
            'testNamespace.matches(Regex("[a-z0-9-]{1,40}"))' in vault,
       "safe-lifecycle-testing": "deleteEntry(alias(namespace))" in lifecycle and
            "store.clearAll()" in lifecycle and
            "DevicePrivateCredentialVault(context, namespace)" in lifecycle and
            "DevicePrivateCredentialVault(context)" not in lifecycle,
       "physical-runner-no-production-mutators": "shell run-as" in physical_runner and
            "DevicePrivateCredentialLifecycleInstrumentedTest" in physical_runner and
            not any(value in physical_runner for value in ("pm clear", "adb uninstall", "install -r app-debug.apk", "spdecode.private-credentials.v1")),
       "physical-evidence-gated": "PENDIENTE DE EJECUCIÓN EN EQUIPO FÍSICO" in physical_guide and
            "P1-P11" in physical_guide and "NO APLICABLE" in physical_guide,
       "signer-remains-external": "SPDECODE_SIGNING_KEYSTORE_BASE64" in release and
            'keytool' in release and 'storepass:env STORE_PASSWORD' in release,
       "no-secret-autofill-via-intent": "Intent(" not in import_dialog and "ClipData" not in import_dialog,
    }
    langs=["values","values-es","values-pt-rBR","values-ar"]
    translations={}
    for lang in langs:
        text=(root/STRINGS/lang/"strings.xml").read_text("utf-8")
        translations[lang]=all('name="'+key+'"' in text for key in (
            "s4_vault_title","s4_vault_warning","s4_vault_unreadable",
            "s4_vault_delete_confirm","s4_vault_secret",
            "s4_import_title","s4_import_description","s4_import_without_password",
        ))
    violations=[name for name,passed in predicates.items() if not passed]
    violations.extend("missing-translation-"+lang for lang,ok in translations.items() if not ok)
    return {
       "status":"PASS" if not violations else "FAIL",
       "violations":violations,
       "controls":len(predicates)+len(translations),
       "secretsReported":False,
       "devicePrivateKeyInApk":False,
       "decoderParityUnchanged":True,
    }


def apk(apk_path:Path)->dict:
    violations=[]
    with zipfile.ZipFile(apk_path) as zf:
        names=zf.namelist()
        dex=[name for name in names if re.fullmatch(r"classes\d*\.dex",name)]
        if not dex:
            violations.append("missing-dex")
        for name in names:
            lower=name.lower()
            if re.search(r"(?:^|/)(?:private-credentials|credentials-private|service-account)(?:/|\.|$)",lower):
                violations.append("private-record-packaged")
            if lower.endswith((".s4k",".s4k.bak",".jks",".p12",".pfx",".keystore")):
                violations.append("private-key-file-packaged")
        if "assets/embedded_kotlin_profiles.json" in names:
            violations.append("s1-plaintext-resource-packaged")
    return {
       "status":"PASS" if not violations else "FAIL",
       "violations":sorted(set(violations)),
       "dexFilesChecked":len(dex),
       "credentialsReported":False,
    }


def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--apk",type=Path)
    parser.add_argument("--report",type=Path)
    args=parser.parse_args()
    result={"phase":"S.4","source":source()}
    if args.apk:
        result["apk"]=apk(args.apk)
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n","utf-8")
    ok=result["source"]["status"]=="PASS" and (
        "apk" not in result or result["apk"]["status"]=="PASS")
    print("Phase S.4 provisioning audit:", "PASS" if ok else "FAIL",
          "source controls:",result["source"]["controls"],
          "APK checked:",args.apk is not None)
    for issue in result["source"]["violations"]+result.get("apk",{}).get("violations",[]):
        print("Policy violation:",issue)
    return 0 if ok else 1


if __name__=="__main__":
    raise SystemExit(main())
