"""C5 source gate: keep original decoders and secret material out of Cloud builds."""
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/"android/app"
GRADLE=(APP/"build.gradle.kts").read_text("utf-8")
CLOUD=APP/"src/cloud/java/com/ghostdeveloper/spdecode"
class CloudC5SourceIsolation(unittest.TestCase):
    def test_release_distribution_cannot_package_legacy_engines_or_qa(self):
        assert 'gradle.taskGraph.whenReady' in GRADLE
        # Only Cloud or the isolated Offline native variant may be shipped.
        # The old literal Cloud-only gate is intentionally no longer valid.
        assert 'require(enableCloud || nativeOffline)' in GRADLE
        assert 'require(!nativeOffline || !enableCloud)' in GRADLE
        assert 'require(!nativeOffline || !enablePlayAab)' in GRADLE
        assert 'if (nativeOffline) {' in GRADLE
        assert 'sourceSets.getByName("main").java.setSrcDirs(listOf(file("src/offlineNative/java")))' in GRADLE
        assert 'sourceSets.getByName("main").assets.setSrcDirs(emptyList<File>())' in GRADLE
        assert '} else if (enableCloud) {' in GRADLE
        assert 'sourceSets.getByName("main").java.setSrcDirs(listOf(cloudSourceRoot))' in GRADLE
        assert 'require(!enableQaBuild)' in GRADLE
    def test_original_sources_excluded(self):
        assert 'exclude("com/ghostdeveloper/spdecode/parity/**")' in GRADLE
        for name in ["TextProtocolDecoder.kt","TextPhaseGPort.kt","HttpInjectorCloudPort.kt","NurTunnelServerCatalog.kt"]:
            assert 'exclude("com/ghostdeveloper/spdecode/'+name+'")' in GRADLE
        assert 'java.setSrcDirs(listOf(cloudSourceRoot))' in GRADLE
    def test_cloud_assets_allowlist(self):
        assert 'from("src/main/assets/decoder_catalog.json")' in GRADLE
        assert 'assets.setSrcDirs(listOf(cloudAssetRoot))' in GRADLE
        assert 'if (!enableCloud) implementation("org.bouncycastle:bcprov-jdk18on:1.86")' in GRADLE
    def test_only_non_decrypting_adapters(self):
        source="\n".join(p.read_text("utf-8") for p in CLOUD.rglob("*.kt"))
        assert len(list(CLOUD.rglob("*.kt")))==5  # Four inert decoder adapters plus optional push bootstrap.
        for x in ["SIGN_KEY","RESPONSE_KEY","SecretKeySpec","Cipher.getInstance","XChaCha","HKDF","SecureAssetVault","hc-envelope-seal","libspdecode_cloud.so"]:
            assert x not in source,x
        assert "fun decode(context:Context,input:Input):String? = null" in source
    def test_hccfg_inspection_over_network(self):
        activity=(APP/"src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt").read_text("utf-8")
        client=(APP/"src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt").read_text("utf-8")
        assert "cloudClient.inspectHcRequirements(preview," in activity
        assert 'decodeFile("hc",bytes,onCompatibleExport=' in client
if __name__=="__main__":unittest.main()
