package com.ghostdeveloper.attestation

import com.android.keyattestation.verifier.*
import com.android.keyattestation.verifier.testing.*
import com.google.protobuf.ByteString
import java.math.BigInteger
import java.security.cert.TrustAnchor
import java.time.Instant
import java.time.LocalDate
import java.time.YearMonth
import java.util.Base64
import kotlin.test.*

class PolicyTest {
    @Test fun revocationParserRejectsSuspendedKeysAndMalformedResponses() {
        assertEquals(setOf("1","2"),parseRevocations("""{"entries":{"01":{"status":"REVOKED"},"2":{"status":"SUSPENDED"}}}"""))
        assertFails { parseRevocations("""{"entries":{"1":{"status":"UNKNOWN"}}}""") }
        assertFails { parseRevocations("{}") }
    }
    private val factory=KeyAttestationCertPathFactory(FakeCalendar(LocalDate.now()))
    private val challenge=ByteString.copyFrom(ByteArray(32) { it.toByte() })
    private val digest=ByteString.copyFrom(ByteArray(32) { 0xa1.toByte() })
    private val app=AttestationApplicationId(setOf(AttestationPackageInfo("com.ghostdeveloper.spdecode",BigInteger.valueOf(34))),setOf(digest))
    private val policy=Policy("com.ghostdeveloper.spdecode",setOf(digest),BigInteger.valueOf(33),"tee",12)
    private fun verifier(revoked:Set<String> = emptySet(), googleRoots:Boolean = false)=Verifier(
        { if(googleRoots) GoogleTrustAnchors() else setOf(TrustAnchor(factory.root,null)) },
        { revoked }, { Instant.now() },app,
        ConstraintConfig(attestationApplicationId=AttestationApplicationIdConstraint.STRICT))
    private fun description(locked:Boolean=true, patch:YearMonth=YearMonth.now(),
        level:SecurityLevel=SecurityLevel.TRUSTED_ENVIRONMENT,
        vendorPatch:YearMonth?=patch, bootPatch:YearMonth?=patch,
        osPatch:YearMonth?=patch)=KeyDescription(
        BigInteger.valueOf(400),level,BigInteger.valueOf(400),level,challenge,ByteString.EMPTY,
        AuthorizationList(attestationApplicationId=app),
        AuthorizationList(origin=Origin.GENERATED,
            rootOfTrust=RootOfTrust(ByteString.copyFrom(ByteArray(32)),locked,VerifiedBootState.VERIFIED),
            osPatchLevel=osPatch?.let { PatchLevel(it) },vendorPatchLevel=vendorPatch?.let { PatchLevel(it) },
            bootPatchLevel=bootPatch?.let { PatchLevel(it) }))
    private fun evidence(description:KeyDescription=description()):Evidence {
        val chain=factory.generateCertPath(description).certificatesWithAnchor
        return Evidence(chain.map { Base64.getEncoder().encodeToString(it.encoded) },
            Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.toByteArray()),
            Base64.getUrlEncoder().withoutPadding().encodeToString(chain.first().publicKey.encoded))
    }
    @Test fun acceptsCryptographicallyVerifiedHardwareEvidence() {
        assertTrue(decide(evidence(),policy,verifier()).valid)
    }
    @Test fun productionRootsRejectSyntheticCertificateAuthority() {
        assertFalse(decide(evidence(),policy,verifier(googleRoots=true)).valid)
    }
    @Test fun acceptsValidHardwareWithoutOptionalVendorAndBootPatches() {
        // Android's schema permits omitted vendor/boot patch fields.
        val optionalMissing=evidence(description(vendorPatch=null,bootPatch=null))
        assertTrue(decide(optionalMissing,policy,verifier()).valid)
    }
    @Test fun rejectsMissingOrStaleMandatorySystemPatch() {
        assertFalse(decide(evidence(description(osPatch=null)),policy,verifier()).valid)
        assertFalse(decide(evidence(description(osPatch=YearMonth.now().minusMonths(13))),
            policy,verifier()).valid)
        assertFalse(decide(evidence(description(vendorPatch=YearMonth.now().minusMonths(13))),
            policy,verifier()).valid)
    }
    @Test fun rejectsWrongChallengeAndPublicKey() {
        val e=evidence()
        assertFalse(decide(e.copy(challenge=Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32))),policy,verifier()).valid)
        assertFalse(decide(e.copy(publicKey=e.publicKey.dropLast(1)+if(e.publicKey.last()=='A')"B" else "A"),policy,verifier()).valid)
    }
    @Test fun rejectsUnlockedSoftwareStalePatchesAndWrongApp() {
        assertFalse(decide(evidence(description(locked=false)),policy,verifier()).valid)
        assertFalse(decide(evidence(description(patch=YearMonth.now().minusMonths(13))),policy,verifier()).valid)
        assertFalse(decide(evidence(description(level=SecurityLevel.SOFTWARE)),policy,verifier()).valid)
        assertFalse(decide(evidence(),policy.copy(packageName="com.other.app"),verifier()).valid)
    }
    @Test fun compatibilityPolicyAcceptsOlderPatchesOnlyDuringBoundedWindow() {
        val oldPatch=YearMonth.now().minusMonths(30)
        val unmodified=evidence(description(patch=oldPatch))
        assertFalse(decide(unmodified,policy,verifier()).valid)
        val approved=DeviceAdmission(36,true,true,System.currentTimeMillis()+3600000)
        assertTrue(decide(unmodified.copy(devicePolicy=approved),policy,verifier()).valid)
        assertFalse(decide(unmodified.copy(devicePolicy=approved.copy(patchMonths=24)),
            policy,verifier()).valid)
        assertFalse(decide(unmodified.copy(devicePolicy=approved.copy(expiresAt=System.currentTimeMillis()-1000)),
            policy,verifier()).valid)
    }
    @Test fun compatibilitySwitchesCanRelaxPatchAndBootWithoutSkippingTrustRootsOrIdentity() {
        val test=DeviceAdmission(48,false,false,System.currentTimeMillis()+3600000)
        val oldUnlocked=evidence(description(locked=false,patch=YearMonth.now().minusMonths(50)))
        assertFalse(decide(oldUnlocked,policy,verifier()).valid)
        assertTrue(decide(oldUnlocked.copy(devicePolicy=test),policy,verifier()).valid)
        assertFalse(decide(oldUnlocked.copy(devicePolicy=test.copy(enforceBoot=true)),policy,verifier()).valid)
        assertFalse(decide(oldUnlocked.copy(devicePolicy=test),policy,verifier(googleRoots=true)).valid)
        assertFalse(decide(oldUnlocked.copy(devicePolicy=test),policy.copy(packageName="com.wrong.app"),verifier()).valid)
        assertFalse(decide(oldUnlocked.copy(devicePolicy=test.copy(expiresAt=System.currentTimeMillis()+72*3600000)),
            policy,verifier()).valid)
    }
    @Test fun strongboxPolicyRejectsTeeAndRevokedChains() {
        assertFalse(decide(evidence(),policy.copy(level="strongbox"),verifier()).valid)
        val e=evidence()
        val chain=factory.generateCertPath(description()).certificatesWithAnchor
        assertFalse(decide(e,policy,verifier(setOf(chain[1].serialNumber.toString(16)))).valid)
    }
}
