package com.ghostdeveloper.spdecode.parity

import android.content.Context

/**
 * Deterministic offline Android reference dispatcher.
 *
 * A suffix maps to exactly one original decoder. No fallback to unrelated
 * cryptographic keys, no key brute forcing, no networking or subprocess.
 * Not exposed to users until the SAF/import UI and vendor validation gates.
 */
object AndroidOfflineDecoderRouter {
    fun decode(context: Context, filename: String, input: ByteArray): String? =
        decodeInternal(context,filename,input,null,null)

    /** Source-specific password paths for HC and protected V2Box only.
     * Never retry another file family's cipher on authentication failure. */
    fun decodeWithUserPassword(context:Context,filename:String,input:ByteArray,password:ByteArray):String? {
        if(password.isEmpty() || password.size>4096)return null
        return decodeInternal(context,filename,input,password,null)
    }

    fun decodeWithCredentials(context:Context,filename:String,input:ByteArray,
        password:ByteArray?,hwid:String?):String? {
        if(password!=null && (password.isEmpty() || password.size>4096))return null
        if(hwid!=null && hwid.length>128)return null
        return decodeInternal(context,filename,input,password,hwid)
    }

    private fun decodeInternal(context: Context, filename: String, input: ByteArray,
        userPassword:ByteArray?, userHwid:String?): String? {
        if (input.isEmpty()) return null
        val format = AndroidDecoderCatalog.detect(filename, AndroidDecoderCatalog.read(context))
            ?: return null
        // Enforce exactly the same limit at the UI and native entrypoint.
        // The historical ports stay at 1 MiB; only B/C and the collided .ost
        // use the 2 MiB limit already implemented by their specific engines.
        val maxInput = when {
            format.suffix == "solid" -> NurTunnelPort.MAX_INPUT
            format.suffix == "lnk" -> LinkLayerPort.MAX_INPUT
            format.suffix == "npvs" -> NpvsPort.MAX_INPUT
            format.migrationPhase == "B" -> GenericVpnPort.MAX_INPUT_BYTES
            format.migrationPhase == "D" -> RenzPort.MAX_INPUT_BYTES
            format.migrationPhase == "E" -> SpecialCrypto.MAX
            format.migrationPhase == "F" -> IndependentCrypto.MAX
            format.migrationPhase == "C" || format.suffix == "ost" ->
                UltraSandokPort.MAX_INPUT_BYTES
            else -> LegacyPortPrimitives.MAX_INPUT
        }
        if (input.size > maxInput) return null
        if(userHwid!=null && (format.suffix!="hc" ||
            HcHccfgPort.inspectRequirements(input)?.requiresCredentials!=true))return null
        if(userPassword!=null && format.suffix=="v2box"){
            if(!com.ghostdeveloper.spdecode.cloud.V2BoxPasswordProbe.requiresPassword(input))
                return null
        } else if(userPassword!=null && (format.suffix!="hc" ||
            HcHccfgPort.inspectRequirements(input)?.requiresCredentials!=true ||
            !HcHccfgPort.requiresExternalPassword(input)))return null
        // Phase A: 178 bot-only suffixes are catalogued but have no native port.
        // Keep a hard gate before the old 61-case dispatcher to prevent
        // accidental treatment as a supported decoder or unrelated fallback.
        if (!format.hasNativeDecoder) return null
        // The 81 generic suffixes are explicitly selected by catalog phase,
        // never inserted into the old 61-case switch or treated as fallback.
        if (format.suffix == "solid") return NurTunnelPort.decodeSolid(context,input)
        if (format.migrationPhase == "B") {
            return GenericVpnPort.decode(context, format.suffix, input)
        }
        if (format.migrationPhase == "C") {
            return UltraSandokPort.decode(context, format.suffix, input)
        }
        if (format.migrationPhase == "D") {
            return RenzPort.decode(context, format.suffix, input)
        }
        // Family dispatch is based on audited native suffixes, never Python paths
        // shipped in assets or received from a remote catalog.
        if (format.migrationPhase == "E") {
            return when (format.suffix) {
                "apnalite","apnatnl","omanova","4ulite","bdnet",
                "hsome","ursa","fnf","hxt" -> SpecialE3Port.decode(format.suffix,input)
                "st","itv","eut","v2box","slipnet","juanscript","juan","mobi" ->
                    SpecialE1Port.decode(context,format.suffix,input,userPassword)
                else -> SpecialE2Port.decode(context,format.suffix,input)
            }
        }
        if (format.migrationPhase == "F") {
            return when (format.suffix) {
                "izph" -> IzphNativePort.decode(input)
                "flexnet","flex","ltm","lt","vn7" ->
                    IndependentF1Port.decode(context,format.suffix,input)
                "cerv","crev","cer","zoba","n4","dev","ktr" ->
                    IndependentF2Port.decode(context,format.suffix,input)
                else -> null
            }
        }
        return when (format.suffix) {
            "v2" -> V2RayReferencePort.decode(input)
            "tls" -> TlsReferencePort.decode(context,input)
            "phc" -> PhcPort.decode(context,input)
            "mina" -> MinaPort.decode(input)
            "vpnlite" -> VpnLitePort.decode(input)
            "cloudy" -> CloudyPort.decode(context,input)
            "mij" -> MijPort.decode(input)
            "fnnetwork" -> FnNetworkPort.decode(input)
            "uwu" -> UwuPort.decode(input)
            "sksrv" -> SksrvPort.decode(input)
            "maya" -> MayaPort.decode(input)
            "xui" -> XuiPort.decode(input)
            "at" -> AtPort.decode(input)
            "nm" -> NmPort.decode(input)
            "ost" -> OstPort.decode(input) ?: UltraSandokPort.decode(context, "ost", input)
            "sbr" -> SbrPort.decode(input)
            "pcx" -> PcxPort.decode(input)
            "nt" -> NtPort.decode(input)
            "pb" -> PbPort.decode(input)
            "aro" -> AroPort.decode(input)
            "ipt" -> IptPort.decode(input)
            "gold" -> GoldPort.decode(context,input)
            "agn" -> AgnPort.decode(input)
            "cly" -> ClyPort.decode(input)
            "fɴ" -> FnLegacyPort.decode(input)
            "jvc" -> JvcPort.decode(input)
            "jvi" -> JviPort.decode(input)
            "v2i" -> V2iPort.decode(input)
            "sksrv.png" -> SksrvPngPort.decode(input)
            "xscks" -> XscksPort.decode(input)
            "mrc" -> MrcPort.decode(input)
            "mtl" -> MtlPort.decode(input)
            "jez" -> JezPort.decode(input)
            "hrt" -> HrtPort.decode(input)
            "ziv" -> ZivPort.decode(context,input)
            "epro" -> EproPort.decode(context,input)
            "npv2" -> Npv2Port.decode(context,input)
            "rez" -> RezPort.decode(input)
            "rezl" -> RezlPort.decode(input)
            "tvt" -> TvtPort.decode(input)
            "stk" -> StkPort.decode(input)
            "xtp" -> XtpPort.decode(input)
            "roy" -> RoyPort.decode(input)
            "sksplus" -> SksplusPort.decode(input)
            "sks" -> SksPort.decode(context,input)
            "sut" -> SutPort.decode(input)
            "tnl" -> TnlPort.decode(context,input)
            "ssh" -> SshPort.decode(context,input)
            "ht" -> HtPort.decode(context,input)
            "htb" -> HtbPort.decode(context,input)
            "hat" -> HatPort.decode(context,input)
            "ehil" -> EhilPort.decode(context,input)
            "dark" -> DarkPort.decode(context,input)
            "ehi" -> EhiPort.decode(context,input)
            "npv4" -> Npv4Port.decode(context,input)
            "npvt" -> NpvtPort.decode(context,input)
            "npvs" -> NpvsPort.decode(context,input)
            "sip" -> SipPort.decode(context,input)
            "lnk" -> LinkLayerPort.decode(input)
            "ssc" -> SscPort.decode(input)
            "hc" -> HcPort.decode(context,input) ?: when {
                userHwid != null -> HcHccfgPort.decodeWithCredentials(
                    input,userPassword,userHwid)
                userPassword == null -> HcHccfgPort.decode(input)
                else -> HcHccfgPort.decodeWithUserPassword(input,userPassword)
            }
            else -> null
        }
    }
}
