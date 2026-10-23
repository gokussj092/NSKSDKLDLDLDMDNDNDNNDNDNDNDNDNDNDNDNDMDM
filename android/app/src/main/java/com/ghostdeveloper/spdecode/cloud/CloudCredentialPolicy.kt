package com.ghostdeveloper.spdecode.cloud

/** Format-specific credential gates; never retry one family's failed auth using another codec. */
internal object CloudCredentialPolicy {
    private val filePasswords = setOf("hc","ua","npvs","1ftnl","tut")
    private val simpleDialogs = setOf("ua","npvs","1ftnl","tut")
    private val npvPrefixes = listOf("npvt://","npvt-ssh://",
        "npvt-vless://","npvt-vmess://","npv://")
    private val onefPrefixes = listOf("1FTnl.","1FT1.",
        "1ftunnel://1FTnl/","1ftunnel://1FT1/")

    /** Reusable across current and future password-capable file/text engines.
     * AUTH_FAILED must be returned by the authenticated worker; malformed
     * credential requests (INVALID_CREDENTIALS) are not wrong passwords.
     * If HWID is also involved, never assert the password alone was wrong.
     */
    fun incorrectPassword(code:String, submittedPassword:Boolean,
                          submittedHwid:Boolean=false):Boolean =
        code=="AUTH_FAILED" && submittedPassword && !submittedHwid

    /** An unsupported NPVS recipient/key scheme is a compatibility notice,
     * not damaged input, a wrong password, or a service failure. */
    fun npvsProtectionNotice(code:String,format:String?):Boolean =
        format=="npvs" && code in setOf(
            "PRIVATE_KEY_REQUIRED","RECIPIENT_MISMATCH",
            "NPVS_PROTECTION_UNSUPPORTED"
        )

    /** Expected user/format outcomes must not become client error telemetry. */
    fun expectedCredentialResponse(code:String):Boolean =
        code in setOf("PASSWORD_REQUIRED","HWID_REQUIRED",
            "HWID_PASSWORD_REQUIRED","AUTH_FAILED","INVALID_CREDENTIALS",
            "PRIVATE_KEY_REQUIRED","RECIPIENT_MISMATCH",
            "NPVS_PROTECTION_UNSUPPORTED")

    fun fileAcceptsPassword(suffix:String):Boolean = suffix in filePasswords
    fun fileNeedsPasswordDialog(suffix:String):Boolean = suffix in simpleDialogs

    fun textAcceptsPassword(text:String):Boolean {
        val candidate=text.trim()
        return (candidate.startsWith("ua://",ignoreCase=true) &&
            candidate.length>"ua://".length) ||
            npvPrefixes.any { candidate.startsWith(it,ignoreCase=true) &&
                candidate.length>it.length } ||
            onefPrefixes.any { candidate.startsWith(it) &&
                candidate.length>it.length }
    }
}
