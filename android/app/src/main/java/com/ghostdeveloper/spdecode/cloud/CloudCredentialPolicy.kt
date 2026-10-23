package com.ghostdeveloper.spdecode.cloud

/** Format-specific credential gates; never retry one family's failed auth using another codec. */
internal object CloudCredentialPolicy {
    private val filePasswords = setOf("hc","ua","npvs","1ftnl","tut")
    private val simpleDialogs = setOf("ua","npvs","1ftnl","tut")
    private val npvPrefixes = listOf("npvt://","npvt-ssh://",
        "npvt-vless://","npvt-vmess://","npv://")
    private val onefPrefixes = listOf("1FTnl.","1FT1.",
        "1ftunnel://1FTnl/","1ftunnel://1FT1/")

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
