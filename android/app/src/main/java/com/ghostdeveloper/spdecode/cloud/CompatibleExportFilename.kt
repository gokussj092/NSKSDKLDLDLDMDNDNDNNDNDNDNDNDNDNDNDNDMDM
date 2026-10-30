package com.ghostdeveloper.spdecode.cloud

internal object CompatibleExportFilename {
    fun forSource(original:String,suffix:String):String {
        require(suffix.matches(Regex("[a-z0-9]{1,8}")))
        val leaf=original.replace('\\','/').substringAfterLast('/')
        val base=leaf.substringBeforeLast('.',leaf).filterNot {
            it.isISOControl() || it in "<>:\"/\\|?*" || it in '\u202a'..'\u202e' || it in '\u2066'..'\u2069'
        }.trim().trimEnd('.', ' ')
        val clean=base.removeSuffix(" (Unlocked)").ifBlank { "config" }
        // Keep Unicode code points intact and leave room for suffix on common filesystems.
        val limited=StringBuilder()
        var used=0; var offset=0
        while(offset<clean.length) {
            val cp=clean.codePointAt(offset);val next=String(Character.toChars(cp))
            val n=next.toByteArray(Charsets.UTF_8).size
            if(used+n>180)break
            limited.append(next);used+=n;offset+=Character.charCount(cp)
        }
        return "$limited (Unlocked).$suffix"
    }
}
