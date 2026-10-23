package com.ghostdeveloper.spdecode

/**
 * Android providers can append a duplicate counter AFTER a filename extension.
 * This is a routing-only basename; never rename the SAF Uri, decrypted bytes,
 * imported result, history or exported original name.
 */
object ImportFilenameNormalizer {
    private val duplicateCounter = Regex(""" ?\([1-9][0-9]{0,5}\)$""")

    fun forDetection(filename: String): String {
        val basename = filename.substringAfterLast('/').substringAfterLast('\\')
        val match = duplicateCounter.find(basename) ?: return basename
        val candidate = basename.substring(0, match.range.first)
        val lastDot = candidate.lastIndexOf('.')
        // A suffix needs a nonempty basename and cannot contain whitespace.
        if (lastDot <= 0 || lastDot == candidate.lastIndex ||
            candidate.substring(lastDot + 1).any { it.isWhitespace() }) return basename
        return candidate
    }
}
