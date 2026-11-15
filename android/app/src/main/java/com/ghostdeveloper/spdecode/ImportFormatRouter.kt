package com.ghostdeveloper.spdecode

import com.ghostdeveloper.spdecode.cloud.CloudFileFormats
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog

/** The verified local Cloud snapshot is consulted before built-in routes.
 * Never guess a format from a MIME type or untrusted URI when suffix data is absent.
 */
internal object ImportFormatRouter {
    fun detect(
        filename:String,
        cloudEnabled:Boolean,
        verifiedFormats:List<AndroidDecoderCatalog.Format>,
        bundledFormats:()->List<AndroidDecoderCatalog.Format>,
    ):AndroidDecoderCatalog.Format? {
        val name=ImportFilenameNormalizer.forDetection(filename)
        if(cloudEnabled) {
            if(verifiedFormats.isNotEmpty()) {
                AndroidDecoderCatalog.detect(name,verifiedFormats)?.let { return it }
            }
            CloudFileFormats.detect(name)?.let { return it }
            if(verifiedFormats.isNotEmpty())return null
        }
        return AndroidDecoderCatalog.detect(name,bundledFormats())
    }
}
