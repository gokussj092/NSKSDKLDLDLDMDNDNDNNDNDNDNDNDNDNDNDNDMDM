package com.ghostdeveloper.spdecode

import android.content.Intent
import android.net.Uri

/** Resolve external content grants without relying on a provider's file paths. */
internal object ExternalImportUris {
    @Suppress("DEPRECATION")
    fun resolve(intent:Intent?):List<Uri> {
        if(intent==null)return emptyList()
        val clipUris=intent.clipData?.let { clip ->
            (0 until clip.itemCount.coerceAtMost(BatchImportQueue.MAX_FILES))
                .mapNotNull { clip.getItemAt(it).uri }
        }.orEmpty()
        return when(intent.action) {
            Intent.ACTION_VIEW->listOfNotNull(intent.data).ifEmpty { clipUris.take(1) }
            Intent.ACTION_SEND->listOfNotNull(
                intent.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri
            ).ifEmpty { clipUris.take(1) }
            Intent.ACTION_SEND_MULTIPLE->{
                (intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM).orEmpty()+
                    clipUris).distinct().take(BatchImportQueue.MAX_FILES)
            }
            else->emptyList()
        }
    }
}
