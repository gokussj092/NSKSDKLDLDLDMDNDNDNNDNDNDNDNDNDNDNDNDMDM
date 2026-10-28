package com.android.keyattestation.verifier

import com.google.gson.Gson
import java.security.cert.TrustAnchor

/** Pinned upstream mirror of Google's public roots, never supplied by a client. */
object GoogleTrustAnchors : () -> Set<TrustAnchor> {
    private val anchors by lazy {
        val json = checkNotNull(javaClass.getResourceAsStream("/roots.json")).bufferedReader().use { it.readText() }
        Gson().fromJson(json, Array<String>::class.java).map { TrustAnchor(it.asX509Certificate(), null) }.toSet()
    }
    override fun invoke() = anchors
}
