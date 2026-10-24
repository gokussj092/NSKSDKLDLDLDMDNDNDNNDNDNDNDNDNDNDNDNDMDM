package com.ghostdeveloper.spdecode.parity

import android.content.Context
import com.ghostdeveloper.spdecode.ImportFilenameNormalizer
import org.json.JSONObject
import java.util.Locale

/**
 * Complete read-only bot inventory for Android migration, not a certification list.
 *
 * Phase F completes 61 legacy + 81 generic + 41 Ultra + 16 RENZ + 27 special
 * + 13 independent native formats; none are pending (all are experimental).
 * Native availability is NOT vendor/exporter version certification.
 *
 * The bundled JSON is generated from the canonical registry with *public*
 * metadata only. Python paths and execution details remain server-side.
 */
object AndroidDecoderCatalog {
    const val TOTAL_SUFFIXES = 239
    const val LEGACY_NATIVE_SUFFIXES = 61
    const val GENERIC_NATIVE_SUFFIXES = 81
    const val ULTRA_NATIVE_SUFFIXES = 41
    const val RENZ_NATIVE_SUFFIXES = 16
    const val SPECIAL_NATIVE_SUFFIXES = 27
    const val INDEPENDENT_NATIVE_SUFFIXES = 13
    const val NATIVE_SUFFIXES = LEGACY_NATIVE_SUFFIXES + GENERIC_NATIVE_SUFFIXES + ULTRA_NATIVE_SUFFIXES + RENZ_NATIVE_SUFFIXES + SPECIAL_NATIVE_SUFFIXES + INDEPENDENT_NATIVE_SUFFIXES
    const val PENDING_NATIVE_SUFFIXES = TOTAL_SUFFIXES - NATIVE_SUFFIXES
    const val GENERIC_AES_STATUS = "experimental_generic_aes_gcm_synthetic"
    const val GENERIC_DES_STATUS = "experimental_generic_des_ecb_synthetic"
    const val ULTRA_STATUS = "experimental_ultra_sandok_argon2id_synthetic"
    const val RENZ_STATUS = "experimental_renz_aes_xxtea_threefish_synthetic"
    const val SPECIAL_STATUS = "experimental_special_13_engines_synthetic"
    const val INDEPENDENT_STATUS = "experimental_independent_9_engines_synthetic"
    const val PENDING_STATUS = "registered_not_implemented"

    data class Format(
        val suffix: String,
        val appName: String,
        val portStatus: String,
        val androidVerified: Boolean,
        val migrationPhase: String,
        val cloudSupported: Boolean = true,
        // Validated Cloud catalog metadata, never an Android decoder or key.
        val credentialFields: Set<String> = emptySet(),
    ) {
        val hasNativeDecoder: Boolean
            get() = (migrationPhase == "legacy" &&
                portStatus != PENDING_STATUS && portStatus != "not_implemented") ||
                (migrationPhase == "B" &&
                    (portStatus == GENERIC_AES_STATUS || portStatus == GENERIC_DES_STATUS)) ||
                (migrationPhase == "C" && portStatus == ULTRA_STATUS) ||
                (migrationPhase == "D" && portStatus == RENZ_STATUS) ||
                (migrationPhase == "E" && portStatus == SPECIAL_STATUS) ||
                (migrationPhase == "F" && portStatus == INDEPENDENT_STATUS) ||
                (migrationPhase == "NUR" && suffix == "solid")
        val isPending: Boolean get() = !hasNativeDecoder
    }

    fun read(context: Context): List<Format> {
        val source = context.assets.open("decoder_catalog.json").bufferedReader(Charsets.UTF_8)
            .use { it.readText() }
        val doc = JSONObject(source)
        require(doc.getInt("schemaVersion") == 4)
        require(doc.getInt("botRegisteredSuffixes") == TOTAL_SUFFIXES)
        require(doc.getInt("androidExistingSuffixes") == LEGACY_NATIVE_SUFFIXES)
        require(doc.getInt("androidGenericNativeSuffixes") == GENERIC_NATIVE_SUFFIXES)
        require(doc.getInt("androidUltraNativeSuffixes") == ULTRA_NATIVE_SUFFIXES)
        require(doc.getInt("androidRenzNativeSuffixes") == RENZ_NATIVE_SUFFIXES)
        require(doc.getInt("androidSpecialNativeSuffixes") == SPECIAL_NATIVE_SUFFIXES)
        require(doc.getInt("androidIndependentNativeSuffixes") == INDEPENDENT_NATIVE_SUFFIXES)
        require(doc.getInt("androidNativePortSuffixes") == NATIVE_SUFFIXES)
        require(doc.getInt("androidPendingNativeSuffixes") == PENDING_NATIVE_SUFFIXES)
        require(doc.getInt("androidCertifiedSuffixes") == 0)
        val entries = doc.getJSONArray("entries")
        require(entries.length() == TOTAL_SUFFIXES)
        val formats = (0 until entries.length()).map { index ->
            val item = entries.getJSONObject(index)
            Format(
                suffix = item.getString("suffix"),
                appName = item.getString("name"),
                portStatus = item.getString("androidPortStatus"),
                androidVerified = item.getBoolean("androidVerified"),
                migrationPhase = item.getString("migrationPhase"),
            )
        }
        require(formats.map { it.suffix }.toSet().size == TOTAL_SUFFIXES)
        require(formats.all { it.suffix.isNotEmpty() && it.suffix == it.suffix.lowercase(Locale.ROOT) })
        require(formats.none { it.androidVerified })
        require(formats.count { it.hasNativeDecoder } == NATIVE_SUFFIXES)
        require(formats.count { it.migrationPhase == "legacy" && it.hasNativeDecoder } == LEGACY_NATIVE_SUFFIXES)
        require(formats.count { it.migrationPhase == "B" && it.hasNativeDecoder } == GENERIC_NATIVE_SUFFIXES)
        require(formats.count { it.migrationPhase == "C" && it.hasNativeDecoder } == ULTRA_NATIVE_SUFFIXES)
        require(formats.count { it.migrationPhase == "D" && it.hasNativeDecoder } == RENZ_NATIVE_SUFFIXES)
        require(formats.count { it.migrationPhase == "E" && it.hasNativeDecoder } == SPECIAL_NATIVE_SUFFIXES)
        require(formats.count { it.migrationPhase == "F" && it.hasNativeDecoder } == INDEPENDENT_NATIVE_SUFFIXES)
        require(formats.single { it.suffix == "ost" }.migrationPhase == "legacy")
        require(formats.count { it.isPending } == PENDING_NATIVE_SUFFIXES)
        return formats
    }

    /** Longest suffix wins; .sksrv.png must not be confused with .png. */
    fun detect(filename: String, formats: List<Format>): Format? {
        val candidate = ImportFilenameNormalizer.forDetection(filename)
            .lowercase(Locale.ROOT)
        if (candidate.isBlank()) return null
        // The existing 239 audited suffixes remain frozen; NUR is independently routed.
        if (candidate.endsWith(".solid")) return Format(
            "solid", "NUR TUNNEL VPN", "experimental_nur_solid_native",
            false, "NUR"
        )
        return formats.filter {
            candidate.endsWith("." + it.suffix.lowercase(Locale.ROOT))
        }.maxByOrNull { it.suffix.length }
    }
}
