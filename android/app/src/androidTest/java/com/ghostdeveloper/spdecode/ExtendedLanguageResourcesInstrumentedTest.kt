package com.ghostdeveloper.spdecode

import android.content.res.Configuration
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Locale

/** i18n-only checks; no decoding or network activity. */
@RunWith(AndroidJUnit4::class)
class ExtendedLanguageResourcesInstrumentedTest {
    @Test fun eachNewLocaleHasTranslatedUiCloudHcAndGuide() {
        val ctx=InstrumentationRegistry.getInstrumentation().targetContext
        val expected=mapOf(
            "fa" to "تنظیمات",
            "fr" to "Paramètres",
            "id" to "Pengaturan",
            "ru" to "Настройки",
            "de" to "Einstellungen",
        )
        for((tag,settingsTitle) in expected) {
            val config=Configuration(ctx.resources.configuration)
            config.setLocale(Locale.forLanguageTag(tag))
            config.setLayoutDirection(Locale.forLanguageTag(tag))
            val res=ctx.createConfigurationContext(config).resources
            assertEquals("language=$tag",settingsTitle,
                res.getString(R.string.settings_title))
            for(id in listOf(
                R.string.guide_step_six, R.string.guide_step_seven, R.string.guide_step_eight,
                R.string.cloud_http_injector_privacy, R.string.hc_auth_failed,
                R.string.hc_auth_hwid_hint, R.string.npvs_private_key_unsupported,
            )) assertTrue("missing resource $tag:$id",res.getString(id).isNotBlank())
            val progress=res.getString(R.string.guide_progress,1,8)
            // Android may format 7 as ۷ in Persian; test numeric value, not glyph.
            assertTrue("localized progress $tag: $progress",
                progress.any { Character.getNumericValue(it)==8 })
            assertTrue(res.getString(R.string.hc_auth_description,"file.hc")
                .contains("file.hc"))
            assertTrue(res.getString(R.string.batch_import_summary,1,2).isNotBlank())
            assertEquals("right-to-left $tag",tag=="fa",
                config.layoutDirection==android.view.View.LAYOUT_DIRECTION_RTL)
        }
    }

    @Test fun languageRegistryContainsNoDuplicateTags() {
        val tags=SupportedLanguages.options.map { it.tag }
        assertEquals(tags.size,tags.toSet().size)
        for(tag in listOf("fa","fr","id","ru","de")) {
            assertTrue(tag,SupportedLanguages.supports(tag))
        }
        assertFalse(SupportedLanguages.supports("unsupported-language"))
    }
}
