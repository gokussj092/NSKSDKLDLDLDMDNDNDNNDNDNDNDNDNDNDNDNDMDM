package com.ghostdeveloper.spdecode

import android.content.res.Configuration
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Locale

/** Phase 3: five new languages must resolve actual resource tables, not only
 * show their names in the language picker. No network connection is required. */
@RunWith(AndroidJUnit4::class)
class NewLanguagesInstrumentedTest {
    private val app get()=InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun allFiveAreRegisteredAndLocalized() {
        val languages=mapOf(
            "tr" to "Türkçe",
            "vi" to "Tiếng Việt",
            "hi" to "हिन्दी",
            "ja" to "日本語",
            "it" to "Italiano",
        )
        val englishConfiguration=Configuration(app.resources.configuration).apply {
            setLocale(Locale.ENGLISH)
        }
        val english=app.createConfigurationContext(englishConfiguration)
        for((tag,name) in languages) {
            assertTrue("Missing $tag in selector",SupportedLanguages.supports(tag))
            assertEquals(name,SupportedLanguages.options.first { it.tag==tag }.nativeName)
            val configuration=Configuration(app.resources.configuration).apply {
                setLocale(Locale.forLanguageTag(tag))
            }
            val ctx=app.createConfigurationContext(configuration)
            // These strings are deliberately different from the default
            // English locale; a missing values-XX folder would fail.
            assertNotEquals(tag,english.getString(R.string.settings),
                ctx.getString(R.string.settings))
            assertNotEquals(tag,english.getString(R.string.server_vpn_new_badge),
                ctx.getString(R.string.server_vpn_new_badge))
            for(id in listOf(
                R.string.cloud_legal_title,
                R.string.server_vpn_manual_refresh,
                R.string.cloud_failure_network,
                R.string.hc_auth_title,
                R.string.cloud_password_title,
            )) assertTrue("$tag $id",ctx.getString(id).isNotBlank())
            val formatted=ctx.getString(R.string.cloud_password_description,"Example")
            assertTrue(formatted.contains("Example"))
        }
    }

    @Test fun unsupportedTagsRemainRejected() {
        assertFalse(SupportedLanguages.supports("xx"))
        assertTrue(SupportedLanguages.supports("system"))
    }
}
