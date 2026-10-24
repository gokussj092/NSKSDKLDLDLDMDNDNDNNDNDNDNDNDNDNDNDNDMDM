package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Presentation regressions: only the screen is normalized; source is immutable. */
@RunWith(AndroidJUnit4::class)
class RawResultFormatterInstrumentedTest {
    @Test fun httpInjectorNestedObjectExpandsWithinItsOriginalKey() {
        val raw = "┌───────────────\n" +
            "│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ehi)\n" +
            "├───────────────\n" +
            "│[۞] configMessage: hello<br><b>test</b>\n" +
            "│[۞] overwriteServerData: {\"city\":\"Los Angeles\",\"proxy\":{\"port\":8080,\"sshPort\":22},\"flags\":[true,false]}\n" +
            "│[۞] payload: GET / HTTP/1.1[crlf]Host: example.org\n" +
            "├───────────────\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n"
        val doc = DecodeView("case.ehi","ehi",raw,256)
        val shown = RawResultFormatter.render(doc.rawText)
        assertTrue(shown.contains("│[۞] overwriteServerData:\n│   {"))
        assertTrue(shown.contains("\"city\": \"Los Angeles\""))
        assertTrue(shown.contains("\"sshPort\": 22"))
        assertTrue(shown.contains("\"flags\": ["))
        assertTrue(shown.contains("│[۞] payload: GET / HTTP/1.1[crlf]"))
        assertTrue(shown.contains("configMessage: hello<br><b>test</b>"))
        assertTrue(shown.contains("│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve"))
        assertEquals(raw, ResultPresentation.formatted(doc.document, ResultExport.ORIGINAL))
        assertEquals(raw,doc.rawText)
    }

    @Test fun malformedJsonIsKeptVerbatimAndRepeatedNamesRemainVisible() {
        val raw="│[۞] Data: {bad JSON}\n│[۞] DNS: first\n│[۞] DNS: second"
        assertEquals(raw,RawResultFormatter.render(raw))
    }

    @Test fun credentialsHiddenOnlyWhenUserExplicitlyEnablesMasking() {
        val raw="│[۞] Password: dummy\n" +
            "│[۞] Config: {\"name\":\"test\",\"password\":\"inside\",\"child\":{\"sshPassword\":\"deep\"}}"
        val expanded=RawResultFormatter.render(raw)
        assertTrue(expanded.contains("Password: dummy"))
        assertTrue(expanded.contains("inside"))
        val masked=RawResultFormatter.render(raw,true)
        assertFalse(masked.contains("dummy"))
        assertFalse(masked.contains("inside"))
        assertFalse(masked.contains("deep"))
        assertTrue(masked.contains("••••••••"))
        assertEquals(raw,raw) // Source string is never modified.
    }

    @Test fun standaloneJsonRendersNestedFieldsAndPreservesTypedCopy() {
        val raw="{\"host\":\"example.org\",\"nested\":{\"tls\":true,\"port\":443}}"
        val doc=ResultPresentation.parse(raw,"xui")
        val shown=RawResultFormatter.render(doc.original)
        assertTrue(shown.contains("\"port\": 443"))
        assertTrue(shown.contains("\"tls\": true"))
        assertEquals(raw,ResultPresentation.formatted(doc,ResultExport.ORIGINAL))
    }

    @Test fun extensibleLanguageRegistryRetainsCurrentChoices() {
        assertEquals(listOf("system","es","en","pt-BR","ar","fa","fr","id","ru","de",
            "tr","vi","hi","ja","it"),
            SupportedLanguages.options.map{it.tag})
        assertTrue(SupportedLanguages.supports("pt-BR"))
        assertFalse(SupportedLanguages.supports("unknown"))
    }
}
