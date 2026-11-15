package com.ghostdeveloper.spdecode.admin

import org.junit.Assert.*
import org.junit.Test

class AdminRulesTest {
    @Test
    fun chatOnlyFollowsNewMessagesWhenInitiallyOpenedOrNearBottom() {
        assertTrue(shouldFollowNewMessages(0, -1))
        assertTrue(shouldFollowNewMessages(10, 8))
        assertTrue(shouldFollowNewMessages(10, 9))
        assertFalse(shouldFollowNewMessages(10, 2))
        assertFalse(shouldFollowNewMessages(10, -1))
    }

    @Test
    fun moneyUsesExactCentsAndRejectsRoundingAndOutOfRangeInput() {
        assertEquals(499L, parsePrice("4.99"))
        assertEquals(499L, parsePrice("4,99"))
        assertEquals(10L, parsePrice("0.10"))
        assertEquals("$4.99", money(499))
        assertEquals("$0.01", money(1))
        for (value in listOf("0", "-1", "NaN", "1e3", "4.999", "100000.00", "1,2.3")) assertNull(
            value,
            parsePrice(value),
        )
    }

    @Test
    fun apiRequiresOneLiteralAddressWithoutHostOrPort() {
        assertEquals("192.0.2.10", canonicalIp(" 192.0.2.10 "))
        assertNotNull(canonicalIp("2001:db8::1"))
        for (value in
            listOf(
                "example.com",
                "192.0.2.1:443",
                "192.0.2.1/24",
                "256.1.1.1",
                "192.00.2.1",
                "::::",
                "https://192.0.2.1",
            )) assertNull(value, canonicalIp(value))
    }

    @Test
    fun csvEscapesDelimitersQuotesAndSpreadsheetFormulaPrefixes() {
        assertEquals("\"a,b\"", csvCell("a,b"))
        assertEquals("\"a\"\"b\"", csvCell("a\"b"))
        assertEquals("\"'=1+1\"", csvCell("=1+1"))
        assertTrue(csvCell("  @SUM(A1)").startsWith("\"'"))
        assertEquals("\"line1\nline2\"", csvCell("line1\nline2"))
    }
}
