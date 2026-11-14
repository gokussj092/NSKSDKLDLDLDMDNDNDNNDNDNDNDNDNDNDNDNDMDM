package com.ghostdeveloper.spdecode.admin

import org.junit.Assert.*
import org.junit.Test

class PreviewStateTest {
    @Test
    fun editingAProfileKeepsTicketIdentityAndDoesNotChangeOtherAccounts() {
        val state = PreviewState()
        val other = state.user("alex")
        state.saveUser("NexorQA", "qa@example.com", "nexor")
        assertEquals(other, state.user("alex"))
        assertEquals("NexorQA", state.user(state.ticket("00284").userId).name)
        assertNotNull(state.userError("Alex_L", "new@example.com", "nexor"))
    }

    @Test
    fun suspendingAndReactivatingRetainsPremium() {
        val state = PreviewState()
        state.toggleSuspension("nexor")
        assertEquals("Suspendido", state.user("nexor").status)
        state.toggleSuspension("nexor")
        assertEquals("Premium", state.user("nexor").status)
    }

    @Test
    fun supportRejectsClosedAndBlankRepliesAndMarksNewMessagesLocal() {
        val state = PreviewState()
        val before = state.ticket("00283")
        state.send(before.id, "test")
        assertEquals(before, state.ticket(before.id))
        state.send("00284", "   ")
        assertEquals(3, state.ticket("00284").messages.size)
        state.send("00284", "  mensaje  ")
        assertTrue(state.ticket("00284").messages.last().local)
        assertEquals("mensaje", state.ticket("00284").lastMessage)
        state.markRead("00284")
        assertEquals(0, state.ticket("00284").unread)
        assertEquals(1, state.ticket("00282").unread)
    }

    @Test
    fun productPriceChangesDoNotRewriteExistingOrderSnapshots() {
        val state = PreviewState()
        val before = state.orders.first { it.id == "SPD-2048" }
        state.saveProduct(state.product("offline").copy(cents = 999))
        assertEquals(before, state.orders.first { it.id == before.id })
        assertEquals(999L, state.product("offline").cents)
    }

    @Test
    fun financeIgnoresPendingAndRefundedAndRefundCancelsTheCompletedContribution() {
        val state = PreviewState()
        assertEquals(2498L, state.revenue(30))
        state.changeOrder("SPD-2046", OrderStatus.Completed)
        assertEquals(2897L, state.revenue(30))
        state.changeOrder("SPD-2046", OrderStatus.Refunded)
        assertEquals(2498L, state.revenue(30))
        assertTrue(runCatching { state.changeOrder("SPD-2046", OrderStatus.Completed) }.isFailure)
    }

    @Test
    fun licenseAndGiftGenerationStayExplicitlyDemoAndRevocationIsIsolated() {
        val state = PreviewState()
        val license = state.generateLicense("nexor", 3, 30)
        assertTrue(license.code.startsWith("DEMO-"))
        state.toggleLicense(license.id)
        assertTrue(state.licenses.first { it.id == license.id }.revoked)
        assertFalse(state.licenses.first { it.id == "lic1" }.revoked)
        state.saveProduct(state.product("offline").copy(available = false))
        assertTrue(runCatching { state.generateGift("offline", 1, 0, 3) }.isFailure)
        val gift = state.generateGift("credits", 5, 7, 1)
        assertTrue(gift.code.startsWith("DEMO-"))
        assertEquals(5, gift.maxUses)
    }

    @Test
    fun apiEditsKeepTheClientAndRotationDoesNotRestoreRevokedAccess() {
        val state = PreviewState()
        val id = state.saveApi("QA Client", "2001:db8::1")
        val old = state.apiClients.first { it.id == id }
        state.toggleApi(id)
        state.rotateApi(id)
        val current = state.apiClients.first { it.id == id }
        assertTrue(current.revoked)
        assertNotEquals(old.key, current.key)
        assertEquals(id, state.saveApi("QA Client 2", "192.0.2.20", id))
        assertEquals(4, state.apiClients.size)
    }

    @Test
    fun creditAdjustmentsRequireReasonKeepBalancesNonnegativeAndCreateHistory() {
        val state = PreviewState()
        assertTrue(runCatching { state.adjustCredits("alex", -11, "Revisión") }.isFailure)
        assertTrue(runCatching { state.adjustCredits("alex", 10, "") }.isFailure)
        state.adjustCredits("alex", 5, "Ajuste QA")
        assertEquals(15, state.user("alex").credits)
        assertEquals(25, state.user("nexor").credits)
        assertEquals(5, state.creditHistory.single().amount)
    }

    @Test
    fun catalogPublicationIsAtomicRequiresAllRowsAndNotifiesOnce() {
        val state = PreviewState()
        val version = state.catalogVersion
        val count = state.notices.size
        assertTrue(runCatching { state.publishCatalog(mapOf("hc" to false)) }.isFailure)
        assertEquals(version, state.catalogVersion)
        val draft =
            state.catalog
                .associate { it.id to it.enabled }
                .toMutableMap()
                .apply { this["hc"] = false }
        assertTrue(state.publishCatalog(draft))
        assertEquals(version + 1, state.catalogVersion)
        assertEquals(count + 1, state.notices.size)
        assertFalse(state.publishCatalog(draft))
        assertEquals(count + 1, state.notices.size)
    }

    @Test
    fun allFourteenClientLocalesHaveCompleteMessagesAndUnsupportedLocalesAreRejected() {
        val state = PreviewState()
        val messages = defaultCatalogNotice()
        assertEquals(14, messages.size)
        assertEquals(noticeLanguages.map { it.code }.toSet(), messages.keys)
        assertTrue(
            messages.values.all {
                it.title.isNotBlank() &&
                    it.message.isNotBlank() &&
                    it.confirm.isNotBlank() &&
                    it.cancel.isNotBlank()
            }
        )
        assertEquals(setOf("ar", "fa"), noticeLanguages.filter { it.rtl }.map { it.code }.toSet())
        val id =
            state.publishNotice("Todos los usuarios", "Actualización de catálogo", messages, true)
        assertEquals(14, state.broadcasts.single().messages.size)
        assertEquals(id, state.notices.first().target)
        assertTrue(
            runCatching {
                    state.publishNotice(
                        "Todos los usuarios",
                        "Aviso general",
                        mapOf("unknown" to messages.getValue("es")),
                        true,
                    )
                }
                .isFailure
        )
    }

    @Test
    fun ownerRoleCannotBeEditedEvenThroughTheLocalModel() {
        val state = PreviewState()
        assertTrue(runCatching { state.saveRole("Owner nuevo", "Cambio", "owner") }.isFailure)
        assertTrue(runCatching { state.savePermissions("owner", emptySet()) }.isFailure)
    }
}
