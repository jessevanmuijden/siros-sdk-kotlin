package org.siros.sdk.sample

import android.app.Activity
import org.junit.Ignore
import android.net.Uri
import android.util.Log
import org.siros.sdk.sample.BuildConfig
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.credentials.CredentialOffer
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.wallet.SirosWallet
import org.siros.sdk.wallet.WalletConfig
import org.siros.sdk.wallet.WalletState

@OptIn(ExperimentalCoroutinesApi::class)
class WalletViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
        mockkObject(SirosWallet.Companion)
        mockkStatic(Log::class)
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun openAddCredential_loads_available_offers_and_resets_loading() = runTest(dispatcher) {
        val wallet = mockWallet()
        val offers = listOf(
            CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
            )
        )
        coEvery { wallet.getAvailableCredentials() } returns offers
        every { SirosWallet.create(any(), any()) } returns wallet
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))

        viewModel.openAddCredential()
        advanceUntilIdle()

        assertTrue(viewModel.showAddCredential.value)
        assertFalse(viewModel.isLoadingOffers.value)
        assertEquals(offers, viewModel.availableCredentials.value)
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun wallet_uses_stable_default_backend_and_tenant() {
        val configs = mutableListOf<WalletConfig>()
        every { SirosWallet.create(any(), capture(configs)) } returns mockWallet()

        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))

        assertEquals(BuildConfig.DEFAULT_BACKEND_URL, viewModel.backendUrl)
        assertEquals("default", viewModel.tenantId)
        assertEquals(1, configs.size)
        assertEquals(BuildConfig.DEFAULT_BACKEND_URL, configs.single().backendUrl)
        assertEquals("default", configs.single().tenantId)
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun handleAuthRedirect_completes_pending_authorization() {
        val wallet = mockWallet()
        every { SirosWallet.create(any(), any()) } returns wallet
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))
        setField(viewModel, "pendingAuthFlowId", "flow-789")

        viewModel.handleAuthRedirect("code-123", "state-456")

        verify(exactly = 1) { wallet.completeAuthorization("flow-789", "code-123", "state-456") }
        assertNull(getField(viewModel, "pendingAuthFlowId"))
        assertNull(viewModel.errorMessage.value)
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun handleAuthRedirect_sets_error_when_no_pending_flow() {
        val wallet = mockWallet()
        every { SirosWallet.create(any(), any()) } returns wallet
        val mockActivity = mockk<Activity>(relaxed = true)
        every { mockActivity.getString(any()) } returns "Authentication failed"
        val viewModel = WalletViewModel(mockActivity)
        // No pending flow ID set

        viewModel.handleAuthRedirect("code-123", "state-456")

        verify(exactly = 0) { wallet.completeAuthorization(any(), any(), any()) }
        assertEquals("Authentication failed", viewModel.errorMessage.value)
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun clearError_resets_existing_error_message() {
        val wallet = mockWallet()
        every { SirosWallet.create(any(), any()) } returns wallet
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))
        setField(viewModel, "_errorMessage", MutableStateFlow("existing error"))

        viewModel.clearError()

        assertNull(viewModel.errorMessage.value)
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun handleQrResult_routes_credential_offer_to_issuance() = runTest(dispatcher) {
        val wallet = mockWallet(state = MutableStateFlow(WalletState.Ready(userId = "u1", displayName = "Alice", credentials = emptyList())))
        every { SirosWallet.create(any(), any()) } returns wallet
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))

        viewModel.openActivate()
        viewModel.handleQrResult("openid-credential-offer://offer?credential_offer=test")
        advanceUntilIdle()

        assertNull(viewModel.activateMode.value)
        coVerify(exactly = 1) { wallet.startIssuance("openid-credential-offer://offer?credential_offer=test") }
        coVerify(exactly = 0) { wallet.startPresentation(any()) }
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun handleQrResult_routes_non_offer_uri_to_presentation() = runTest(dispatcher) {
        val wallet = mockWallet(state = MutableStateFlow(WalletState.Ready(userId = "u1", displayName = "Alice", credentials = emptyList())))
        every { SirosWallet.create(any(), any()) } returns wallet
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))

        viewModel.openActivate()
        viewModel.handleQrResult("openid4vp://request?client_id=verifier")
        advanceUntilIdle()

        assertNull(viewModel.activateMode.value)
        coVerify(exactly = 0) { wallet.startIssuance(any()) }
        coVerify(exactly = 1) { wallet.startPresentation("openid4vp://request?client_id=verifier") }
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun handleQrResult_surfaces_error_when_wallet_call_fails() = runTest(dispatcher) {
        val wallet = mockWallet(state = MutableStateFlow(WalletState.Ready(userId = "u1", displayName = "Alice", credentials = emptyList())))
        coEvery { wallet.startPresentation(any()) } throws IllegalStateException("presentation failed")
        every { SirosWallet.create(any(), any()) } returns wallet
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))

        viewModel.handleQrResult("openid4vp://request?client_id=verifier")
        advanceUntilIdle()

        assertEquals("presentation failed", viewModel.errorMessage.value)
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun login_rebuilds_wallet_with_updated_config_when_disconnected() = runTest(dispatcher) {
        val firstWallet = mockWallet(state = MutableStateFlow(WalletState.Disconnected()))
        val secondWallet = mockWallet(state = MutableStateFlow(WalletState.Disconnected()))
        val configs = mutableListOf<WalletConfig>()
        every { SirosWallet.create(any(), capture(configs)) } returnsMany listOf(firstWallet, secondWallet)
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))
        coEvery { secondWallet.login() } just runs

        viewModel.login()
        advanceUntilIdle()

        coVerify(exactly = 0) { firstWallet.login() }
        coVerify(exactly = 1) { secondWallet.login() }
        assertEquals(2, configs.size)
        // backendUrl and tenantId are now read-only from BuildConfig/prefs
        assertEquals(viewModel.backendUrl, configs.last().backendUrl)
        assertEquals(viewModel.tenantId, configs.last().tenantId)
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun register_surfaces_errors_and_resets_loading() = runTest(dispatcher) {
        val wallet = mockWallet()
        every { SirosWallet.create(any(), any()) } returns wallet
        coEvery { wallet.register(any()) } throws IllegalStateException("registration failed")
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))

        viewModel.register("Test User")
        advanceUntilIdle()

        assertFalse(viewModel.isLoading.value)
        assertEquals("registration failed", viewModel.errorMessage.value)
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun openHistory_copies_wallet_history_and_sets_visible() {
        val history = listOf(
            PresentationRecord(
                id = 1L,
                flowId = "flow-1",
                credentialIds = listOf(1L),
                credentialNames = listOf("PID"),
                timestamp = 123L,
            )
        )
        val wallet = mockWallet(presentationHistory = history)
        every { SirosWallet.create(any(), any()) } returns wallet
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))

        viewModel.openHistory()

        assertTrue(viewModel.showHistory.value)
        assertEquals(history, viewModel.presentationHistory.value)
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun deleteCredential_clears_selection_and_surfaces_delete_errors() = runTest(dispatcher) {
        val wallet = mockWallet()
        coEvery { wallet.deleteCredential(1L) } throws IllegalStateException("delete failed hard")
        every { SirosWallet.create(any(), any()) } returns wallet
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))
        viewModel.openCredentialDetail(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw", batchId = 1L, instanceId = 0)
        )

        viewModel.deleteCredential(1L)
        advanceUntilIdle()

        assertNull(viewModel.selectedCredential.value)
        assertEquals("delete failed hard", viewModel.errorMessage.value)
    }

    @Test
    @Ignore("Requires native WSCD library — run as instrumented test on device")
    fun disconnect_logs_out_and_clears_add_credential_state() {
        val wallet = mockWallet()
        every { SirosWallet.create(any(), any()) } returns wallet
        val viewModel = WalletViewModel(mockk<Activity>(relaxed = true))
        setField(
            viewModel,
            "_availableCredentials",
            MutableStateFlow(
                listOf(
                    CredentialOffer(
                        credentialConfigurationId = "pid",
                        credentialIssuerIdentifier = "https://issuer.example.com",
                        credentialName = "PID",
                        issuerName = "Issuer",
                    )
                )
            )
        )
        setField(viewModel, "_showAddCredential", MutableStateFlow(true))

        viewModel.disconnect()

        verify(exactly = 1) { wallet.logout() }
        assertFalse(viewModel.showAddCredential.value)
        assertTrue(viewModel.availableCredentials.value.isEmpty())
    }

    private fun mockWallet(
        state: MutableStateFlow<WalletState> = MutableStateFlow(WalletState.Disconnected()),
        presentationHistory: List<PresentationRecord> = emptyList(),
    ): SirosWallet {
        val wallet = mockk<SirosWallet>(relaxed = true)
        every { wallet.state } returns state
        every { wallet.setEventListener(any()) } just runs
        every { wallet.presentationHistory } returns presentationHistory
        return wallet
    }

    private fun setField(target: Any, fieldName: String, value: Any?) {
        val field = target.javaClass.getDeclaredField(fieldName)
        field.isAccessible = true
        field.set(target, value)
    }

    private fun getField(target: Any, fieldName: String): Any? {
        val field = target.javaClass.getDeclaredField(fieldName)
        field.isAccessible = true
        return field.get(target)
    }
}
