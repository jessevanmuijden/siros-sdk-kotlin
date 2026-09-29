package org.siros.sdk.wallet

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.slot
import io.mockk.verify
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlin.reflect.full.callSuspend
import kotlin.reflect.full.declaredMemberFunctions
import kotlin.reflect.jvm.isAccessible
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.putJsonObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.siros.sdk.auth.AuthServerClient
import org.siros.sdk.auth.AuthTokens
import org.siros.sdk.auth.BackendApiClient
import org.siros.sdk.auth.DeactivationOutcome
import org.siros.sdk.auth.WalletInstance
import org.siros.sdk.auth.WalletInstanceStatus
import org.siros.sdk.auth.WalletLifecycleRefusal
import org.siros.sdk.credentials.AuthException
import org.siros.sdk.credentials.BackendApiException
import org.siros.sdk.credentials.CredentialConsumptionPolicy
import org.siros.sdk.credentials.CredentialMatcher
import org.siros.sdk.credentials.CredentialMetadata
import org.siros.sdk.credentials.CredentialStore
import org.siros.sdk.credentials.NetworkException
import org.siros.sdk.credentials.PresentationRecord
import org.siros.sdk.credentials.SignerSecurityProperties
import org.siros.sdk.credentials.StoredCredential
import org.siros.sdk.credentials.WalletException
import org.siros.sdk.keystore.AttestationChain
import org.siros.sdk.keystore.KeyInfo
import org.siros.sdk.keystore.KeypairInfo
import org.siros.sdk.keystore.KeystoreManager
import org.siros.sdk.keystore.NativeAttestationEvidence
import org.siros.sdk.keystore.NativeAttestationProvider
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.siros.sdk.transport.engine.CredentialNotificationEvent
import org.siros.sdk.transport.engine.CredentialResult
import org.siros.sdk.transport.engine.CredentialMatch
import org.siros.sdk.transport.engine.FlowCompleteMessage
import org.siros.sdk.transport.engine.FlowError
import org.siros.sdk.transport.engine.FlowErrorMessage
import org.siros.sdk.transport.engine.FlowProgressMessage
import org.siros.sdk.transport.engine.MatchRequestMessage
import org.siros.sdk.transport.engine.ProofObject
import org.siros.sdk.transport.engine.SignRequestMessage
import org.siros.sdk.transport.engine.SignRequestParams
import org.siros.sdk.transport.engine.WalletEngineSession

@OptIn(ExperimentalCoroutinesApi::class)
class SirosWalletTest {

    private val dispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        SirosWallet.createEngineSession = { baseUrl, tenantId -> WalletEngineSession(baseUrl, tenantId) }
    }

    @Test
    fun logout_disconnects_clears_and_sets_disconnected_state() {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val keystore = mockk<KeystoreManager>(relaxed = true)
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val accountRegistry = mockk<AccountRegistry>(relaxed = true)
        every { accountRegistry.listLoginableAccounts() } returns emptyList()
        val scope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val stateFlow = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "user-1", displayName = "Alice")
        )
        val wallet = newWallet(
            "_state" to stateFlow,
            "engineSession" to engine,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "accountRegistry" to accountRegistry,
            "scope" to scope,
            "apiClient" to mockk<BackendApiClient>(relaxed = true),
        )

        wallet.logout()

        verify(exactly = 1) { engine.disconnect() }
        verify(exactly = 1) { keystore.lock() }
        verify(exactly = 1) { sessionStore.clear() }
        assertEquals(WalletState.Disconnected(), wallet.state.value)
    }

    @Test
    fun completeAuthorization_sends_authorization_complete_action() {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "engineSession" to engine,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
        )

        wallet.completeAuthorization(flowId = "flow-123", code = "code-abc", state = "state-xyz")

        verify(exactly = 1) {
            engine.sendFlowAction(
                "flow-123",
                "authorization_complete",
                match {
                    it.toString().contains("\"code\":\"code-abc\"") &&
                        it.toString().contains("\"state\":\"state-xyz\"")
                }
            )
        }
    }

    @Test
    fun getIssuers_accepts_plain_array_and_filters_hidden_entries() = runBlocking {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.getIssuers() } returns JsonArray(
            listOf(
                buildJsonObject {
                    put("id", 1)
                    put("credentialIssuerIdentifier", "https://issuer-1.example.com")
                    put("visible", true)
                },
                buildJsonObject {
                    put("id", 2)
                    put("credentialIssuerIdentifier", "https://issuer-2.example.com")
                    put("visible", false)
                },
            )
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "apiClient" to apiClient,
            "json" to Json { ignoreUnknownKeys = true },
        )

        val issuers = wallet.getIssuers()

        assertEquals(1, issuers.size)
        assertEquals(1L, issuers.first().id)
        assertEquals("https://issuer-1.example.com", issuers.first().credentialIssuerIdentifier)
    }

    @Test
    fun getAvailableCredentials_uses_backend_metadata_proxy_and_merges_display_fields() = runBlocking {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.getIssuers() } returns JsonArray(
            listOf(
                buildJsonObject {
                    put("id", 7)
                    put("credentialIssuerIdentifier", "https://issuer-1.example.com")
                    put("visible", true)
                }
            )
        )
        coEvery { apiClient.getIssuerMetadata(7) } returns buildJsonObject {
            put("credential_issuer", "https://issuer-1.example.com")
            putJsonArray("display") {
                add(buildJsonObject {
                    put("name", "Issuer One")
                    put("background_color", "#102030")
                    put("text_color", "#f0f4f8")
                    putJsonObject("logo") {
                        put("uri", "https://issuer-1.example.com/logo.png")
                    }
                })
            }
            putJsonObject("credential_configurations_supported") {
                putJsonObject("pid") {
                    put("format", "dc+sd-jwt")
                    putJsonObject("credential_metadata") {
                        putJsonArray("display") {
                            add(buildJsonObject {
                                put("name", "Personal ID")
                                put("description", "Government issued PID")
                                put("background_color", "#223344")
                                put("text_color", "#ffffff")
                                putJsonObject("logo") {
                                    put("uri", "https://issuer-1.example.com/pid.png")
                                }
                            })
                        }
                    }
                }
            }
        }
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "apiClient" to apiClient,
            "json" to Json { ignoreUnknownKeys = true },
        )

        val offers = wallet.getAvailableCredentials()

        coVerify(exactly = 1) { apiClient.getIssuerMetadata(7) }
        assertEquals(1, offers.size)
        assertEquals("pid", offers.single().credentialConfigurationId)
        assertEquals("Personal ID", offers.single().credentialName)
        assertEquals("Issuer One", offers.single().issuerName)
        assertEquals("#223344", offers.single().backgroundColor)
        assertEquals("#ffffff", offers.single().textColor)
        assertEquals("https://issuer-1.example.com/pid.png", offers.single().logoUri)
        assertEquals("https://issuer-1.example.com/logo.png", offers.single().issuerLogoUri)
    }

    @Test
    fun deleteCredential_updates_ready_state_without_backend_sync_when_keystore_locked() = runBlocking {
        val remainingCredential = StoredCredential(
            id = 2L,
            format = "dc+sd-jwt",
            raw = "raw-2",
            metadata = CredentialMetadata(name = "Credential Two"),
            batchId = 2L,
            instanceId = 0,
        )
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw-1", batchId = 1L, instanceId = 0),
                remainingCredential,
            )
        )
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(
                    userId = "user-1",
                    displayName = "Alice",
                    credentials = store.getAll(),
                )
            ),
            "credentialStore" to store,
            "keystore" to keystore,
        )

        wallet.deleteCredential(1L)

        val state = wallet.state.value as WalletState.Ready
        assertEquals(listOf(2L), state.credentials.map { it.id })
    }

    @Test
    fun deleteCredential_syncs_private_data_when_keystore_unlocked() = runBlocking {
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        val containerJson = """{"prfKeys":[],"jwe":"test-jwe"}"""
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns containerJson.toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
        )

        wallet.deleteCredential(999L)

        coVerify(exactly = 1) { keystore.exportEncryptedContainer() }
        verify(exactly = 1) { sessionStore.privateDataJwe = containerJson }
        coVerify(exactly = 1) {
            apiClient.updatePrivateData(match { it["jwe"]?.jsonPrimitive?.content == "test-jwe" })
        }
    }

    @Test
    fun handleTrustEvaluation_rejects_missing_subject_id_without_backend_call() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-1",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_type", "credential_issuer")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) { engine.sendTrustResult("flow-1", false, "Missing subject_id") }
    }

    @Test
    fun handleTrustEvaluation_builds_authzen_request_and_returns_backend_decision() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject {
            put("decision", true)
        }
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "trustCache" to TrustCache(),
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-2",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "verifier-123")
                    put("subject_type", "credential_verifier")
                    putJsonObject("key_material") {
                        put("type", "jwk")
                        putJsonObject("jwk") {
                            put("kty", "EC")
                            put("crv", "P-256")
                            put("x", "abc")
                            put("y", "def")
                        }
                    }
                    putJsonObject("context") {
                        put("policy", "strict")
                    }
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 1) {
            apiClient.evaluateTrust(match { request ->
                request["subject"]?.toString() == "{\"type\":\"key\",\"id\":\"verifier-123\"}" &&
                    request["action"]?.toString() == "{\"name\":\"credential-verifier\"}" &&
                    request["context"]?.toString() == "{\"policy\":\"strict\"}" &&
                    request["resource"]?.toString()?.contains("\"type\":\"jwk\"") == true &&
                    request["resource"]?.toString()?.contains("\"key\":[{") == true &&
                    request["resource"]?.toString()?.contains("\"kty\":\"EC\"") == true
            })
        }
        verify(exactly = 1) { engine.sendTrustResult("flow-2", true, null) }
    }

    @Test
    fun handleTrustEvaluation_returns_failure_reason_when_backend_throws() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws IllegalStateException("trust backend offline")
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "trustCache" to TrustCache(),
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-3",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "issuer-456")
                    put("subject_type", "credential_issuer")
                    putJsonObject("key_material") {
                        put("type", "x5c")
                        putJsonArray("x5c") {
                            add(JsonPrimitive("cert-1"))
                        }
                    }
                }
            }
        )
        advanceUntilIdle()

        verify(exactly = 1) { engine.sendTrustResult("flow-3", false, "trust backend offline") }
    }

    /**
     * Regression (#219): go-wallet-backend#396/#401 sets
     * requires_resolution/request_jwt for a did:-scheme verifier when the
     * engine could not resolve the DID itself (no verifier PDP configured).
     * The handler must call /v1/resolve, extract a verificationMethod's
     * publicKeyJwk from the resulting DID document, verify request_jwt
     * against it, and evaluate trust using THAT key - never the request's
     * own (absent) key_material.
     */
    @Test
    fun handleTrustEvaluation_resolves_did_key_material_when_requires_resolution() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val verifierKey = ECKeyGenerator(Curve.P_256).keyID("did:web:verifier.example.com#key-1").generate()
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:verifier.example.com#key-1").build(),
            JWTClaimsSet.Builder().claim("client_id", "did:web:verifier.example.com").build(),
        )
        signedJwt.sign(ECDSASigner(verifierKey))

        coEvery { apiClient.resolveKey("did:web:verifier.example.com") } returns buildJsonObject {
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    put("id", "did:web:verifier.example.com")
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:verifier.example.com#key-1")
                            put("type", "JsonWebKey2020")
                            put("publicKeyJwk", Json.parseToJsonElement(verifierKey.toPublicJWK().toJSONString()))
                        }
                    }
                }
            }
        }
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "trustCache" to TrustCache(),
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-did",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", signedJwt.serialize())
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { apiClient.resolveKey("did:web:verifier.example.com") }
        coVerify(exactly = 1) {
            apiClient.evaluateTrust(match { request ->
                request["resource"]?.toString()?.contains("\"type\":\"jwk\"") == true
            })
        }
        verify(exactly = 1) { engine.sendTrustResult("flow-did", true, null) }
    }

    /**
     * Regression (#219 review finding): an Ed25519 (EdDSA/OKP) verification
     * method - common in did:key/did:web documents emitted by go-trust's
     * supported DID resolvers - must resolve too, not just EC/RSA. Nimbus's
     * `JWK.parse` yields an `OctetKeyPair` for these, which the initial fix
     * fell through to `else -> continue` on, silently rejecting every
     * Ed25519 verifier.
     */
    @Test
    fun handleTrustEvaluation_resolves_did_key_material_with_ed25519_verification_method() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val verifierKey = OctetKeyPairGenerator(Curve.Ed25519).keyID("did:web:verifier.example.com#key-1").generate()
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("did:web:verifier.example.com#key-1").build(),
            JWTClaimsSet.Builder().claim("client_id", "did:web:verifier.example.com").build(),
        )
        signedJwt.sign(Ed25519Signer(verifierKey))

        coEvery { apiClient.resolveKey("did:web:verifier.example.com") } returns buildJsonObject {
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:verifier.example.com#key-1")
                            put("type", "JsonWebKey2020")
                            put("publicKeyJwk", Json.parseToJsonElement(verifierKey.toPublicJWK().toJSONString()))
                        }
                    }
                }
            }
        }
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "trustCache" to TrustCache(),
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-did-eddsa",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", signedJwt.serialize())
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) { engine.sendTrustResult("flow-did-eddsa", true, null) }
    }

    /**
     * The counterpart failure case: a request_jwt that does not verify
     * against the resolved DID document's key must fail CLOSED - never
     * treated as trusted, and never as "no key material" (which some
     * caller might read as a legitimately keyless scheme and proceed
     * regardless).
     */
    @Test
    fun handleTrustEvaluation_fails_closed_when_resolved_key_does_not_verify_request_jwt() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val realKey = ECKeyGenerator(Curve.P_256).keyID("did:web:verifier.example.com#key-1").generate()
        val attackerKey = ECKeyGenerator(Curve.P_256).keyID("did:web:verifier.example.com#key-1").generate()
        // Signed by attackerKey, but the DID document (below) only lists
        // realKey - verification against the resolved key must fail.
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:verifier.example.com#key-1").build(),
            JWTClaimsSet.Builder().claim("client_id", "did:web:verifier.example.com").build(),
        )
        signedJwt.sign(ECDSASigner(attackerKey))

        coEvery { apiClient.resolveKey("did:web:verifier.example.com") } returns buildJsonObject {
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:verifier.example.com#key-1")
                            put("publicKeyJwk", Json.parseToJsonElement(realKey.toPublicJWK().toJSONString()))
                        }
                    }
                }
            }
        }
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "trustCache" to TrustCache(),
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-did-bad",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", signedJwt.serialize())
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) {
            engine.sendTrustResult(
                "flow-did-bad",
                false,
                match { it != null && it.contains("did not verify") },
            )
        }
    }

    @Test
    fun handleTrustEvaluation_fails_closed_when_requires_resolution_but_no_request_jwt() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "trustCache" to TrustCache(),
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-did-missing-jwt",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { apiClient.resolveKey(any()) }
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) {
            engine.sendTrustResult(
                "flow-did-missing-jwt",
                false,
                match { it != null && it.contains("request_jwt") },
            )
        }
    }

    @Test
    fun connectEngine_forwards_authorization_required_and_transitions_to_flow_active() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to store,
            "eventListener" to listener,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-auth",
                step = "authorization_required",
                payload = buildJsonObject {
                    put("authorization_url", "https://issuer.example.com/auth?state=state-from-url")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "state-from-url")
                },
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            listener.onAuthorizationRequired(
                "flow-auth",
                "https://issuer.example.com/auth?state=state-from-url",
                "siros://callback",
                "state-from-url",
            )
        }
        verify(exactly = 1) { engine.connect("app-token", any(), any()) }
        assertEquals(
            WalletState.FlowActive(
                userId = "user-1",
                displayName = "Alice",
                flowId = "flow-auth",
                flowType = "authorization_required",
                status = "authorization_required",
                credentials = emptyList(),
            ),
            wallet.state.value,
        )
    }

    @Test
    fun connectEngine_reauth_required_state_notifies_listener_and_logs_out() = runTest(dispatcher) {
        // The engineStateJob started by connectEngine() is the only currently-wired
        // path to WalletEngineSession.State.REAUTH_REQUIRED (e.g. the background
        // reconnect loop's token refresh being rejected) - this locks in that the
        // host app is notified and the SDK's own session state is put back in sync.
        val listener = mockk<WalletEventListener>(relaxed = true)
        val keystore = mockk<KeystoreManager>(relaxed = true)
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val accountRegistry = mockk<AccountRegistry>(relaxed = true)
        every { accountRegistry.listLoginableAccounts() } returns emptyList()
        val engineState = MutableStateFlow(WalletEngineSession.State.CONNECTED)
        val engine = mockEngineConstructor()
        every { engine.state } returns engineState
        every { engine.disconnect() } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "accountRegistry" to accountRegistry,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()

        engineState.value = WalletEngineSession.State.REAUTH_REQUIRED
        advanceUntilIdle()

        verify(exactly = 1) { listener.onReauthenticationRequired() }
        verify(atLeast = 1) { engine.disconnect() }
        // The SDK now attempts one self-driven re-login before giving up (see
        // handleReauthenticationRequired), and both that attempt's teardown
        // and the logout it falls back to lock the keystore.
        verify(atLeast = 1) { keystore.lock() }
        assertEquals(WalletState.Disconnected(), wallet.state.value)
    }

    @Test
    fun completeAuthorization_resumes_via_stateless_flow_start_using_saved_context() = runTest(dispatcher) {
        // The WebSocket session that started the flow is very often already gone by the
        // time the browser redirects back (Android backgrounds/throttles the app for the
        // OAuth login) - completeAuthorization must resume on a fresh flow_start using the
        // code_verifier/credential_offer saved from the original authorization_required
        // message, not a flow_action on the (likely dead) original flow_id.
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        every { engine.resumeIssuance(any(), any(), any(), any(), any()) } just runs
        coEvery { engine.awaitConnected(any()) } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to store,
            "eventListener" to listener,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
            "json" to Json { ignoreUnknownKeys = true },
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-auth",
                step = "authorization_required",
                payload = buildJsonObject {
                    put("authorization_url", "https://issuer.example.com/auth?state=state-from-url")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "state-from-url")
                    put("code_verifier", "verifier-abc")
                    putJsonObject("credential_offer") {
                        put("credential_issuer", "https://issuer.example.com")
                    }
                },
            )
        )
        advanceUntilIdle()

        wallet.completeAuthorization(flowId = "flow-auth", code = "auth-code-xyz", state = "state-from-url")
        advanceUntilIdle()

        coVerify(exactly = 1) { engine.forceReconnect() }
        verify(exactly = 1) {
            engine.resumeIssuance(
                offer = match { it != null && it.contains("\"credential_issuer\":\"https://issuer.example.com\"") },
                credentialOfferUri = null,
                redirectUri = "siros://callback",
                authCode = "auth-code-xyz",
                codeVerifier = "verifier-abc",
            )
        }
        verify(exactly = 0) { engine.sendFlowAction("flow-auth", "authorization_complete", any()) }
    }

    /**
     * The resumed flow_start carries no client attestation any more: the
     * engine asks for it via a `request_attestation` sign request on the
     * resume too (go-wallet-backend's Execute() runs its attestation setup
     * before branching on msg.AuthCode), so no WIA/PoP work - and no issuer
     * metadata fetch - happens on this side before resumeIssuance.
     */
    @Test
    fun completeAuthorization_resumesWithoutClientAttestation_engineRequestsIt() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        every { engine.resumeIssuance(any(), any(), any(), any(), any(), any(), any()) } just runs
        coEvery { engine.awaitConnected(any()) } just runs

        val sessionStore = mockk<SessionStore>(relaxed = true)
        every { sessionStore.instanceKeyId } returns "instance-key-1"
        val keystore = mockk<KeystoreManager>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)

        val issuerUrl = "https://issuer.example.com"
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to store,
            "eventListener" to listener,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
            "sessionStore" to sessionStore,
            "keystore" to keystore,
            "apiClient" to apiClient,
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-auth",
                step = "authorization_required",
                payload = buildJsonObject {
                    put("authorization_url", "$issuerUrl/auth?state=state-from-url")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "state-from-url")
                    put("code_verifier", "verifier-abc")
                    putJsonObject("credential_offer") {
                        put("credential_issuer", issuerUrl)
                    }
                },
            )
        )
        advanceUntilIdle()

        wallet.completeAuthorization(flowId = "flow-auth", code = "auth-code-xyz", state = "state-from-url")
        advanceUntilIdle()

        verify(exactly = 1) {
            engine.resumeIssuance(
                offer = match { it != null && it.contains("\"credential_issuer\":\"$issuerUrl\"") },
                credentialOfferUri = null,
                redirectUri = "siros://callback",
                authCode = "auth-code-xyz",
                codeVerifier = "verifier-abc",
                clientAttestation = null,
                clientAttestationPoP = null,
            )
        }
        coVerify(exactly = 0) { apiClient.requestWIAChallenge() }
        coVerify(exactly = 0) { apiClient.generateWIA(any(), any(), any(), any()) }
        coVerify(exactly = 0) { keystore.generateKeyProof(any(), any(), any(), any(), any()) }
    }

    @Test
    fun completeAuthorization_surfaces_error_via_onFlowError_when_reconnect_fails() = runTest(dispatcher) {
        // If forcing a fresh connection fails outright, the failure must be visible to
        // the app immediately (onFlowError) rather than leaving it stuck showing
        // whatever UI state was current when completeAuthorization was called.
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        coEvery { engine.forceReconnect() } throws IllegalStateException("Engine WebSocket connection failed")
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to store,
            "eventListener" to listener,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
            "json" to Json { ignoreUnknownKeys = true },
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-auth",
                step = "authorization_required",
                payload = buildJsonObject {
                    put("authorization_url", "https://issuer.example.com/auth?state=state-from-url")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "state-from-url")
                },
            )
        )
        advanceUntilIdle()

        wallet.completeAuthorization(flowId = "flow-auth", code = "auth-code-xyz", state = "state-from-url")
        advanceUntilIdle()

        verify(exactly = 1) { listener.onFlowError("flow-auth", any()) }
        verify(exactly = 0) { engine.resumeIssuance(any(), any(), any(), any(), any()) }
    }

    @Test
    fun completeAuthorization_throws_on_state_mismatch_instead_of_resuming() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        every { engine.resumeIssuance(any(), any(), any(), any(), any()) } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-1",
                redirectUri = "siros://callback",
            ),
            "credentialStore" to store,
            "eventListener" to listener,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
            "json" to Json { ignoreUnknownKeys = true },
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-auth",
                step = "authorization_required",
                payload = buildJsonObject {
                    put("authorization_url", "https://issuer.example.com/auth?state=state-from-url")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "state-from-url")
                },
            )
        )
        advanceUntilIdle()

        var thrown: Throwable? = null
        try {
            wallet.completeAuthorization(flowId = "flow-auth", code = "auth-code-xyz", state = "wrong-state")
        } catch (e: Throwable) {
            thrown = e
        }
        assertTrue(thrown is WalletException)
        verify(exactly = 0) { engine.resumeIssuance(any(), any(), any(), any(), any()) }

        // The mismatched attempt above must not have consumed the saved
        // resume context - a subsequent call with the real state (e.g. a
        // legitimate retry, or the attacker's forged callback firing before
        // the real one) must still be checked against it, not silently fall
        // through to the no-context branch which sends the flow action with
        // no CSRF validation at all.
        wallet.completeAuthorization(flowId = "flow-auth", code = "auth-code-xyz", state = "state-from-url")
        advanceUntilIdle()
        verify(exactly = 1) { engine.resumeIssuance(any(), any(), any(), any(), any()) }
    }

    @Test
    fun startIssuanceByOffer_passes_redirect_uri_to_engine() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to engine,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                tenantId = "tenant-42",
                redirectUri = "siros-sample://callback",
            ),
        )

        wallet.startIssuanceByOffer(
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "Personal ID",
                issuerName = "Issuer",
            )
        )

        verify(exactly = 1) {
            engine.startIssuance(
                offer = match { offer ->
                    offer.contains("\"credential_issuer\":\"https://issuer.example.com\"") &&
                        offer.contains("\"credential_configuration_ids\":[\"pid\"]")
                },
                credentialOfferUri = null,
                redirectUri = "siros-sample://callback",
            )
        }
    }

    /**
     * go-wallet-backend's credential-type registry service (TS11-backed,
     * carries `attestation_los`/`Vctm.requiredKeyStorage`) was never queried
     * by this SDK at all - only issuer-direct strategies existed. Confirms
     * [WalletConfig.registryUrl]'s zero-config default (derived from
     * [WalletConfig.backendUrl] as `<backendUrl>/registry`) actually reaches
     * [VctmFetcher.fetch] via [SirosWallet.startIssuanceByOffer].
     */
    @Test
    fun startIssuanceByOffer_passesDerivedRegistryUrl_toVctmFetcher() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val vctmFetcher = mockk<org.siros.sdk.credentials.VctmFetcher>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to engine,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "vctmFetcher" to vctmFetcher,
        )

        wallet.startIssuanceByOffer(
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "Personal ID",
                issuerName = "Issuer",
            )
        )

        coVerify(exactly = 1) {
            vctmFetcher.fetchDocument(
                issuerUrl = "https://issuer.example.com",
                scope = "pid",
                vct = null,
                registryUrl = "https://wallet.example.com/registry",
            )
        }
    }

    /**
     * Companion to the above: an integrator whose registry is deployed
     * separately from their main wallet backend must be able to override
     * [WalletConfig.registryUrl] independently - mirroring wallet-frontend's
     * `VCT_REGISTRY_URL` being a distinct, independently-settable config
     * value in that reference implementation, not merely derived.
     */
    @Test
    fun startIssuanceByOffer_passesExplicitConfigRegistryUrl_toVctmFetcher() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val vctmFetcher = mockk<org.siros.sdk.credentials.VctmFetcher>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to engine,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                registryUrl = "https://registry.other-example.com/type-metadata-service",
            ),
            "vctmFetcher" to vctmFetcher,
        )

        wallet.startIssuanceByOffer(
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "Personal ID",
                issuerName = "Issuer",
            )
        )

        coVerify(exactly = 1) {
            vctmFetcher.fetchDocument(
                issuerUrl = "https://issuer.example.com",
                scope = "pid",
                vct = null,
                registryUrl = "https://registry.other-example.com/type-metadata-service",
            )
        }
    }

    /**
     * Same registryUrl wiring, mdoc side: [SirosWallet.resolveEffectiveKeystoreForIssuance]
     * fetches the MDDL schema via [MddlSchemaFetcher] when no [Vctm] is
     * already active, and must pass the same derived/overridable registryUrl
     * through so the registry-first strategy can run there too.
     */
    @Test
    fun resolveEffectiveKeystoreForIssuance_passesRegistryUrl_toMddlSchemaFetcher() = runTest(dispatcher) {
        val defaultKeystore = mockk<KeystoreManager>(relaxed = true)
        // Not relaxed: a relaxed mock would auto-generate a non-null
        // MddlSchema with a mocked (non-blank) requiredKeyStorage/doctype,
        // which would then send resolveEffectiveKeystoreForIssuance down the
        // real WscdSelectionPolicy resolution path and throw
        // NoEligibleWscdPluginException - this test only cares about the
        // registryUrl argument reaching the fetcher, so the schema itself is
        // stubbed to null (registry/issuer both "no data" - the common case).
        val mddlSchemaFetcher = mockk<org.siros.sdk.credentials.MddlSchemaFetcher>()
        coEvery {
            mddlSchemaFetcher.fetch(issuerUrl = any(), scope = any(), vct = any(), registryUrl = any())
        } returns null
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            availableKeystores = mapOf("softkey" to defaultKeystore),
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to defaultKeystore,
            "mddlSchemaFetcher" to mddlSchemaFetcher,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "mdl",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "mDL",
                issuerName = "Issuer",
            ),
        )

        val method = wallet::class.declaredMemberFunctions.first { it.name == "resolveEffectiveKeystoreForIssuance" }
        method.isAccessible = true
        kotlinx.coroutines.runBlocking { method.callSuspend(wallet) }

        coVerify(exactly = 1) {
            mddlSchemaFetcher.fetch(
                issuerUrl = "https://issuer.example.com",
                scope = "mdl",
                vct = null,
                registryUrl = "https://wallet.example.com/registry",
            )
        }
    }

    /**
     * The registry-first VCTM/MDDL strategy queries go-wallet-backend's own
     * credential-type registry service, so it must carry the same
     * `X-Tenant-ID`/`Authorization` headers every other authenticated
     * go-wallet-backend call does (see [BackendApiClient.addCommonHeaders])
     * - the registry's `RequireAuth` gate is deployment-dependent, not always
     * off. This is the regression test for [SirosWallet.fetchTypeMetadataUrl]
     * only attaching those headers when the target URL is the registry
     * service itself - NEVER for the issuer-direct/well-known fallback
     * strategies, which hit arbitrary third-party issuer domains and would
     * otherwise leak the wallet's own bearer token/tenant ID to them.
     */
    @Test
    fun fetchTypeMetadataUrl_attachesAuthHeaders_onlyForRegistryUrl() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setBody("{}"))
            server.enqueue(MockResponse().setBody("{}"))

            val baseUrl = server.url("/").toString().trimEnd('/')
            val wallet = newWallet(
                "config" to WalletConfig(backendUrl = baseUrl, tenantId = "tenant-42"),
                "httpClient" to OkHttpClient(),
                "legacyAppToken" to "test-app-token",
            )

            val method = wallet::class.declaredMemberFunctions.first { it.name == "fetchTypeMetadataUrl" }
            method.isAccessible = true

            // Registry-service URL (derived registryUrl = "$baseUrl/registry"): expect both headers.
            kotlinx.coroutines.runBlocking {
                method.callSuspend(wallet, "$baseUrl/registry/type-metadata?vct=urn%3Aexample%3Adiploma")
            }
            val registryRequest = server.takeRequest()
            assertEquals("tenant-42", registryRequest.getHeader("X-Tenant-ID"))
            assertEquals("Bearer test-app-token", registryRequest.getHeader("Authorization"))

            // Issuer-direct URL (same host, different path - not the registry service): expect neither header.
            kotlinx.coroutines.runBlocking {
                method.callSuspend(wallet, "$baseUrl/type-metadata/diploma_scope")
            }
            val issuerRequest = server.takeRequest()
            assertNull(issuerRequest.getHeader("X-Tenant-ID"))
            assertNull(issuerRequest.getHeader("Authorization"))
        } finally {
            server.shutdown()
        }
    }

    /**
     * `activeOffer` (used to build display metadata for a stored credential -
     * see [CredentialUtils.buildMetadata]/[CredentialUtils.buildMdocMetadata])
     * was previously only ever populated by [SirosWallet.startIssuanceByOffer].
     * The QR/deep-link entry point, [SirosWallet.startIssuance], never set it,
     * so credentials issued via a scanned offer (real-world issuers included)
     * were always stored with no display metadata at all - confirmed against a
     * real geneva2026.mdoc.online mDL credential offer. These tests confirm
     * [SirosWallet.startIssuance] now resolves it by fetching the issuer's
     * standard OID4VCI metadata, for both offer-URI shapes it accepts.
     */
    @Test
    fun startIssuance_resolvesActiveOffer_fromBareOfferJson() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, "org.iso.18013.5.1.mDL")))
            val engine = mockk<WalletEngineSession>(relaxed = true)
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "engineSession" to engine,
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            val issuerUrl = server.url("/").toString().trimEnd('/')
            val offerJson = """{"credential_issuer":"$issuerUrl","credential_configuration_ids":["org.iso.18013.5.1.mDL"]}"""

            wallet.startIssuance(offerJson)
            advanceUntilIdle()

            val activeOffer = getField(wallet, "activeOffer") as? org.siros.sdk.credentials.CredentialOffer
            assertEquals("Mobile Driving License", activeOffer?.credentialName)
            assertEquals(issuerUrl, activeOffer?.credentialIssuerIdentifier)
            assertEquals("org.iso.18013.5.1.mDL", activeOffer?.credentialConfigurationId)
            verify(exactly = 1) { engine.startIssuance(offer = offerJson, credentialOfferUri = null, redirectUri = "siros-sample://callback") }
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun startIssuance_resolvesActiveOffer_fromOpenidCredentialOfferDeepLink() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, "org.iso.18013.5.1.mDL")))
            val engine = mockk<WalletEngineSession>(relaxed = true)
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "engineSession" to engine,
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            val issuerUrl = server.url("/").toString().trimEnd('/')
            val offerJson = """{"credential_issuer":"$issuerUrl","credential_configuration_ids":["org.iso.18013.5.1.mDL"]}"""
            val deepLink = "openid-credential-offer://?credential_offer=" +
                java.net.URLEncoder.encode(offerJson, "UTF-8")

            wallet.startIssuance(deepLink)
            advanceUntilIdle()

            val activeOffer = getField(wallet, "activeOffer") as? org.siros.sdk.credentials.CredentialOffer
            assertEquals("Mobile Driving License", activeOffer?.credentialName)
            assertEquals(issuerUrl, activeOffer?.credentialIssuerIdentifier)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun startIssuance_leavesActiveOfferNull_andStillIssues_whenIssuerMetadataUnreachable() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to engine,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        // No mdoc/scope matches any listening server - metadata resolution fails,
        // but issuance must still proceed.
        val offerJson = """{"credential_issuer":"https://issuer.invalid","credential_configuration_ids":["pid"]}"""

        wallet.startIssuance(offerJson)
        advanceUntilIdle()

        assertEquals(null, getField(wallet, "activeOffer"))
        verify(exactly = 1) { engine.startIssuance(offer = offerJson, credentialOfferUri = null, redirectUri = "siros-sample://callback") }
    }

    /**
     * Regression (real bug, live Geneva interop testing): a slow/unresponsive
     * issuer leaves the wallet in [WalletState.Ready] the whole time it's
     * awaiting the engine's first progress message, since the engine doesn't
     * assign (and report) a flow ID until then - [WalletState.FlowActive] is
     * never reached. `cancelCurrentFlow()` used to reset the issuance-guard
     * fields only inside its `is WalletState.FlowActive` branch, so cancelling
     * during exactly that window did nothing at all - not even a local reset -
     * permanently stranding `issuanceInFlight` at `true` and rejecting every
     * subsequent issuance attempt with "Another issuance is already in
     * progress" until the app process was killed. Verifies
     * [SirosWallet.cancelCurrentFlow] now clears the guard unconditionally.
     */
    @Test
    fun cancelCurrentFlow_clearsIssuanceGuard_whenIssuerNeverReachedFlowActive() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to engine,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        val offerJson = """{"credential_issuer":"https://issuer.invalid","credential_configuration_ids":["pid"]}"""

        // First attempt: the (slow/unresponsive) issuer never progresses the
        // wallet past Ready, so no FlowActive is ever reached.
        wallet.startIssuance(offerJson)
        advanceUntilIdle()
        assertTrue(getField(wallet, "issuanceInFlight") as Boolean)

        wallet.cancelCurrentFlow()
        assertTrue(
            "cancelCurrentFlow() must clear issuanceInFlight even when no FlowActive state was ever reached",
            (getField(wallet, "issuanceInFlight") as Boolean).not(),
        )

        // Retrying must succeed - not throw "Another issuance is already in progress".
        wallet.startIssuance(offerJson)
        advanceUntilIdle()

        verify(exactly = 2) { engine.startIssuance(offer = offerJson, credentialOfferUri = null, redirectUri = "siros-sample://callback") }
    }

    /**
     * A `ZkIssuancePreparation` carries what the holder committed to before
     * the issuer signed - for blind BBS the secret prover blind behind the
     * commitment. A cancelled issuance never produces a credential, so
     * nothing will ever consume it: left in the pending map it would sit
     * in process memory indefinitely
     * and gain one entry per cancelled attempt. Verifies
     * [SirosWallet.cancelCurrentFlow] drops the cancelled flow's preparation
     * and leaves other flows' alone.
     */
    @Test
    fun cancelCurrentFlow_discardsThatFlowsUnconsumedZkIssuancePreparation() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val accountRegistry = mockk<AccountRegistry>(relaxed = true)
        every { accountRegistry.listAccounts() } returns emptyList()
        val preparations =
            java.util.concurrent.ConcurrentHashMap<String, org.siros.sdk.credentials.ZkIssuancePreparation>()
        preparations["flow-1"] = fakeZkIssuancePreparation()
        preparations["flow-2"] = fakeZkIssuancePreparation()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-1",
                    flowType = "issuance",
                    status = "in_progress",
                )
            ),
            "engineSession" to engine,
            "accountRegistry" to accountRegistry,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
            "zkPreparationsByFlow" to preparations,
        )

        wallet.cancelCurrentFlow()

        assertNull(
            "cancelCurrentFlow() must discard the cancelled flow's holder commitment material",
            preparations["flow-1"],
        )
        assertNotNull(
            "cancelling one flow must not consume another flow's preparation",
            preparations["flow-2"],
        )
    }

    private fun fakeZkIssuancePreparation() = object : org.siros.sdk.credentials.ZkIssuancePreparation {
        override val credentialRequestFields: Map<String, String> =
            mapOf("bbs_commitment" to "\"AAAA\"")
    }

    /** header.{"exp": exp}.sig - just enough for CredentialUtils.parseJwtPayload to read `exp`. */
    private fun fakeJwtWithExp(exp: Long): String {
        val payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""{"exp":$exp}""".toByteArray(Charsets.UTF_8))
        return "eyJhbGciOiJub25lIn0.$payload.sig"
    }

    /** A fake WIA JWT carrying `exp`, `cnf.jkt`, and `attestation_source` - for currentWalletInstanceId() tests. */
    private fun fakeWiaJwt(exp: Long, jkt: String?, attestationSource: String?): String {
        val cnfField = if (jkt != null) ""","cnf":{"jkt":"$jkt"}""" else ""
        val sourceField = if (attestationSource != null) ""","attestation_source":"$attestationSource"""" else ""
        val payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""{"exp":$exp$cnfField$sourceField}""".toByteArray(Charsets.UTF_8))
        return "eyJhbGciOiJub25lIn0.$payload.sig"
    }

    /**
     * OAuth Client Attestation is engine-requested now (go-wallet-backend#304
     * `request_attestation`, see requestAttestationSignRequest_* below):
     * startIssuance sends the flow_start bare - no WIA challenge round trip,
     * no per-issuer PoP, and no attestation-only offer/metadata fetch on this
     * side. The single issuer metadata fetch left is resolveOfferForDisplay's.
     */
    @Test
    fun startIssuance_sendsNoClientAttestation_engineRequestsIt() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setBody(issuerMetadataJson(server, "org.iso.18013.5.1.mDL")))
            val engine = mockk<WalletEngineSession>(relaxed = true)
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            val apiClient = mockk<BackendApiClient>(relaxed = true)

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "engineSession" to engine,
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            val issuerUrl = server.url("/").toString().trimEnd('/')
            val offerJson = """{"credential_issuer":"$issuerUrl","credential_configuration_ids":["org.iso.18013.5.1.mDL"]}"""

            wallet.startIssuance(offerJson)
            advanceUntilIdle()

            verify(exactly = 1) {
                engine.startIssuance(
                    offer = offerJson,
                    credentialOfferUri = null,
                    redirectUri = "siros-sample://callback",
                    clientAttestation = null,
                    clientAttestationPoP = null,
                )
            }
            coVerify(exactly = 0) { apiClient.requestWIAChallenge() }
            coVerify(exactly = 0) { apiClient.generateWIA(any(), any(), any(), any()) }
            coVerify(exactly = 0) { keystore.generateKeyProof(any(), any(), any(), any(), any()) }
            // Exactly one issuer metadata fetch (display), none for attestation.
            assertEquals(1, server.requestCount)
        } finally {
            server.shutdown()
        }
    }

    /**
     * When a `nativeAttestationProvider` is configured, `ensureWalletInstanceAttestation()`
     * must attach its evidence to the WIA generate call as `native_attestation`,
     * snake_case `key_id` included, so the backend's KA trust gate can see it.
     * Triggered the way it happens in production: by the engine's
     * `request_attestation` sign request.
     */
    @Test
    fun requestAttestation_includesNativeAttestation_whenProviderConfigured() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            // fetchAttestationChallenge's two well-known probes: no challenge_endpoint.
            server.enqueue(MockResponse().setResponseCode(404))
            server.enqueue(MockResponse().setResponseCode(404))
            val asUrl = server.url("/").toString().trimEnd('/')

            val signFlow = MutableSharedFlow<SignRequestMessage>()
            val engine = mockEngineConstructor(signRequests = signFlow)
            every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any()) } just runs
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            coEvery {
                keystore.generateKeyProof(keyId = any(), typ = any(), issuer = any(), audience = any(), extraClaims = any())
            } returns "pop-jwt"
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            coEvery { apiClient.requestWIAChallenge() } returns buildJsonObject { put("challenge", "chal-1") }
            val wiaJwt = fakeJwtWithExp(System.currentTimeMillis() / 1000 + 3600)
            val nativeAttestationSlot = slot<JsonObject>()
            coEvery {
                apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = any(), nativeAttestation = capture(nativeAttestationSlot))
            } returns wiaJwt
            val provider = object : NativeAttestationProvider {
                override val isAvailable = true
                override suspend fun generateEvidence(challenge: String, keyId: String) = NativeAttestationEvidence(
                    type = "google_play_integrity",
                    token = "integrity-token-abc",
                    keyId = keyId,
                    challenge = challenge,
                )
            }

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "config" to WalletConfig(
                    backendUrl = "https://wallet.example.com",
                    redirectUri = "siros-sample://callback",
                    nativeAttestationProvider = provider,
                ),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            invokeConnectEngine(wallet, "app-token")
            advanceUntilIdle()

            signFlow.emit(
                SignRequestMessage(
                    flowId = "flow-att",
                    messageId = "msg-att",
                    action = "request_attestation",
                    params = SignRequestParams(audience = asUrl, issuer = "siros-sample://callback"),
                )
            )
            repeat(10) {
                runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(100) }
                advanceUntilIdle()
            }

            verify(exactly = 1) {
                engine.sendSignResponse(
                    flowId = "flow-att",
                    messageId = "msg-att",
                    clientAttestation = wiaJwt,
                    clientAttestationPoP = "pop-jwt",
                )
            }
            val nativeAttestation = nativeAttestationSlot.captured
            assertEquals("google_play_integrity", nativeAttestation["type"]?.jsonPrimitive?.content)
            assertEquals("integrity-token-abc", nativeAttestation["token"]?.jsonPrimitive?.content)
            assertEquals("instance-key-1", nativeAttestation["key_id"]?.jsonPrimitive?.content)
            assertEquals("chal-1", nativeAttestation["challenge"]?.jsonPrimitive?.content)
        } finally {
            server.shutdown()
        }
    }

    /**
     * `sign_client_auth` (go-wallet-backend#317): the engine asks for a DPoP
     * proof and a fresh attestation PoP for one request. Both must be signed
     * with the instance key - the WIA's `cnf` key - and the reply must name
     * that key as `dpop_key_id`, so the sender-constrained token ends up
     * bound to the attested key.
     */
    @Test
    fun signClientAuth_signsDpopAndFreshPopWithInstanceKey() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            // fetchAttestationChallenge's two well-known probes: no challenge_endpoint.
            server.enqueue(MockResponse().setResponseCode(404))
            server.enqueue(MockResponse().setResponseCode(404))
            val asUrl = server.url("/").toString().trimEnd('/')

            val signFlow = MutableSharedFlow<SignRequestMessage>()
            val engine = mockEngineConstructor(signRequests = signFlow)
            every {
                engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
            } just runs
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            coEvery {
                keystore.generateKeyProof(keyId = any(), typ = any(), issuer = any(), audience = any(), extraClaims = any())
            } returns "pop-jwt"
            coEvery {
                keystore.generateDPoPProof(keyId = any(), htm = any(), htu = any(), nonce = any(), accessTokenHash = any())
            } returns "dpop-jwt"
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            coEvery { apiClient.requestWIAChallenge() } returns buildJsonObject { put("challenge", "chal-1") }
            val wiaJwt = fakeJwtWithExp(System.currentTimeMillis() / 1000 + 3600)
            coEvery { apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = any(), nativeAttestation = any()) } returns wiaJwt

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            invokeConnectEngine(wallet, "app-token")
            advanceUntilIdle()

            signFlow.emit(
                SignRequestMessage(
                    flowId = "flow-ca",
                    messageId = "msg-ca",
                    action = "sign_client_auth",
                    params = SignRequestParams(
                        audience = asUrl,
                        issuer = "siros-sample://callback",
                        htm = "POST",
                        htu = "$asUrl/token",
                        dpopNonce = "n-1",
                        ath = "ath-value",
                    ),
                )
            )
            repeat(10) {
                runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(100) }
                advanceUntilIdle()
            }

            coVerify(exactly = 1) {
                keystore.generateDPoPProof(
                    keyId = "instance-key-1",
                    htm = "POST",
                    htu = "$asUrl/token",
                    nonce = "n-1",
                    accessTokenHash = "ath-value",
                )
            }
            // The per-issuer PoP is signed with the same instance key, aud = the AS.
            coVerify(exactly = 1) {
                keystore.generateKeyProof(
                    keyId = "instance-key-1",
                    typ = "oauth-client-attestation-pop+jwt",
                    issuer = "siros-sample://callback",
                    audience = asUrl,
                    extraClaims = any(),
                )
            }
            verify(exactly = 1) {
                engine.sendSignResponse(
                    flowId = "flow-ca",
                    messageId = "msg-ca",
                    clientAttestation = wiaJwt,
                    clientAttestationPoP = "pop-jwt",
                    dpopKeyId = "instance-key-1",
                    dpopProof = "dpop-jwt",
                )
            }
        } finally {
            server.shutdown()
        }
    }

    /**
     * A resource-request `sign_client_auth` (no audience) yields a DPoP proof
     * only, and a renewal's `key_id` picks the key the refresh_token was bound
     * to instead of the current instance key. No WIA round trip either way.
     */
    @Test
    fun signClientAuth_dpopOnly_honoursKeyIdHint() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every {
            engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } just runs
        val sessionStore = mockk<SessionStore>(relaxed = true)
        every { sessionStore.instanceKeyId } returns "instance-key-1"
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery {
            keystore.generateDPoPProof(keyId = any(), htm = any(), htu = any(), nonce = any(), accessTokenHash = any())
        } returns "dpop-jwt"
        val apiClient = mockk<BackendApiClient>(relaxed = true)

        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "sessionStore" to sessionStore,
            "keystore" to keystore,
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()

        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-cred",
                messageId = "msg-cred",
                action = "sign_client_auth",
                params = SignRequestParams(
                    htm = "POST",
                    htu = "https://issuer.example.com/credential",
                    ath = "ath-value",
                    keyId = "old-instance-key",
                ),
            )
        )
        repeat(10) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(100) }
            advanceUntilIdle()
        }

        coVerify(exactly = 1) {
            keystore.generateDPoPProof(
                keyId = "old-instance-key",
                htm = "POST",
                htu = "https://issuer.example.com/credential",
                nonce = null,
                accessTokenHash = "ath-value",
            )
        }
        coVerify(exactly = 0) { apiClient.requestWIAChallenge() }
        coVerify(exactly = 0) { keystore.generateKeyProof(any(), any(), any(), any(), any()) }
        verify(exactly = 1) {
            engine.sendSignResponse(
                flowId = "flow-cred",
                messageId = "msg-cred",
                clientAttestation = null,
                clientAttestationPoP = null,
                dpopKeyId = "old-instance-key",
                dpopProof = "dpop-jwt",
            )
        }
    }

    /**
     * `deactivateWallet()` (SID-AUTH-06): revoke every instance server-side,
     * then forget the local account - the vault it decrypts no longer exists.
     */
    @Test
    fun deactivateWallet_revokesAllAndForgetsLocalAccount() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.revokeAllWalletInstances("device stolen") } returns
            DeactivationOutcome(revoked = 2, complete = true)
        val accountRegistry = mockk<AccountRegistry>(relaxed = true)
        every { accountRegistry.activeAccountId } returns "acct-1"
        every { accountRegistry.listLoginableAccounts() } returns emptyList()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to mockk<WalletEngineSession>(relaxed = true),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "sessionStore" to mockk<SessionStore>(relaxed = true),
            "accountRegistry" to accountRegistry,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
        )

        val outcome = wallet.deactivateWallet("device stolen")

        assertEquals(2, outcome.revoked)
        assertTrue(outcome.complete)
        coVerify(exactly = 1) { apiClient.revokeAllWalletInstances("device stolen") }
        verify(exactly = 1) { accountRegistry.removeAccount("acct-1") }
    }

    /**
     * When requesting a backend Key Attestation, each freshly generated
     * credential-issuance key's own FIDO2/CTAP2 attestation (not the wallet's
     * identity key) must be registered with the backend individually, so the
     * per-key trust evidence lines up with the actual keys the KA request's
     * `attested_keys`/`security_properties` claim is about (see
     * `registerFido2AttestationsForBatch`'s doc comment).
     */
    @Test
    fun requestBackendKeyAttestation_registersFido2Attestation_perHardwareBackedKey() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val keypairs = listOf(
            KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }),
            KeypairInfo(keyId = "key-2", publicKeyJWK = buildJsonObject { put("kty", "EC") }),
        )
        coEvery { keystore.generateKeypairs(2) } returns keypairs
        val chain1 = AttestationChain(certificates = listOf(byteArrayOf(0x01)), clientDataHash = ByteArray(32) { 0x09 })
        val chain2 = AttestationChain(certificates = listOf(byteArrayOf(0x02)), clientDataHash = ByteArray(32) { 0x0a })
        coEvery { keystore.attestationChain("key-1") } returns chain1
        coEvery { keystore.attestationChain("key-2") } returns chain2
        coEvery { keystore.securityProperties("key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = null,
                credentialIssuer = "aud-1",
                walletInstanceId = "test-jkt",
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        setField(wallet, "cachedWia", fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "ios_app_attest"))
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 2,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) {
            apiClient.registerFido2Attestation(
                walletInstanceId = "test-jkt",
                attestationObject = chain1.certificates[0],
                clientDataHash = chain1.clientDataHash,
            )
        }
        coVerify(exactly = 1) {
            apiClient.registerFido2Attestation(
                walletInstanceId = "test-jkt",
                attestationObject = chain2.certificates[0],
                clientDataHash = chain2.clientDataHash,
            )
        }
    }

    /**
     * A key generated by a non-hardware-backed (e.g. softkey) plugin has no
     * attestation chain - registration for that key must be skipped, not
     * fail the whole batch or the KA request itself.
     */
    @Test
    fun requestBackendKeyAttestation_skipsFido2Registration_forSoftwareBackedKeys() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val keypairs = listOf(KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { keystore.generateKeypairs(1) } returns keypairs
        coEvery { keystore.attestationChain("key-1") } returns null
        coEvery { keystore.securityProperties("key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = null,
                credentialIssuer = "aud-1",
                walletInstanceId = "test-jkt",
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        setField(wallet, "cachedWia", fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "ios_app_attest"))
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 0) {
            apiClient.registerFido2Attestation(any<String>(), any<ByteArray>(), any<ByteArray>())
        }
    }

    /**
     * With no cached WIA available, there's no `wallet_instance_id` to
     * scope the registration record to - `registerFido2AttestationsForBatch`
     * must skip registration entirely without touching `attestationChain`,
     * and must not block the KA request itself.
     */
    @Test
    fun requestBackendKeyAttestation_skipsFido2Registration_whenNoCachedWia() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val keypairs = listOf(KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { keystore.generateKeypairs(1) } returns keypairs
        coEvery { keystore.securityProperties("key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = null,
                credentialIssuer = "aud-1",
                walletInstanceId = null,
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { keystore.attestationChain(any<String>()) }
        coVerify(exactly = 0) {
            apiClient.registerFido2Attestation(any<String>(), any<ByteArray>(), any<ByteArray>())
        }
    }

    private class InMemoryWscdTofuStore : WscdTofuStore {
        val entries = mutableMapOf<String, String>()
        private fun key(issuer: String, credentialType: String) = "$issuer|$credentialType"
        override fun get(issuer: String, credentialType: String): String? = entries[key(issuer, credentialType)]
        override fun put(issuer: String, credentialType: String, pluginId: String) {
            entries[key(issuer, credentialType)] = pluginId
        }
    }

    /**
     * End-to-end: an issuer with multiple registered [WalletConfig.availableKeystores]
     * plugins, requesting a Key Attestation for a credential type that
     * declares (via [Vctm.requiredKeyStorage]) it needs `iso_18045_high` -
     * only the "fido2" plugin's static tier meets that per
     * [org.siros.sdk.keystore.WscdPluginCapabilities], so
     * [WscdSelectionPolicy] must auto-pick it (the only eligible plugin, see
     * that class's resolution order) and `generateKeypairs` must be called
     * on the fido2 keystore instance, never on the wallet's own default
     * [keystore].
     */
    @Test
    fun requestBackendKeyAttestation_usesEligiblePlugin_forCredentialTypeRequiringHigherTier() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>()
        val fido2Keystore = mockk<KeystoreManager>()
        val keypairs = listOf(KeypairInfo(keyId = "fido2-key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { fido2Keystore.generateKeypairs(1) } returns keypairs
        coEvery { fido2Keystore.attestationChain(any()) } returns null
        coEvery { fido2Keystore.securityProperties("fido2-key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = null,
                credentialIssuer = "https://issuer.example.com",
                walletInstanceId = null,
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            availableKeystores = mapOf("softkey" to defaultKeystore, "fido2" to fido2Keystore),
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to defaultKeystore,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
            ),
        )
        setField(
            wallet,
            "activeVctm",
            org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = "iso_18045_high"),
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "https://issuer.example.com",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { fido2Keystore.generateKeypairs(1) }
        coVerify(exactly = 0) { defaultKeystore.generateKeypairs(any()) }
    }

    /**
     * Reproduces a real bug found via live testing: the `jwt` proof branch
     * (preferred over `attestation` whenever an issuer supports it - the
     * common case) used to sign directly on the wallet's own default
     * [KeystoreManager], never consulting [WscdSelectionPolicy] at all. A
     * credential type requiring `iso_18045_high` with only "fido2"
     * registered as eligible must still route signing to the fido2
     * keystore even when the issuer only advertises `jwt` support - not
     * just when it advertises `attestation` (see the sibling
     * `requestBackendKeyAttestation_usesEligiblePlugin_forCredentialTypeRequiringHigherTier`
     * test for that half).
     */
    @Test
    fun generateProofsForRequest_usesEligiblePlugin_forJwtProofType_notJustAttestation() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>(relaxed = true)
        val fido2Keystore = mockk<KeystoreManager>()
        coEvery { fido2Keystore.generateProof(audience = any(), nonce = any(), freshKey = any()) } returns "fido2-signed-proof-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            availableKeystores = mapOf("softkey" to defaultKeystore, "fido2" to fido2Keystore),
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to defaultKeystore,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
            ),
        )
        setField(
            wallet,
            "activeVctm",
            org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = "iso_18045_high"),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "https://issuer.example.com",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("jwt") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { fido2Keystore.generateProof(audience = "https://issuer.example.com", nonce = "nonce-1", freshKey = false) }
        coVerify(exactly = 0) { defaultKeystore.generateProof(any(), any(), any()) }
    }

    /**
     * When zero registered plugins meet a credential type's declared
     * requirement, [WscdSelectionPolicy] throws [NoEligibleWscdPluginException]
     * - `requestBackendKeyAttestation` must let it propagate rather than
     * quietly falling back to the (insufficient) default keystore, so no
     * keys are ever generated with a plugin that can't satisfy the
     * requirement and no sign response is sent for that request.
     */
    @Test
    fun requestBackendKeyAttestation_doesNotFallBack_whenNoPluginMeetsRequirement() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        val engine = mockEngineConstructor(signRequests = signFlow)
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            // Only "softkey" ("basic") registered - insufficient for "high".
            availableKeystores = mapOf("softkey" to defaultKeystore),
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to defaultKeystore,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
            ),
        )
        setField(
            wallet,
            "activeVctm",
            org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = "iso_18045_high"),
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "https://issuer.example.com",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { defaultKeystore.generateKeypairs(any()) }
        coVerify(exactly = 0) { engine.sendSignResponse(any(), any(), any(), any()) }
    }

    /**
     * Regression (PR #85 review, bug 1): `resolveEffectiveKeystoreForIssuance`
     * must key [WscdSelectionPolicy] lookups (TOFU/defaultMapping) by the
     * credential type's real `vct`/`doctype` identifier, NOT
     * `CredentialOffer.credentialConfigurationId` - the two are deliberately
     * different here (`credentialConfigurationId` is an OID4VCI-internal ID
     * the docs/config examples never use as a key). A TOFU entry keyed by the
     * `vct` for a plugin that's the ONLY one of two eligible plugins must be
     * found and used without prompting - if the buggy `credentialConfigurationId`
     * key were still used instead, this TOFU lookup would miss, both eligible
     * plugins ("fido2"/"r2ps") would fall through to the ask-user step, and
     * (with no `requestWscdChoice` configured) resolution would throw
     * [AmbiguousWscdPluginException] instead of silently succeeding.
     */
    @Test
    fun resolveEffectiveKeystoreForIssuance_keysWscdLookupByVct_notCredentialConfigurationId() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val fido2Keystore = mockk<KeystoreManager>()
        val r2psKeystore = mockk<KeystoreManager>(relaxed = true)
        val keypairs = listOf(KeypairInfo(keyId = "fido2-key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { fido2Keystore.generateKeypairs(1) } returns keypairs
        coEvery { fido2Keystore.attestationChain(any()) } returns null
        coEvery { fido2Keystore.securityProperties("fido2-key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = null,
                credentialIssuer = "https://issuer.example.com",
                walletInstanceId = null,
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            availableKeystores = mapOf("fido2" to fido2Keystore, "r2ps" to r2psKeystore),
        )
        // TOFU pre-populated keyed by the real vct, not the (deliberately
        // different) credentialConfigurationId set below.
        val tofuStore = InMemoryWscdTofuStore().apply {
            put("https://issuer.example.com", "urn:eu.europa.ec.eudi:pid:1", "fido2")
        }
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to fido2Keystore,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = tofuStore),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "totally-different-internal-config-id",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
            ),
        )
        setField(
            wallet,
            "activeVctm",
            org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = "iso_18045_high"),
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "https://issuer.example.com",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { fido2Keystore.generateKeypairs(1) }
        coVerify(exactly = 0) { r2psKeystore.generateKeypairs(any()) }
    }

    /**
     * Regression (PR #85 review, bug 2): when the backend Key Attestation
     * call fails, the self-signed fallback
     * ([KeystoreManager.generateKeyAttestation]) must be invoked on the SAME
     * resolved plugin [WscdSelectionPolicy] picked for this call (here,
     * "fido2"), never on the wallet's own unconditional default `keystore`
     * field - otherwise a resolved higher-tier plugin is silently bypassed on
     * fallback, downgrading to a lower-tier self-signed attestation.
     */
    @Test
    fun requestBackendKeyAttestation_selfSignedFallback_usesResolvedKeystore_notWalletDefault() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>(relaxed = true)
        val fido2Keystore = mockk<KeystoreManager>()
        val keypairs = listOf(KeypairInfo(keyId = "fido2-key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { fido2Keystore.generateKeypairs(1) } returns keypairs
        coEvery { fido2Keystore.attestationChain(any()) } returns null
        coEvery { fido2Keystore.securityProperties("fido2-key-1") } returns null
        coEvery { fido2Keystore.generateKeyAttestation(nonce = "nonce-1", count = 1) } returns "self-signed-by-fido2"
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        // Simulate the backend attestation call failing, forcing the
        // self-signed fallback path.
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = any(),
                nonce = any(),
                securityProperties = any(),
                credentialIssuer = any(),
                walletInstanceId = any(),
            )
        } throws RuntimeException("backend unavailable")
        val engine = mockEngineConstructor(signRequests = signFlow)
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            availableKeystores = mapOf("softkey" to defaultKeystore, "fido2" to fido2Keystore),
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to defaultKeystore,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
        )
        setField(
            wallet,
            "activeOffer",
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "PID",
                issuerName = "Issuer",
            ),
        )
        setField(
            wallet,
            "activeVctm",
            org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = "iso_18045_high"),
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "https://issuer.example.com",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { fido2Keystore.generateKeyAttestation(nonce = "nonce-1", count = 1) }
        coVerify(exactly = 0) { defaultKeystore.generateKeyAttestation(any(), any()) }
    }

    /**
     * A native-attestation failure (device doesn't support it, Play Services
     * missing, etc.) must degrade to a plain backend-attested WIA, not decline
     * the engine's `request_attestation` entirely - the same best-effort
     * contract as every other step of ensureWalletInstanceAttestation().
     */
    @Test
    fun requestAttestation_omitsNativeAttestation_whenProviderThrows() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            server.enqueue(MockResponse().setResponseCode(404))
            server.enqueue(MockResponse().setResponseCode(404))
            val asUrl = server.url("/").toString().trimEnd('/')

            val signFlow = MutableSharedFlow<SignRequestMessage>()
            val engine = mockEngineConstructor(signRequests = signFlow)
            every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any()) } just runs
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            coEvery {
                keystore.generateKeyProof(keyId = any(), typ = any(), issuer = any(), audience = any(), extraClaims = any())
            } returns "pop-jwt"
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            coEvery { apiClient.requestWIAChallenge() } returns buildJsonObject { put("challenge", "chal-1") }
            val wiaJwt = fakeJwtWithExp(System.currentTimeMillis() / 1000 + 3600)
            coEvery {
                apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = any(), nativeAttestation = null)
            } returns wiaJwt
            val throwingProvider = object : NativeAttestationProvider {
                override val isAvailable = true
                override suspend fun generateEvidence(challenge: String, keyId: String): NativeAttestationEvidence {
                    throw IllegalStateException("device attestation unavailable")
                }
            }

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "config" to WalletConfig(
                    backendUrl = "https://wallet.example.com",
                    redirectUri = "siros-sample://callback",
                    nativeAttestationProvider = throwingProvider,
                ),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            invokeConnectEngine(wallet, "app-token")
            advanceUntilIdle()

            signFlow.emit(
                SignRequestMessage(
                    flowId = "flow-att",
                    messageId = "msg-att",
                    action = "request_attestation",
                    params = SignRequestParams(audience = asUrl, issuer = "siros-sample://callback"),
                )
            )
            repeat(10) {
                runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(100) }
                advanceUntilIdle()
            }

            verify(exactly = 1) {
                engine.sendSignResponse(
                    flowId = "flow-att",
                    messageId = "msg-att",
                    clientAttestation = wiaJwt,
                    clientAttestationPoP = "pop-jwt",
                )
            }
        } finally {
            server.shutdown()
        }
    }

    /**
     * draft-ietf-oauth-attestation-based-client-auth-10 fixes, confirmed
     * against a real geneva2026.mdoc.online conformance run:
     * - the WIA's `sub` and the per-issuer PoP's `iss` must both equal the
     *   OAuth client_id - a real credential offer flagged sub/iss=<instance
     *   jkt> as FAILs. The PoP `iss` is the engine-supplied effective
     *   client_id (params.issuer); the WIA `sub` is config.redirectUri.
     * - the per-issuer PoP's optional `challenge` claim, when the issuer's AS
     *   publishes a `challenge_endpoint` in its metadata, must be fetched
     *   from there and included - flagged as a FAIL when absent. The AS is
     *   now the engine-supplied params.audience: no issuer metadata fetch on
     *   this side.
     */
    @Test
    fun requestAttestation_usesClientIdForSubAndIss_andFetchesChallengeFromEngineSuppliedAs() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            val asUrl = server.url("/").toString().trimEnd('/')
            server.enqueue(MockResponse().setBody("""{"challenge_endpoint":"$asUrl/attestation/challenge"}"""))
            server.enqueue(MockResponse().setBody("""{"attestation_challenge":"chal-from-issuer-as"}"""))

            val signFlow = MutableSharedFlow<SignRequestMessage>()
            val engine = mockEngineConstructor(signRequests = signFlow)
            every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any()) } just runs
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            coEvery {
                keystore.generateKeyProof(
                    keyId = any(), typ = any(), issuer = "siros-sample://callback",
                    audience = "https://wallet.example.com", extraClaims = any(),
                )
            } returns "wia-pop-jwt"
            val perIssuerExtraClaims = slot<Map<String, String>>()
            coEvery {
                keystore.generateKeyProof(
                    keyId = any(), typ = "oauth-client-attestation-pop+jwt", issuer = "siros-sample://callback",
                    audience = asUrl, extraClaims = capture(perIssuerExtraClaims),
                )
            } returns "issuer-pop-jwt"
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            coEvery { apiClient.requestWIAChallenge() } returns buildJsonObject { put("challenge", "chal-1") }
            val wiaJwt = fakeJwtWithExp(System.currentTimeMillis() / 1000 + 3600)
            coEvery { apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = any()) } returns wiaJwt

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "apiClient" to apiClient,
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            invokeConnectEngine(wallet, "app-token")
            advanceUntilIdle()

            signFlow.emit(
                SignRequestMessage(
                    flowId = "flow-att",
                    messageId = "msg-att",
                    action = "request_attestation",
                    params = SignRequestParams(audience = asUrl, issuer = "siros-sample://callback"),
                )
            )
            repeat(10) {
                runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(100) }
                advanceUntilIdle()
            }

            coVerify(exactly = 1) {
                apiClient.generateWIA(pop = any(), challenge = "chal-1", clientId = "siros-sample://callback")
            }
            assertEquals("chal-from-issuer-as", perIssuerExtraClaims.captured["challenge"])
            verify(exactly = 1) {
                engine.sendSignResponse(
                    flowId = "flow-att",
                    messageId = "msg-att",
                    clientAttestation = wiaJwt,
                    clientAttestationPoP = "issuer-pop-jwt",
                )
            }
            // Only the AS metadata + challenge round trip hit the network.
            assertEquals(2, server.requestCount)
        } finally {
            server.shutdown()
        }
    }

    /** Missing/unavailable WIA support must never block issuance - engine.startIssuance still fires, with nulls. */
    /**
     * Engine-requested client attestation (go-wallet-backend#304,
     * `SignActionRequestAttestation`): when the flow_start carried no WIA the
     * backend asks for one after resolving the issuer's authorization server,
     * handing us the PoP `aud` (`params.audience`) and `iss` (`params.issuer`)
     * itself. The reply must carry the WIA and a PoP signed over exactly those
     * values, correlated by message_id.
     */
    @Test
    fun requestAttestationSignRequest_repliesWithWiaAndPopOverEngineSuppliedAudAndIss() = runTest(dispatcher) {
        val server = MockWebServer()
        server.start()
        try {
            // fetchAttestationChallenge probes the AS's two well-known metadata
            // paths; neither publishes a challenge_endpoint here.
            server.enqueue(MockResponse().setResponseCode(404))
            server.enqueue(MockResponse().setResponseCode(404))
            val asUrl = server.url("/").toString().trimEnd('/')

            val signFlow = MutableSharedFlow<SignRequestMessage>()
            val engine = mockEngineConstructor(signRequests = signFlow)
            every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any()) } just runs
            val sessionStore = mockk<SessionStore>(relaxed = true)
            every { sessionStore.instanceKeyId } returns "instance-key-1"
            val keystore = mockk<KeystoreManager>(relaxed = true)
            coEvery {
                keystore.generateKeyProof(
                    keyId = "instance-key-1", typ = "oauth-client-attestation-pop+jwt",
                    issuer = "https://registered-client.example.com", audience = asUrl, extraClaims = any(),
                )
            } returns "engine-pop-jwt"
            val wiaJwt = fakeJwtWithExp(System.currentTimeMillis() / 1000 + 3600)

            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
                "sessionStore" to sessionStore,
                "keystore" to keystore,
                "json" to Json { ignoreUnknownKeys = true },
                "httpClient" to OkHttpClient(),
            )
            invokeConnectEngine(wallet, "app-token")
            setField(wallet, "cachedWia", wiaJwt)
            setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)
            advanceUntilIdle()

            signFlow.emit(
                SignRequestMessage(
                    flowId = "flow-att",
                    messageId = "msg-att-1",
                    action = "request_attestation",
                    params = SignRequestParams(
                        audience = asUrl,
                        issuer = "https://registered-client.example.com",
                    ),
                )
            )
            // fetchAttestationChallenge hops onto the real Dispatchers.IO for
            // its MockWebServer calls - see requestAttestation_usesClientIdForSubAndIss_andFetchesChallengeFromEngineSuppliedAs.
            repeat(10) {
                runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(100) }
                advanceUntilIdle()
            }

            verify(exactly = 1) {
                engine.sendSignResponse(
                    flowId = "flow-att",
                    messageId = "msg-att-1",
                    clientAttestation = wiaJwt,
                    clientAttestationPoP = "engine-pop-jwt",
                )
            }
            // Fallback client_id (config.redirectUri) must NOT have been used
            // when the engine supplied the flow's effective client_id.
            coVerify(exactly = 0) {
                keystore.generateKeyProof(keyId = any(), typ = any(), issuer = "siros-sample://callback", audience = any(), extraClaims = any())
            }
        } finally {
            server.shutdown()
        }
    }

    /**
     * No WIA available (backend WIA support unreachable/disabled) must still
     * produce exactly one - empty - sign_response for the request's
     * message_id, so go-wallet-backend proceeds without attestation right
     * away instead of stalling the issuance for its 30 s ErrSignTimeout.
     */
    @Test
    fun requestAttestationSignRequest_sendsEmptyResponse_whenNoWiaAvailable() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val sessionStore = mockk<SessionStore>(relaxed = true)
        every { sessionStore.instanceKeyId } returns "instance-key-1"
        val keystore = mockk<KeystoreManager>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.requestWIAChallenge() } throws java.io.IOException("backend unreachable")

        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "sessionStore" to sessionStore,
            "keystore" to keystore,
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()

        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-att",
                messageId = "msg-att-2",
                action = "request_attestation",
                params = SignRequestParams(audience = "https://as.example.com", issuer = "https://client.example.com"),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            engine.sendSignResponse(
                flowId = "flow-att",
                messageId = "msg-att-2",
                clientAttestation = null,
                clientAttestationPoP = null,
            )
        }
        coVerify(exactly = 0) { keystore.generateKeyProof(any(), any(), any(), any(), any()) }
        // Declining is not a flow failure - the backend carries on without us.
        assertTrue(wallet.state.value is WalletState.Ready)
    }

    /**
     * An engine sign action this SDK version doesn't know must never be
     * answered with silence: go-wallet-backend's RequestSign unblocks only on
     * a sign_response for its message_id, so an empty one goes back.
     */
    @Test
    fun unknownSignAction_sendsEmptyResponse_ratherThanSilence() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()

        signFlow.emit(
            SignRequestMessage(flowId = "flow-x", messageId = "msg-x", action = "sign_something_new", params = SignRequestParams())
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            engine.sendSignResponse(
                flowId = "flow-x",
                messageId = "msg-x",
                clientAttestation = null,
                clientAttestationPoP = null,
            )
        }
    }

    private fun issuerMetadataJson(server: MockWebServer, configId: String): String {
        val issuerUrl = server.url("/").toString().trimEnd('/')
        return """
            {
              "credential_issuer": "$issuerUrl",
              "credential_configurations_supported": {
                "$configId": {
                  "format": "mso_mdoc",
                  "doctype": "$configId",
                  "credential_metadata": {
                    "display": [
                      {"name": "Mobile Driving License", "locale": "en-US", "logo": {"uri": "https://issuer.example.com/logo.png"}}
                    ]
                  }
                }
              }
            }
        """.trimIndent()
    }

    @Test
    fun connectEngine_flowComplete_stores_credentials_notifies_listener_and_returns_ready() = runTest(dispatcher) {
        // Minimal valid JWT: {"alg":"none"}.{"sub":"test","iat":1700000000,"exp":9999999999}.
        val testCredential = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        mockEngineConstructor(flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-complete",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-complete",
                credentials = listOf(
                    CredentialResult(format = "dc+sd-jwt", credential = testCredential)
                ),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) { listener.onFlowComplete("flow-complete") }
        verify(exactly = 1) {
            listener.onCredentialReceived(match { it.format == "dc+sd-jwt" && it.raw == testCredential })
        }
        coVerify(exactly = 1) { keystore.exportEncryptedContainer() }
        coVerify(exactly = 1) { apiClient.updatePrivateData(any()) }
        val ready = wallet.state.value as WalletState.Ready
        assertEquals("user-1", ready.userId)
        assertEquals(1, ready.credentials.size)
        assertEquals(testCredential, ready.credentials.single().raw)
    }

    /**
     * A BBS credential's holder state has to reach the container before the
     * credential reaches the store — the state is what names the credential's
     * id. So a [CredentialStore] that refuses the credential (it is
     * host-supplied, and may) would otherwise leave that entry behind: a
     * long-lived secret filed under an id nothing will ever look up, and one
     * nothing else deletes either, since §6.1.2's rule is "deleting the
     * entity deletes the entry" and here the entity never existed.
     */
    @Test
    fun connectEngine_flowComplete_rollsBackHolderState_whenStoringTheBbsCredentialFails() = runTest(dispatcher) {
        val issuedJwp = "the.jwp.here"
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf(), saveFailure = RuntimeException("store refused"))
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } returns null
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"j"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}

        val extensionStore = RecordingExtensionStore()
        val holderState = org.siros.sdk.credentials.BbsHolderState(
            issuerPublicKey = ByteArray(96) { 1 },
            secretProverBlind = ByteArray(32) { 2 },
            committedMessages = listOf(byteArrayOf(3)),
            keybindPublicKeys = emptyList(),
        )
        val preparation = mockk<org.siros.sdk.credentials.BbsIssuancePreparation>().also {
            every { it.accept(issuedJwp, any()) } returns holderState
        }
        val preparations =
            java.util.concurrent.ConcurrentHashMap<String, org.siros.sdk.credentials.ZkIssuancePreparation>()
        preparations["flow-complete"] = preparation

        mockEngineConstructor(flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-complete",
                    flowType = "issuance",
                    status = "in_progress",
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
            "zkPreparationsByFlow" to preparations,
            "bbsHolderStateVault" to org.siros.sdk.keystore.BbsHolderStateVault(extensionStore),
            "activeZkIssuanceInput" to ZkIssuanceInput("{}", issuerPublicKey = ByteArray(96)),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-complete",
                credentials = listOf(CredentialResult(format = "jwp", credential = issuedJwp)),
            )
        )
        advanceUntilIdle()

        assertTrue(
            "the holder state must have been written before the store was asked",
            extensionStore.everWritten,
        )
        assertEquals(
            "a credential that could not be stored must leave no holder state behind",
            emptyMap<String, String>(),
            extensionStore.entries[org.siros.sdk.keystore.BbsHolderStateVault.NAMESPACE].orEmpty(),
        )
        assertEquals("no credential may be reported as received", 0, store.getAll().size)
        verify(exactly = 0) { listener.onCredentialReceived(any()) }
        verify(exactly = 1) { listener.onFlowError("flow-complete", any(), any()) }
    }

    /** An in-memory [org.siros.sdk.keystore.ExtensionStore] that remembers whether anything was ever written. */
    private class RecordingExtensionStore : org.siros.sdk.keystore.ExtensionStore {
        val entries = mutableMapOf<String, MutableMap<String, String>>()
        var everWritten = false
            private set

        override suspend fun extensionEntries(namespace: String): Map<String, String> =
            entries[namespace]?.toMap() ?: emptyMap()

        override suspend fun setExtensionEntry(namespace: String, key: String, value: String) {
            everWritten = true
            entries.getOrPut(namespace) { mutableMapOf() }[key] = value
        }

        override suspend fun removeExtensionEntry(namespace: String, key: String) {
            entries[namespace]?.remove(key)
        }
    }

    @Test
    fun connectEngine_flowComplete_assignsSharedBatchIdAndSequentialInstanceIds_forMultiCredentialBatch() = runTest(dispatcher) {
        // Minimal valid JWTs: {"alg":"none"}.{"sub":"test","iat":1700000000,"exp":9999999999}.
        val cred = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        mockEngineConstructor(flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-batch",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-batch",
                credentials = listOf(
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                ),
            )
        )
        advanceUntilIdle()

        val stored = store.getAll()
        assertEquals(3, stored.size)
        val batchId = stored.first().batchId
        assertNotNull(batchId)
        assertTrue(stored.all { it.batchId == batchId })
        assertEquals(listOf(0, 1, 2), stored.map { it.instanceId })
    }

    @Test
    fun connectEngine_flowComplete_assignsPerInstanceKid_fromAttestedKeyIds_forBatchIssuance() = runTest(dispatcher) {
        // Regression test for the wrong-key-signing bug: a batch issuance
        // where each instance is bound to its own device key (e.g. an
        // OID4VCI issuer minting credential N from attested_keys[N], see
        // SirosWallet.activeAttestedKeyIds's doc comment) must record which
        // key each STORED credential actually uses - not just its position
        // in the batch. Directly injects activeAttestedKeyIds (the
        // generate_proof -> attestedKeyIds wiring itself is covered by
        // connectEngine_signRequest_usesBackendKeyAttestation_whenAvailable)
        // to isolate testing that flowComplete correctly consumes it.
        val cred = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        mockEngineConstructor(flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-batch-keys",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "activeAttestedKeyIds" to listOf("key-a", "key-b", "key-c"),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-batch-keys",
                credentials = listOf(
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                    CredentialResult(format = "dc+sd-jwt", credential = cred),
                ),
            )
        )
        advanceUntilIdle()

        val stored = store.getAll().sortedBy { it.instanceId }
        assertEquals(3, stored.size)
        assertEquals(listOf("key-a", "key-b", "key-c"), stored.map { it.kid })
    }

    @Test
    fun connectEngine_flowComplete_assignsBatchIdAndZeroInstanceId_forSingleCredentialIssuance() = runTest(dispatcher) {
        // Minimal valid JWT: {"alg":"none"}.{"sub":"test","iat":1700000000,"exp":9999999999}.
        val cred = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        mockEngineConstructor(flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-single",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-single",
                credentials = listOf(CredentialResult(format = "dc+sd-jwt", credential = cred)),
            )
        )
        advanceUntilIdle()

        val stored = store.getAll()
        assertEquals(1, stored.size)
        // Every issuance response - batch of one or many - gets its own
        // batchId (matching wallet-frontend's Date.now()-per-issuance model,
        // see StoredCredential.batchId's KDoc); a single credential is
        // simply a batch of one, always instanceId 0.
        assertNotNull(stored.single().batchId)
        assertEquals(0, stored.single().instanceId)
    }

    @Test
    fun connectEngine_flowComplete_sends_credential_notification_when_notification_id_present() = runTest(dispatcher) {
        // Minimal valid JWT: {"alg":"none"}.{"sub":"test","iat":1700000000,"exp":9999999999}.
        val testCredential = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        val engine = mockEngineConstructor(flowComplete = completeFlow)
        every {
            engine.sendCredentialNotification(any(), any(), any(), any())
        } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-notify",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-notify",
                credentials = listOf(
                    CredentialResult(
                        format = "dc+sd-jwt",
                        credential = testCredential,
                        notificationId = "notif-xyz",
                    )
                ),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            engine.sendCredentialNotification(
                flowId = "flow-notify",
                notificationId = "notif-xyz",
                event = CredentialNotificationEvent.ACCEPTED,
            )
        }
        // The stored credential retains the issuer's notification_id.
        assertEquals("notif-xyz", store.let { runBlocking { it.getAll() }.single().notificationId })
    }

    @Test
    fun connectEngine_flowComplete_omits_credential_notification_without_notification_id() = runTest(dispatcher) {
        val testCredential = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        val engine = mockEngineConstructor(flowComplete = completeFlow)
        every {
            engine.sendCredentialNotification(any(), any(), any(), any())
        } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-plain",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-plain",
                credentials = listOf(
                    CredentialResult(format = "dc+sd-jwt", credential = testCredential)
                ),
            )
        )
        advanceUntilIdle()

        verify(exactly = 0) {
            engine.sendCredentialNotification(any(), any(), any(), any())
        }
    }

    /**
     * Regression test for a real bug reported via live device testing:
     * long-press "Renew" on a credential whose batch had no stored
     * refresh_token fell back to [SirosWallet.startIssuanceByOffer] with no
     * lineage tracking at all, so the old batch was never deleted - the user
     * ended up with two credentials of the same type instead of one renewed
     * one. [SirosWallet.startIssuanceByOffer]'s new `replacesBatchId`
     * parameter wires the same `pendingRenewalSourceBatchId` batch-
     * replacement logic [SirosWallet.renewCredential]'s silent path already
     * used into this fallback path too.
     */
    @Test
    fun startIssuanceByOffer_withReplacesBatchId_deletesOldBatch_onFlowComplete() = runTest(dispatcher) {
        val oldCred = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJvbGQiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0."
        val newCred = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJuZXciLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0."
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(
                    id = 111L,
                    format = "dc+sd-jwt",
                    raw = oldCred,
                    credentialIssuerIdentifier = "https://issuer.example.com",
                    credentialConfigurationId = "pid",
                    batchId = 555L,
                    instanceId = 0,
                ),
            ),
        )
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        var privateDataJwe: String? = null
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } answers { privateDataJwe }
        every { sessionStore.privateDataJwe = any() } answers { privateDataJwe = firstArg() }
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"updated-jwe"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        val engine = mockEngineConstructor(flowComplete = completeFlow)
        every { engine.startIssuance(any(), any(), any(), any(), any()) } just runs
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()

        wallet.startIssuanceByOffer(
            org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid",
                credentialIssuerIdentifier = "https://issuer.example.com",
                credentialName = "Personal ID",
                issuerName = "Issuer",
            ),
            replacesBatchId = 555L,
        )
        advanceUntilIdle()

        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-renew-fallback",
                credentials = listOf(CredentialResult(format = "dc+sd-jwt", credential = newCred)),
            )
        )
        advanceUntilIdle()

        val stored = store.getAll()
        assertEquals(1, stored.size)
        assertEquals(newCred, stored.single().raw)
        assertTrue(stored.none { it.batchId == 555L })
    }

    @Test
    fun connectEngine_flowError_notifies_listener_and_returns_ready() = runTest(dispatcher) {
        val errorFlow = MutableSharedFlow<FlowErrorMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        mockEngineConstructor(flowErrors = errorFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-error",
                    flowType = "presentation",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "eventListener" to listener,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        errorFlow.emit(
            FlowErrorMessage(
                flowId = "flow-error",
                error = FlowError(code = "bad_request", message = "presentation denied"),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) { listener.onFlowError("flow-error", "presentation denied") }
        assertEquals(
            WalletState.Ready(userId = "user-1", displayName = "Alice", credentials = emptyList()),
            wallet.state.value,
        )
    }

    @Test
    fun connectEngine_signRequest_generates_proof_and_sends_response() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "nonce-1") } returns "proof-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(audience = "aud-1", nonce = "nonce-1"),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { keystore.generateProof(audience = "aud-1", nonce = "nonce-1") }
        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "jwt", jwt = "proof-jwt")),
                messageId = null,
            )
        }
    }

    /** A `jwt`-proof-type proof-of-possession JWT with the given `kid` embedded in its `jwk` header, matching what [KeystoreManager.generateProof] actually produces. */
    private fun fakeProofJwt(kid: String): String {
        val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        val header = """{"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","kid":"$kid","x":"eA","y":"eQ"}}"""
        val payload = """{"aud":"aud-1","nonce":"nonce-1"}"""
        return "${encoder.encodeToString(header.toByteArray())}.${encoder.encodeToString(payload.toByteArray())}.sig"
    }

    /**
     * Real bug found via live proximity-presentation testing: [KeystoreManager.generateProof]
     * never returned which key it used, so [SirosWallet.activeAttestedKeyIds] stayed null for
     * every credential issued via the `jwt` proof type (the preferred, common path) - leaving
     * `StoredCredential.kid` null and making device-signature verification depend on
     * `signer.listKeys()`'s incidental ordering instead of the credential's actual bound key.
     * The fix recovers the `kid` from the proof JWT's own embedded `jwk` header.
     */
    @Test
    fun connectEngine_signRequest_singleProof_recordsAttestedKeyIdFromJwtHeader() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "nonce-1") } returns fakeProofJwt("sw-0")
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(audience = "aud-1", nonce = "nonce-1"),
            )
        )
        advanceUntilIdle()

        assertEquals(listOf("sw-0"), getField(wallet, "activeAttestedKeyIds"))
    }

    /**
     * A batch of more than one `jwt`-proof-type proof each carries its OWN single-element
     * key-id list (from its own JWT header) - the aggregation must concatenate them in
     * submission order, not just keep the first one's list (which would silently leave
     * every batch index past 0 unbound to any key, same failure mode as the bug above).
     */
    @Test
    fun connectEngine_signRequest_batchProofs_recordsAllAttestedKeyIdsInOrder() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery {
            keystore.generateProof(audience = "aud-1", nonce = "nonce-1", freshKey = true)
        } returnsMany listOf(fakeProofJwt("sw-0"), fakeProofJwt("sw-1"), fakeProofJwt("sw-2"))
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(audience = "aud-1", nonce = "nonce-1", count = 3),
            )
        )
        advanceUntilIdle()

        assertEquals(listOf("sw-0", "sw-1", "sw-2"), getField(wallet, "activeAttestedKeyIds"))
    }

    @Test
    fun connectEngine_signRequest_generates_attestation_proof_when_jwt_not_supported() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateKeyAttestation(nonce = "nonce-1", count = 5) } returns "attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 5,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        // A real external mdoc issuer (this test's motivating case) lists
        // only "attestation" in proof_types_supported - the wallet MUST NOT
        // fall back to jwt (go-wallet-backend rejects with "unsupported
        // proof type" if it does), and must produce exactly ONE proof
        // covering the whole batch, not one per credential.
        coVerify(exactly = 1) { keystore.generateKeyAttestation(nonce = "nonce-1", count = 5) }
        coVerify(exactly = 0) { keystore.generateProof(any(), any(), any()) }
        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "attestation", attestation = "attestation-jwt")),
                messageId = null,
            )
        }
    }

    @Test
    fun connectEngine_signRequest_usesBackendKeyAttestation_whenAvailable() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val keypairs = listOf(
            KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }),
            KeypairInfo(keyId = "key-2", publicKeyJWK = buildJsonObject { put("kty", "EC") }),
        )
        coEvery { keystore.generateKeypairs(2) } returns keypairs
        val securityProps = SignerSecurityProperties(keyStorage = listOf("iso_18045_high"))
        coEvery { keystore.securityProperties("key-1") } returns securityProps
        val apiClient = mockk<BackendApiClient>()
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = securityProps,
                credentialIssuer = "aud-1",
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        // connectEngine builds its own real BackendApiClient - swap in the
        // mock afterward so the backend Key Attestation call is exercised
        // without an actual network round trip.
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 2,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        // Backend-signed attestation (real x5c trust anchor) must be
        // preferred over the self-signed fallback when a session is active
        // and the backend supports the endpoint.
        coVerify(exactly = 0) { keystore.generateKeyAttestation(any(), any()) }
        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "attestation", attestation = "backend-signed-attestation-jwt")),
                messageId = null,
            )
        }
    }

    @Test
    fun currentWalletInstanceId_returnsJkt_whenWiaIsNativeAttested() = runTest(dispatcher) {
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
        )
        setField(
            wallet,
            "cachedWia",
            fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "ios_app_attest"),
        )
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)

        assertEquals("test-jkt", invokeCurrentWalletInstanceId(wallet))
    }

    @Test
    fun currentWalletInstanceId_returnsNull_whenWiaIsNotNativeAttested() = runTest(dispatcher) {
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
        )
        // WIA exists but was never verified as native platform attestation -
        // the backend's KA trust gate wouldn't lift the clamp for it anyway,
        // so walletInstanceId must stay omitted.
        setField(
            wallet,
            "cachedWia",
            fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "backend_attested"),
        )
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)

        assertEquals(null, invokeCurrentWalletInstanceId(wallet))
    }

    @Test
    fun currentWalletInstanceId_returnsNull_whenNoWiaAvailable() = runTest(dispatcher) {
        // No cachedWia seeded - currentWalletInstanceId() peeks the cache
        // only (it must never trigger a WIA fetch of its own), so this must
        // resolve to null without any backend interaction at all.
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
        )

        assertEquals(null, invokeCurrentWalletInstanceId(wallet))
    }

    @Test
    fun requestBackendKeyAttestation_includesWalletInstanceId_whenWiaIsNativeAttested() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val keypairs = listOf(KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { keystore.generateKeypairs(1) } returns keypairs
        val securityProps = SignerSecurityProperties(keyStorage = listOf("iso_18045_high"))
        coEvery { keystore.securityProperties("key-1") } returns securityProps
        val apiClient = mockk<BackendApiClient>()
        coEvery {
            apiClient.requestKeyAttestation(
                jwks = keypairs.map { it.publicKeyJWK },
                nonce = "nonce-1",
                securityProperties = securityProps,
                credentialIssuer = "aud-1",
                walletInstanceId = "test-jkt",
            )
        } returns "backend-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        setField(wallet, "cachedWia", fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "ios_app_attest"))
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 1,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "attestation", attestation = "backend-signed-attestation-jwt")),
                messageId = null,
            )
        }
    }

    @Test
    fun connectEngine_signRequest_fallsBackToSelfSignedAttestation_whenBackendCallFails() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateKeypairs(any()) } throws IllegalStateException("backend session expired")
        coEvery { keystore.generateKeyAttestation(nonce = "nonce-1", count = 3) } returns "self-signed-attestation-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    count = 3,
                    proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} },
                ),
            )
        )
        advanceUntilIdle()

        // A failed backend attempt (offline wallet-provider, older backend,
        // network error) must not surface as a hard failure - it degrades to
        // the self-signed path, same as every other backend-optional flow.
        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "attestation", attestation = "self-signed-attestation-jwt")),
                messageId = null,
            )
        }
    }

    @Test
    fun connectEngine_signRequest_prefers_jwt_when_both_proof_types_supported() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "nonce-1") } returns "proof-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1",
                    nonce = "nonce-1",
                    proofTypesSupported = buildJsonObject {
                        putJsonObject("jwt") {}
                        putJsonObject("attestation") {}
                    },
                ),
            )
        )
        advanceUntilIdle()

        // Existing issuers (ours included) that already support jwt must see
        // no behavior change from adding attestation support.
        coVerify(exactly = 1) { keystore.generateProof(audience = "aud-1", nonce = "nonce-1") }
        coVerify(exactly = 0) { keystore.generateKeyAttestation(any(), any()) }
    }

    @Test
    fun connectEngine_matchRequest_uses_listener_selection_tracks_history_and_sends_matches() = runTest(dispatcher) {
        val matchFlow = MutableSharedFlow<MatchRequestMessage>()
        val listener = mockk<WalletEventListener>()
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(
                    id = 1L,
                    format = "dc+sd-jwt",
                    raw = "raw-1",
                    metadata = CredentialMetadata(name = "Credential One", vct = "urn:example:vct"),
                    batchId = 1L,
                    instanceId = 0,
                ),
                StoredCredential(
                    id = 2L,
                    format = "dc+sd-jwt",
                    raw = "raw-2",
                    metadata = CredentialMetadata(name = "Credential Two", vct = "urn:example:vct"),
                    batchId = 2L,
                    instanceId = 0,
                ),
            )
        )
        val initialCredentials = store.getAll()
        coEvery { listener.onCredentialSelectionRequired(any()) } returns listOf(2L)
        val engine = mockEngineConstructor(matchRequests = matchFlow)
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice", credentials = initialCredentials)
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "eventListener" to listener,
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        matchFlow.emit(MatchRequestMessage(flowId = "flow-match", dcqlQuery = null))
        advanceUntilIdle()

        coVerify(exactly = 1) {
            listener.onCredentialSelectionRequired(
                match<PresentationRequest> { request ->
                    request.candidates.map { it.id } == listOf(1L, 2L)
                },
            )
        }
        verify(exactly = 1) {
            engine.sendMatchResponse(
                "flow-match",
                match<List<CredentialMatch>> { matches ->
                    matches.size == 1 &&
                        matches.single().credentialQueryId == "_default" &&
                        matches.single().credentialId == "2" &&
                        matches.single().format == "dc+sd-jwt" &&
                        matches.single().vct == "urn:example:vct"
                },
            )
        }
        assertEquals(1, wallet.presentationHistory.size)
        assertEquals(listOf(2L), wallet.presentationHistory.single().credentialIds)
        assertEquals(listOf("Credential Two"), wallet.presentationHistory.single().credentialNames)
    }

    /**
     * Regression: an engine-relayed `mso_mdoc_zk` query must offer the plain
     * mdoc it can be proven from. An earlier version dropped ZK queries'
     * candidates at match time, from before this transport's
     * sign_presentation handler could produce a ZK proof - which, once it
     * could, turned every such request into "no matching credential".
     */
    @Test
    fun connectEngine_matchRequest_offers_mdoc_for_zk_query_and_flags_history() = runTest(dispatcher) {
        val matchFlow = MutableSharedFlow<MatchRequestMessage>()
        val listener = mockk<WalletEventListener>()
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(
                    id = 1L,
                    format = "mso_mdoc",
                    raw = "raw-mdl",
                    metadata = CredentialMetadata(name = "Driving Licence", doctype = "org.iso.18013.5.1.mDL"),
                    batchId = 1L,
                    instanceId = 0,
                ),
            )
        )
        coEvery { listener.onCredentialSelectionRequired(any()) } returns listOf(1L)
        val engine = mockEngineConstructor(matchRequests = matchFlow)
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice", credentials = store.getAll())
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "eventListener" to listener,
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        )
        val zkQuery = buildJsonObject {
            put("credentials", JsonArray(listOf(buildJsonObject {
                put("id", "q-zk")
                put("format", "mso_mdoc_zk")
                put("meta", buildJsonObject { put("doctype_value", "org.iso.18013.5.1.mDL") })
            })))
        }

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        matchFlow.emit(MatchRequestMessage(flowId = "flow-zk", dcqlQuery = zkQuery))
        advanceUntilIdle()

        coVerify(exactly = 1) {
            listener.onCredentialSelectionRequired(
                match<PresentationRequest> { request ->
                    request.candidates.map { it.id } == listOf(1L) &&
                        request.matchResults.single().format == "mso_mdoc_zk"
                },
            )
        }
        verify(exactly = 1) {
            engine.sendMatchResponse(
                "flow-zk",
                match<List<CredentialMatch>> { matches ->
                    matches.size == 1 && matches.single().credentialQueryId == "q-zk"
                },
            )
        }
        assertTrue(wallet.presentationHistory.single().zkProof)
    }

    /**
     * Regression (#218): handleWmpTrustEvaluation caches the trust result
     * under lastTrustResults[flowId] before the match_request for that same
     * flow ever arrives, but the match_request handler never read it back -
     * the consent screen got neither a verifier name NOR (once #218's
     * sample-app fallback ships) the verified identity a missing name could
     * fall back to. It must reach PresentationRequest.trustResult, and
     * verifierName must be derived from it the same way the legacy
     * (non-WMP) credential_selection path already does.
     */
    @Test
    fun connectEngine_matchRequest_forwards_cached_trust_result_to_listener() = runTest(dispatcher) {
        val matchFlow = MutableSharedFlow<MatchRequestMessage>()
        val listener = mockk<WalletEventListener>()
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(
                    id = 1L,
                    format = "dc+sd-jwt",
                    raw = "raw-1",
                    metadata = CredentialMetadata(name = "Credential One", vct = "urn:example:vct"),
                    batchId = 1L,
                    instanceId = 0,
                ),
            )
        )
        coEvery { listener.onCredentialSelectionRequired(any()) } returns listOf(1L)
        val engine = mockEngineConstructor(matchRequests = matchFlow)
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        val cachedTrustResult = TrustResult(
            trusted = true,
            entityName = null,
            clientIdScheme = "did",
            identifier = "did:web:verifier.example.com",
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice", credentials = store.getAll())
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "eventListener" to listener,
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
            "lastTrustResults" to mutableMapOf("flow-match" to cachedTrustResult),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        matchFlow.emit(MatchRequestMessage(flowId = "flow-match", dcqlQuery = null))
        advanceUntilIdle()

        coVerify(exactly = 1) {
            listener.onCredentialSelectionRequired(
                match<PresentationRequest> { request ->
                    request.trustResult === cachedTrustResult &&
                        request.verifierName == null &&
                        request.trustResult?.identifier == "did:web:verifier.example.com"
                },
            )
        }
    }

    /**
     * A wallet with nothing the verifier asked for must say so, not sit
     * silent (the engine then reports a generic FLOW_TIMEOUT five minutes
     * later) and not decline (which tells the verifier the user refused a
     * request they were never shown). go-wallet-backend#335/#336.
     */
    @Test
    fun credentialSelection_with_nothing_matching_reports_credentials_matched_not_a_decline() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(
                    id = 1L,
                    format = "mso_mdoc",
                    raw = "raw-mdl",
                    metadata = CredentialMetadata(name = "Driving Licence", doctype = "org.iso.18013.5.1.mDL"),
                    batchId = 1L,
                    instanceId = 0,
                ),
            )
        )
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice", credentials = store.getAll())
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "eventListener" to listener,
            "lastTrustResults" to mutableMapOf<String, Any?>(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-nomatch",
                step = "credential_selection",
                payload = buildJsonObject {
                    putJsonObject("dcql_query") {
                        putJsonArray("credentials") {
                            add(buildJsonObject {
                                put("id", "q-pid")
                                put("format", "dc+sd-jwt")
                                putJsonObject("meta") {
                                    putJsonArray("vct_values") { add(JsonPrimitive("urn:eu.europa.ec.eudi:pid:1")) }
                                }
                            })
                        }
                    }
                },
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            engine.sendCredentialsMatched(
                "flow-nomatch",
                emptyList(),
                match<String> { it.contains("urn:eu.europa.ec.eudi:pid:1") },
            )
        }
        verify(exactly = 0) { engine.sendFlowAction("flow-nomatch", "decline", any()) }
        // The user is never asked to consent to a request nothing can answer.
        coVerify(exactly = 0) { listener.onCredentialSelectionRequired(any()) }
    }

    @Test
    fun matchRequest_with_nothing_matching_reports_credentials_matched_with_a_reason() = runTest(dispatcher) {
        val matchFlow = MutableSharedFlow<MatchRequestMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(
                    id = 1L,
                    format = "dc+sd-jwt",
                    raw = "raw-1",
                    metadata = CredentialMetadata(name = "Loyalty Card", vct = "urn:example:loyalty"),
                    batchId = 1L,
                    instanceId = 0,
                ),
            )
        )
        val engine = mockEngineConstructor(matchRequests = matchFlow)
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice", credentials = store.getAll())
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "eventListener" to listener,
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )
        val pidQuery = buildJsonObject {
            put("credentials", JsonArray(listOf(buildJsonObject {
                put("id", "q-pid")
                put("format", "dc+sd-jwt")
                put("meta", buildJsonObject {
                    put("vct_values", JsonArray(listOf(JsonPrimitive("urn:eu.europa.ec.eudi:pid:1"))))
                })
            })))
        }

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        matchFlow.emit(MatchRequestMessage(flowId = "flow-nm", dcqlQuery = pidQuery))
        advanceUntilIdle()

        verify(exactly = 1) {
            engine.sendMatchResponse(
                "flow-nm",
                emptyList(),
                match<String> { it.contains("urn:eu.europa.ec.eudi:pid:1") },
            )
        }
        verify(exactly = 1) {
            engine.sendCredentialsMatched("flow-nm", emptyList(), any())
        }
        coVerify(exactly = 0) { listener.onCredentialSelectionRequired(any()) }
    }

    /**
     * The WMP transport's match handler used to answer every request with
     * every stored credential, ignoring the DCQL query entirely.
     */
    @Test
    fun wmpMatchRequest_answers_only_with_credentials_the_query_asked_for() = runBlocking {
        val store = FakeCredentialStore(
            mutableListOf(
                StoredCredential(
                    id = 1L,
                    format = "dc+sd-jwt",
                    raw = "raw-pid",
                    metadata = CredentialMetadata(name = "PID", vct = "urn:eu.europa.ec.eudi:pid:1"),
                    batchId = 1L,
                    instanceId = 0,
                ),
                StoredCredential(
                    id = 2L,
                    format = "dc+sd-jwt",
                    raw = "raw-loyalty",
                    metadata = CredentialMetadata(name = "Loyalty Card", vct = "urn:example:loyalty"),
                    batchId = 2L,
                    instanceId = 0,
                ),
            )
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
        )

        val pidResult = invokeWmpMatchRequest(wallet, "flow-wmp", vctQueryPayload("urn:eu.europa.ec.eudi:pid:1"))
        assertEquals(listOf("1"), pidResult.matches.map { it.credentialId })
        assertEquals(listOf("q-vct"), pidResult.matches.map { it.credentialQueryId })
        assertNull(pidResult.noMatchReason)

        val missingResult = invokeWmpMatchRequest(wallet, "flow-wmp", vctQueryPayload("urn:example:absent"))
        assertTrue(missingResult.matches.isEmpty())
        assertTrue(
            "The reason must name what was asked for: ${missingResult.noMatchReason}",
            missingResult.noMatchReason!!.contains("urn:example:absent"),
        )
    }

    /**
     * An issuance that sent the wallet through a verifier (vc's
     * `auth_provider: openid4vp`) is parked on `authorization_required` when
     * that presentation fails - nothing will ever come back for it.
     */
    @Test
    fun noMatchingCredential_error_also_fails_the_issuance_that_was_waiting_on_it() = runTest(dispatcher) {
        val errorFlow = MutableSharedFlow<FlowErrorMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(flowErrors = errorFlow)
        val pendingAuthorizations = mutableMapOf<String, Any?>("flow-issuance" to "resume-context")
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.Ready(userId = "user-1", displayName = "Alice")
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "eventListener" to listener,
            "pendingAuthorizations" to pendingAuthorizations,
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        errorFlow.emit(
            FlowErrorMessage(
                flowId = "flow-vp",
                error = FlowError(
                    code = "NO_MATCHING_CREDENTIAL",
                    message = "This request needs a credential you do not have: urn:eu.europa.ec.eudi:pid:1",
                    details = buildJsonObject {
                        put("requested_types", JsonArray(listOf(JsonPrimitive("urn:eu.europa.ec.eudi:pid:1"))))
                        put("no_match_reason", "This wallet holds no credential matching the request")
                    },
                ),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            listener.onFlowError("flow-vp", "This request needs a credential you do not have: urn:eu.europa.ec.eudi:pid:1", null)
        }
        verify(exactly = 1) {
            listener.onFlowError("flow-issuance", "This request needs a credential you do not have: urn:eu.europa.ec.eudi:pid:1", null)
        }
        assertTrue("The parked resume context is dead once its presentation failed", pendingAuthorizations.isEmpty())
    }

    // ── DC API (Digital Credentials API) ─────────────────────────────

    @Test
    fun handleDCAPIRequest_unsignedRequest_signsSdJwtAndReturnsUnencryptedVpToken() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "issuer.payload.sig~disclosure~",
                metadata = CredentialMetadata(name = "Diploma", vct = "urn:example:vct"),
                batchId = 1L,
                instanceId = 0,
            ),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        val requestJson = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
            put("response_type", "vp_token")
            put("nonce", "dc-nonce-1")
            put("response_mode", "dc_api")
            putJsonObject("dcql_query") {
                putJsonArray("credentials") {
                    add(buildJsonObject {
                        put("id", "query1")
                        put("format", "dc+sd-jwt")
                    })
                }
            }
        })

        val result = wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

        coVerify(exactly = 1) {
            keystore.signVpToken(
                credential = "issuer.payload.sig~disclosure~",
                disclosedClaims = any(),
                nonce = "dc-nonce-1",
                audience = "origin:https://relying-party.example",
            )
        }
        assertEquals(listOf(1L), result.credentialIds)
        val parsed = Json.parseToJsonElement(result.responseJson).jsonObject
        assertEquals("openid4vp-v1-unsigned", parsed["protocol"]?.jsonPrimitive?.content)
        val data = parsed["data"]?.jsonObject
        // OpenID4VP 1.0 (#response_parameters): each vp_token entry MUST be a
        // JSON array of Presentations, even for a single match.
        assertEquals(
            "signed-vp-token",
            data?.get("vp_token")?.jsonObject?.get("query1")?.jsonArray?.single()?.jsonPrimitive?.content,
        )
        assertEquals(1, wallet.presentationHistory.size)
    }

    @Test
    fun handleDCAPIRequest_untrustedVerifier_throwsAndNeverSigns() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject {
            put("decision", false)
            putJsonObject("context") { put("reason", "not on the whitelist") }
        }
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "issuer.payload.sig~disclosure~",
                metadata = CredentialMetadata(name = "Diploma", vct = "urn:example:vct"),
                batchId = 1L,
                instanceId = 0,
            ),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        val requestJson = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
            put("nonce", "dc-nonce-untrusted")
            put("response_mode", "dc_api")
            putJsonObject("dcql_query") {
                putJsonArray("credentials") {
                    add(buildJsonObject { put("id", "query1"); put("format", "dc+sd-jwt") })
                }
            }
        })

        var thrown: Throwable? = null
        try {
            wallet.handleDCAPIRequest(requestJson, origin = "https://untrusted-relying-party.example")
        } catch (e: Throwable) {
            thrown = e
        }
        assertTrue(thrown is WalletException)
        coVerify(exactly = 0) { keystore.signVpToken(any(), any(), any(), any()) }
        assertEquals(0, wallet.presentationHistory.size)
    }

    @Test
    fun handleDCAPIRequest_unsignedRequest_ignoresBodyClientIdAndEvaluatesTrustAgainstOrigin() = runTest(dispatcher) {
        // The unsigned DC API protocol variant's client_id is just a field in
        // the untrusted request body - unlike the signed variant, it is not
        // bound to anything the platform verified. Trust must be evaluated
        // against the platform-attested origin, not a spoofable body field.
        val apiClient = mockk<BackendApiClient>()
        val subjectIds = mutableListOf<String>()
        coEvery { apiClient.evaluateTrust(any()) } answers {
            val req = firstArg<JsonObject>()
            subjectIds.add(req["subject"]!!.jsonObject["id"]!!.jsonPrimitive.content)
            buildJsonObject { put("decision", true) }
        }
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(
                id = 1L,
                format = "dc+sd-jwt",
                raw = "issuer.payload.sig~disclosure~",
                metadata = CredentialMetadata(name = "Diploma", vct = "urn:example:vct"),
                batchId = 1L,
                instanceId = 0,
            ),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        val requestJson = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
            put("nonce", "dc-nonce-spoof")
            put("response_mode", "dc_api")
            // Attacker-controlled: this is an ordinary field in the unsigned
            // request body, not attested by anything.
            put("client_id", "some-other-trusted-verifier.example")
            putJsonObject("dcql_query") {
                putJsonArray("credentials") {
                    add(buildJsonObject { put("id", "query1"); put("format", "dc+sd-jwt") })
                }
            }
        })

        wallet.handleDCAPIRequest(requestJson, origin = "https://real-caller-origin.example")

        assertEquals(listOf("https://real-caller-origin.example"), subjectIds)
    }

    @Test
    fun handleDCAPIRequest_mdocCredential_usesSignMdocPresentationForDCAPI() = runTest(dispatcher) {
        // Production code decodes cred.raw via android.util.Base64 before
        // calling the keystore - the Android SDK stub jar throws on any real
        // call in a plain (non-Robolectric) JUnit test, so it must be
        // statically mocked here even though the decoded bytes themselves
        // are irrelevant (the keystore call itself is mocked below).
        io.mockk.mockkStatic(android.util.Base64::class)
        every { android.util.Base64.decode(any<String>(), any()) } returns "fake-cbor".toByteArray()
        every { android.util.Base64.encodeToString(any(), any()) } returns "ZGV2aWNlLXJlc3BvbnNl"
        try {
            val apiClient = mockk<BackendApiClient>()
            coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
            val keystore = mockk<KeystoreManager>()
            every { keystore.isUnlocked } returns false
            every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
            coEvery {
                keystore.signMdocPresentationForDCAPI(any(), any(), any(), any(), any())
            } returns "device-response".toByteArray()
            val store = FakeCredentialStore(mutableListOf(
                StoredCredential(
                    id = 1L,
                    format = "mso_mdoc",
                    raw = "ZmFrZS1jYm9y",
                    metadata = CredentialMetadata(name = "mDL", doctype = "org.iso.18013.5.1.mDL"),
                    batchId = 1L,
                    instanceId = 0,
                ),
            ))
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "apiClient" to apiClient,
                "keystore" to keystore,
                "credentialStore" to store,
                "trustCache" to TrustCache(),
                "_presentationHistory" to mutableListOf<PresentationRecord>(),
            )

            val requestJson = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
                put("nonce", "dc-nonce-mdl")
                put("response_mode", "dc_api")
            })

            wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

            coVerify(exactly = 1) {
                keystore.signMdocPresentationForDCAPI(
                    credentialBytes = any(),
                    disclosedClaims = any(),
                    nonce = "dc-nonce-mdl",
                    origin = "https://relying-party.example",
                    encryptionPublicJwkThumbprint = null,
                )
            }
        } finally {
            io.mockk.unmockkStatic(android.util.Base64::class)
        }
    }

    @Test
    fun handleDCAPIRequest_credentialMatchesBothZkAndPlainQuery_usesFirstMatchForZkFlag() = runTest(dispatcher) {
        // Regression test (found in review): a single stored mso_mdoc
        // credential can legitimately appear as a candidate under BOTH a
        // plain "mso_mdoc" query and an "mso_mdoc_zk" query in the same
        // request (CredentialMatcher.matchesFormat's own zk-matches-plain
        // rule). Which one actually governs the presentation - and thus
        // whether a ZK proof or a raw disclosure happens - is decided by
        // first-match over queryResults, same order as the request's own
        // "credentials" array. Here the plain query comes first, so this
        // MUST be a raw disclosure: PresentationRecord.zkProof must be
        // false and the raw-mdoc signing path must be used, never the ZK
        // one. A previous bug computed the zk-eligible id set as "is this
        // id a candidate under ANY zk query" independently of first-match,
        // so it wrongly reported this same case as a ZK presentation.
        io.mockk.mockkStatic(android.util.Base64::class)
        every { android.util.Base64.decode(any<String>(), any()) } returns "fake-cbor".toByteArray()
        every { android.util.Base64.encodeToString(any(), any()) } returns "ZGV2aWNlLXJlc3BvbnNl"
        try {
            val apiClient = mockk<BackendApiClient>()
            coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
            val keystore = mockk<KeystoreManager>()
            every { keystore.isUnlocked } returns false
            every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
            coEvery {
                keystore.signMdocPresentationForDCAPI(any(), any(), any(), any(), any())
            } returns "device-response".toByteArray()
            val store = FakeCredentialStore(mutableListOf(
                StoredCredential(
                    id = 1L,
                    format = "mso_mdoc",
                    raw = "ZmFrZS1jYm9y",
                    metadata = CredentialMetadata(name = "mDL", doctype = "org.iso.18013.5.1.mDL"),
                    batchId = 1L,
                    instanceId = 0,
                ),
            ))
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "apiClient" to apiClient,
                "keystore" to keystore,
                "credentialStore" to store,
                "trustCache" to TrustCache(),
                "_presentationHistory" to mutableListOf<PresentationRecord>(),
            )

            val requestJson = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
                put("nonce", "dc-nonce-mixed")
                put("response_mode", "dc_api")
                putJsonObject("dcql_query") {
                    putJsonArray("credentials") {
                        add(buildJsonObject {
                            put("id", "mdl_plain")
                            put("format", "mso_mdoc")
                            putJsonObject("meta") { put("doctype_value", "org.iso.18013.5.1.mDL") }
                        })
                        add(buildJsonObject {
                            put("id", "mdl_zk")
                            put("format", "mso_mdoc_zk")
                            putJsonObject("meta") { put("doctype_value", "org.iso.18013.5.1.mDL") }
                        })
                    }
                }
            })

            wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

            coVerify(exactly = 1) {
                keystore.signMdocPresentationForDCAPI(
                    credentialBytes = any(),
                    disclosedClaims = any(),
                    nonce = "dc-nonce-mixed",
                    origin = "https://relying-party.example",
                    encryptionPublicJwkThumbprint = null,
                )
            }
            assertEquals(1, wallet.presentationHistory.size)
            assertEquals(false, wallet.presentationHistory.single().zkProof)
        } finally {
            io.mockk.unmockkStatic(android.util.Base64::class)
        }
    }

    @Test
    fun handleDCAPIRequest_noMatchingCredential_throwsWalletException() = runTest(dispatcher) {
        // Selection/consent for DC API happens natively via the OS's own
        // credential picker before this Activity/call is ever reached - so
        // there's no in-app "decline" path to test here (see
        // handleDCAPIRequest's doc comment on why it no longer routes
        // through eventListener.onCredentialSelectionRequired). The
        // analogous failure is simply no matching credential in the wallet.
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val store = FakeCredentialStore(mutableListOf())
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to store,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        var thrown: Throwable? = null
        try {
            wallet.handleDCAPIRequest(
                wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject { put("nonce", "n") }),
                origin = "https://relying-party.example",
            )
        } catch (e: Throwable) {
            thrown = e
        }
        assertTrue(thrown is WalletException)
    }

    @Test
    fun handleDCAPIRequest_dcApiJwtResponseMode_encryptsResponse() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw", metadata = CredentialMetadata(name = "X"), batchId = 1L, instanceId = 0),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        val verifierEncKey = ECKeyGenerator(Curve.P_256)
            .keyID("enc-1")
            .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
            .generate()
        val requestJson = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
            put("nonce", "dc-nonce-2")
            put("state", "verifier-session-state")
            put("response_mode", "dc_api.jwt")
            putJsonObject("client_metadata") {
                putJsonObject("jwks") {
                    putJsonArray("keys") {
                        add(Json.parseToJsonElement(
                            verifierEncKey.toPublicJWK().toJSONString()
                        ))
                    }
                }
            }
        })

        val result = wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

        val parsed = Json.parseToJsonElement(result.responseJson).jsonObject
        val jwe = parsed["data"]?.jsonObject?.get("response")?.jsonPrimitive?.content
        assertTrue("response must be a JWE, not a plain vp_token", jwe != null)
        val jweObject = JWEObject.parse(jwe)
        // The JWE header must carry the verifier's own kid so it can find
        // the matching ephemeral private key to decrypt with (a real bug:
        // this used to be omitted entirely).
        assertEquals("enc-1", jweObject.header.keyID)
        jweObject.decrypt(ECDHDecrypter(verifierEncKey))
        val decrypted = Json.parseToJsonElement(jweObject.payload.toString()).jsonObject
        assertEquals(
            "signed-vp-token",
            decrypted["vp_token"]?.jsonObject?.get("_default")?.jsonArray?.single()?.jsonPrimitive?.contentOrNull,
        )
        // The verifier's ONLY means of correlating this response to a
        // session - omitting it was a real bug ("state: missing or empty").
        assertEquals("verifier-session-state", decrypted["state"]?.jsonPrimitive?.contentOrNull)
    }

    @Test
    fun handleDCAPIRequest_signedRequest_verifiesJwsAndUsesPayloadFields() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw", metadata = CredentialMetadata(name = "X"), batchId = 1L, instanceId = 0),
        ))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "trustCache" to TrustCache(),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )

        val verifierSigningKey = ECKeyGenerator(Curve.P_256).keyID("verifier-key-1").generate()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).jwk(verifierSigningKey.toPublicJWK()).build()
        val claims = JWTClaimsSet.Builder()
            .claim("client_id", "https://relying-party.example")
            .claim("nonce", "dc-nonce-signed")
            .claim("response_mode", "dc_api")
            .build()
        val signedJwt = SignedJWT(header, claims)
        signedJwt.sign(ECDSASigner(verifierSigningKey))

        val requestJson = wrapDCAPIRequest("openid4vp-v1-signed", buildJsonObject { put("request", signedJwt.serialize()) })

        wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example")

        coVerify(exactly = 1) {
            keystore.signVpToken(any(), any(), nonce = "dc-nonce-signed", audience = "origin:https://relying-party.example")
        }
        // Trust evaluation must have used the JAR's own client_id (from its
        // verified payload), not the bare origin, since a signed request DOES
        // assert an explicit client_id.
        coVerify(exactly = 1) {
            apiClient.evaluateTrust(match { it["subject"]?.jsonObject?.get("id")?.jsonPrimitive?.content == "https://relying-party.example" })
        }
    }

    @Test
    fun handleDCAPIRequest_signedRequestWithTamperedSignature_throws() = runTest(dispatcher) {
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
        )

        val legitKey = ECKeyGenerator(Curve.P_256).keyID("legit").generate()
        val attackerKey = ECKeyGenerator(Curve.P_256).keyID("attacker").generate()
        // Header advertises the legitimate key, but the JWT is actually
        // signed by a different (attacker-controlled) key - signature
        // verification against the advertised key must fail.
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).jwk(legitKey.toPublicJWK()).build()
        val claims = JWTClaimsSet.Builder().claim("nonce", "n").build()
        val signedJwt = SignedJWT(header, claims)
        signedJwt.sign(ECDSASigner(attackerKey))

        var thrown: Throwable? = null
        try {
            wallet.handleDCAPIRequest(
                wrapDCAPIRequest("openid4vp-v1-signed", buildJsonObject { put("request", signedJwt.serialize()) }),
                origin = "https://relying-party.example",
            )
        } catch (e: Throwable) {
            thrown = e
        }
        assertTrue(thrown is org.siros.sdk.wallet.dcapi.DCAPIRequestException)
    }

    @Test
    fun evaluateReaderTrust_remoteCallThrowsAuthzDeny_failsClosedWithoutFallingBackToLocal() = runTest(dispatcher) {
        // Mirrors evaluateIssuerTrust_remoteCallThrowsAuthzDeny_* below -
        // evaluateReaderTrust shares the same isRemoteTrustEvaluationUnreachable
        // classifier, so a 403 from /v1/evaluate must fail closed here too
        // rather than silently falling back to local RICAL root validation.
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws BackendApiException(403, "API request failed: 403", "")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )

        val result = wallet.evaluateReaderTrust(listOf(ByteArray(4)))

        assertTrue(!result.trusted)
        assertEquals("mdocrical", result.framework)
        assertTrue(result.reason?.contains("403") == true)
    }

    @Test
    fun evaluateIssuerTrust_remoteDecisionTrue_returnsTrustedResult() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val evaluationRequest = slot<JsonObject>()
        coEvery { apiClient.evaluateTrust(capture(evaluationRequest)) } returns buildJsonObject {
            put("decision", JsonPrimitive(true))
            putJsonObject("context") {
                put("framework", JsonPrimitive("vical"))
                put("entity_name", JsonPrimitive("Test Issuer CA"))
            }
        }
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )

        val leafCert = ByteArray(4) { it.toByte() }
        val result = wallet.evaluateIssuerTrust(listOf(leafCert), docType = "org.iso.18013.5.1.mDL")

        assertTrue(result.trusted)
        assertEquals("Test Issuer CA", result.entityName)
        assertEquals("mdoc-issuer-auth", evaluationRequest.captured["action"]?.jsonObject?.get("name")?.jsonPrimitive?.content)
        assertEquals("org.iso.18013.5.1.mDL", evaluationRequest.captured["context"]?.jsonObject?.get("doc_type")?.jsonPrimitive?.content)
    }

    @Test
    fun evaluateIssuerTrust_remoteDecisionFalse_returnsUntrustedResult() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject {
            put("decision", JsonPrimitive(false))
            putJsonObject("context") {
                put("reason", JsonPrimitive("certificate not listed in VICAL for docType"))
            }
        }
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )

        val result = wallet.evaluateIssuerTrust(listOf(ByteArray(4)), docType = "org.iso.18013.5.1.mDL")

        assertTrue(!result.trusted)
        assertEquals("certificate not listed in VICAL for docType", result.reason)
    }

    @Test
    fun evaluateIssuerTrust_remoteCallThrowsNetworkException_fallsBackToLocalAndReportsUnconfigured() = runTest(dispatcher) {
        // A genuine network failure (timeout, DNS, connection refused) surfaces as
        // NetworkException from BackendApiClient - the only condition that should
        // fall back to weaker local validation. See the sibling
        // *_remoteCallThrowsAuthzDeny_* test below for the 403 case, which must
        // NOT fall back.
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws NetworkException("network unreachable")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )

        val result = wallet.evaluateIssuerTrust(listOf(ByteArray(4)), docType = "org.iso.18013.5.1.mDL")

        assertTrue(!result.trusted)
        assertEquals("local-vical-root", result.framework)
        assertTrue(result.reason?.contains("no VICAL root certificate configured") == true)
    }

    @Test
    fun evaluateIssuerTrust_remoteCallThrowsAuthzDeny_failsClosedWithoutFallingBackToLocal() = runTest(dispatcher) {
        // GDC/SDK-6 (Geneva 2026): a 403 from /v1/evaluate is an authorization
        // failure, not a trust decision - it must not be silently treated the
        // same as an unreachable backend, since a locally-configured VICAL root
        // could still declare the chain trusted even though the backend
        // explicitly refused to even answer the question.
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws BackendApiException(403, "API request failed: 403", "")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )

        val result = wallet.evaluateIssuerTrust(listOf(ByteArray(4)), docType = "org.iso.18013.5.1.mDL")

        assertTrue(!result.trusted)
        // "vical" (not "local-vical-root") plus a "403"-mentioning reason proves
        // this took the fail-closed remote-error path, not the local-fallback
        // path (which would report "local-vical-root" / "no VICAL root
        // certificate configured", per the sibling NetworkException test above).
        assertEquals("vical", result.framework)
        assertTrue(result.reason?.contains("403") == true)
    }

    @Test
    fun evaluateIssuerTrust_preferLocalIssuerTrustEvaluation_skipsRemoteCallEntirely() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", preferLocalIssuerTrustEvaluation = true),
        )

        val result = wallet.evaluateIssuerTrust(listOf(ByteArray(4)), docType = "org.iso.18013.5.1.mDL")

        assertTrue(!result.trusted)
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
    }

    @Test
    fun evaluateIssuerTrust_emptyX5chain_returnsUntrustedWithoutCallingBackend() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )

        val result = wallet.evaluateIssuerTrust(emptyList(), docType = "org.iso.18013.5.1.mDL")

        assertTrue(!result.trusted)
        assertEquals("issuerAuth has no certificate chain", result.reason)
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
    }

    // ── MdocTrustEvaluationMode ────────────────────────────────────────────
    //
    // Which of the two mdoc trust paths runs is a security decision, not a
    // performance one: the local path parses no RICAL/VICAL CBOR and enforces
    // neither `trustConstraints` nor `docType`. These pin apart the three
    // outcomes that must never collapse into one another - a backend that
    // said no, a backend that refused US, and a backend that was not there.
    //
    // The discriminator throughout is `framework`: the local path reports
    // `local-rical-root`, every remote-side outcome reports `mdocrical`.

    @Test
    fun evaluateReaderTrust_localOnlyMode_skipsRemoteCallEntirely() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                readerTrustEvaluationMode = MdocTrustEvaluationMode.LOCAL_ONLY,
            ),
        )

        val result = wallet.evaluateReaderTrust(listOf(ByteArray(4)))

        assertEquals("local-rical-root", result.framework)
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
    }

    @Test
    fun evaluateReaderTrust_remoteWithLocalFallback_unreachableBackend_fallsBackToLocal() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws NetworkException("connection refused")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )

        val result = wallet.evaluateReaderTrust(listOf(ByteArray(4)))

        assertEquals("local-rical-root", result.framework)
    }

    /**
     * A 403 on `/v1/evaluate` means the backend was reachable and rejected the
     * CALLER, not the trust question. Falling back to the weaker local check
     * there would let an expired token silently downgrade a security-relevant
     * deny - confirmed live at Geneva 2026.
     */
    @Test
    fun evaluateReaderTrust_remoteWithLocalFallback_backendRefusedCaller_failsClosed() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws BackendApiException(403, "forbidden")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )

        val result = wallet.evaluateReaderTrust(listOf(ByteArray(4)))

        assertTrue(!result.trusted)
        assertEquals("mdocrical", result.framework)
    }

    @Test
    fun evaluateReaderTrust_remoteOnlyMode_unreachableBackend_doesNotFallBackToLocal() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws NetworkException("offline")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                readerTrustEvaluationMode = MdocTrustEvaluationMode.REMOTE_ONLY,
            ),
        )

        val result = wallet.evaluateReaderTrust(listOf(ByteArray(4)))

        assertTrue(!result.trusted)
        assertEquals("mdocrical", result.framework)
        // The reason has to name the configured mode, or an operator cannot
        // tell a deliberate remote-only deny from a genuinely untrusted reader.
        assertTrue("got: ${result.reason}", result.reason?.contains("remote-only") == true)
    }

    @Test
    fun evaluateIssuerTrust_remoteOnlyMode_unreachableBackend_doesNotFallBackToLocal() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws NetworkException("offline")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                issuerTrustEvaluationMode = MdocTrustEvaluationMode.REMOTE_ONLY,
            ),
        )

        val result = wallet.evaluateIssuerTrust(listOf(ByteArray(4)), docType = "org.iso.18013.5.1.mDL")

        assertTrue(!result.trusted)
        assertEquals("vical", result.framework)
        assertTrue("got: ${result.reason}", result.reason?.contains("remote-only") == true)
    }

    /**
     * The deprecated boolean keeps working, so an existing caller's behavior
     * does not change under them.
     */
    @Test
    @Suppress("DEPRECATION")
    fun evaluateReaderTrust_deprecatedPreferLocalBoolean_stillMeansLocalOnly() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                preferLocalReaderTrustEvaluation = true,
            ),
        )

        val result = wallet.evaluateReaderTrust(listOf(ByteArray(4)))

        assertEquals("local-rical-root", result.framework)
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
    }

    /**
     * Precedence: a caller who asks for REMOTE_ONLY must not be silently
     * downgraded to local by a legacy boolean they did not set.
     */
    @Test
    @Suppress("DEPRECATION")
    fun evaluateReaderTrust_explicitModeWinsOverDeprecatedBoolean() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws NetworkException("offline")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                preferLocalReaderTrustEvaluation = true,
                readerTrustEvaluationMode = MdocTrustEvaluationMode.REMOTE_ONLY,
            ),
        )

        val result = wallet.evaluateReaderTrust(listOf(ByteArray(4)))

        assertEquals("mdocrical", result.framework)
        assertTrue("got: ${result.reason}", result.reason?.contains("remote-only") == true)
    }

    /**
     * The awkward precedence case: REMOTE_WITH_LOCAL_FALLBACK is also what an
     * unset mode resolves to, so comparing against the default cannot tell
     * "the caller asked for the fallback mode" from "the caller said
     * nothing". The config property is nullable precisely so that it can.
     */
    @Test
    @Suppress("DEPRECATION")
    fun explicitFallbackMode_isNotDowngradedByDeprecatedBoolean() {
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            preferLocalReaderTrustEvaluation = true,
            readerTrustEvaluationMode = MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK,
        )

        assertEquals(
            MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK,
            config.effectiveReaderTrustEvaluationMode,
        )
    }

    @Test
    @Suppress("DEPRECATION")
    fun unsetMode_stillHonoursTheDeprecatedBoolean() {
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
            preferLocalIssuerTrustEvaluation = true,
        )

        assertEquals(MdocTrustEvaluationMode.LOCAL_ONLY, config.effectiveIssuerTrustEvaluationMode)
    }

    /**
     * Wraps a request's `data` object in the envelope
     * [org.siros.sdk.wallet.dcapi.DCAPIRequestParser.parse] actually expects
     * from [androidx.credentials.GetDigitalCredentialOption.requestJson] -
     * `{"requests": [{"protocol": ..., "data": {...}}]}`, not the bare
     * `data` object on its own (see that parser's fix for why).
     */
    private fun wrapDCAPIRequest(protocol: String, data: JsonObject): String = buildJsonObject {
        putJsonArray("requests") {
            add(buildJsonObject {
                put("protocol", protocol)
                put("data", data)
            })
        }
    }.toString()

    // ── hydrateReloadedCredentials ──────────────────────────────────

    /** `{"alg":"ES256"}.{"iat":1700000000,"exp":1800000000,"vct":"urn:eudi:pid:1"}.sig~` */
    private val reloadedSdJwt = "eyJhbGciOiJFUzI1NiJ9." +
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            """{"iat":1700000000,"exp":1800000000,"vct":"urn:eudi:pid:1"}""".toByteArray(),
        ) + ".c2ln~"

    private fun reloadedCredential(id: Long, metadata: CredentialMetadata? = null) = StoredCredential(
        id = id,
        format = "dc+sd-jwt",
        raw = reloadedSdJwt,
        batchId = id,
        instanceId = 0,
        credentialIssuerIdentifier = "https://issuer.example.com",
        credentialConfigurationId = "eu.europa.ec.eudi.pid_sd_jwt",
        metadata = metadata,
    )

    private fun hydrate(wallet: SirosWallet) {
        val method = wallet::class.declaredMemberFunctions.first { it.name == "hydrateReloadedCredentials" }
        method.isAccessible = true
        method.call(wallet)
    }

    /**
     * The user-visible bug this guards against: a credential whose VCTM
     * can't be fetched used to stay `metadata == null` forever, and the card
     * UI treats null as "loading" - a spinner on every launch. Now a fallback
     * is persisted immediately so the card has something real to draw.
     */
    @Test
    fun hydrate_persistsFallbackMetadata_whenNoDocumentIsAvailable() = runTest(dispatcher) {
        val store = FakeCredentialStore(mutableListOf(reloadedCredential(1L)))
        val vctmFetcher = mockk<org.siros.sdk.credentials.VctmFetcher>()
        coEvery { vctmFetcher.fetch(any(), any(), any(), any()) } returns null
        val state = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "u", displayName = null, credentials = store.getAll()),
        )
        val wallet = newWallet(
            "_state" to state,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "vctmFetcher" to vctmFetcher,
        )

        hydrate(wallet)
        advanceUntilIdle()

        val saved = store.getById(1L)!!
        val meta = saved.metadata!!
        assertTrue(meta.isFallback)
        assertEquals("Pid Sd Jwt", meta.name)
        assertEquals("issuer.example.com", meta.issuer!!.name)
        assertEquals("urn:eudi:pid:1", meta.vct)
        assertNull(meta.svgTemplates)
        // iat/exp are still derived alongside.
        assertEquals(1700000000L, saved.issuedAt)
        assertEquals(1800000000L, saved.expiresAt)
        // And Ready was re-emitted with the hydrated list.
        assertTrue((state.value as WalletState.Ready).credentials.single().metadata!!.isFallback)
        coVerify(exactly = 1) {
            vctmFetcher.fetch(
                issuerUrl = "https://issuer.example.com",
                scope = "eu.europa.ec.eudi.pid_sd_jwt",
                vct = "urn:eudi:pid:1",
                registryUrl = "https://wallet.example.com/registry",
            )
        }
    }

    /** A fallback is still "needs hydration": the next successful fetch replaces it. */
    @Test
    fun hydrate_replacesFallback_whenDocumentBecomesAvailable() = runTest(dispatcher) {
        val fallback = org.siros.sdk.credentials.CredentialUtils.buildFallbackMetadata(reloadedCredential(1L))
        val store = FakeCredentialStore(
            mutableListOf(reloadedCredential(1L, metadata = fallback).copy(issuedAt = 1700000000L, expiresAt = 1800000000L)),
        )
        val vctmFetcher = mockk<org.siros.sdk.credentials.VctmFetcher>()
        coEvery { vctmFetcher.fetch(any(), any(), any(), any()) } returns
            org.siros.sdk.credentials.VctmFetcher().parseVctm(
                """{"vct":"urn:eudi:pid:1","display":[{"locale":"en","name":"Personal ID",
                   "rendering":{"simple":{"background_color":"#003366"}}}]}""",
            )
        val state = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "u", displayName = null, credentials = store.getAll()),
        )
        val wallet = newWallet(
            "_state" to state,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "vctmFetcher" to vctmFetcher,
        )

        hydrate(wallet)
        advanceUntilIdle()

        val meta = store.getById(1L)!!.metadata!!
        assertEquals(false, meta.isFallback)
        assertEquals("Personal ID", meta.name)
        assertEquals("#003366", meta.backgroundColor)
        assertEquals("Personal ID", (state.value as WalletState.Ready).credentials.single().metadata!!.name)
    }

    /**
     * While the negative cache says "not due", `fetch` returns null at once;
     * an existing fallback must then be left alone - no re-save, no Ready
     * re-emission - or every launch would still churn state for nothing.
     */
    @Test
    fun hydrate_leavesExistingFallbackUntouched_whenStillNoDocument() = runTest(dispatcher) {
        val fallback = org.siros.sdk.credentials.CredentialUtils.buildFallbackMetadata(reloadedCredential(1L))
        val existing = reloadedCredential(1L, metadata = fallback).copy(issuedAt = 1700000000L, expiresAt = 1800000000L)
        val saves = mutableListOf<StoredCredential>()
        val store = object : CredentialStore by FakeCredentialStore(mutableListOf(existing)) {
            override suspend fun save(credential: StoredCredential) { saves.add(credential) }
        }
        val vctmFetcher = mockk<org.siros.sdk.credentials.VctmFetcher>()
        coEvery { vctmFetcher.fetch(any(), any(), any(), any()) } returns null
        val initial = WalletState.Ready(userId = "u", displayName = null, credentials = listOf(existing))
        val state = MutableStateFlow<WalletState>(initial)
        val wallet = newWallet(
            "_state" to state,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "vctmFetcher" to vctmFetcher,
        )

        hydrate(wallet)
        advanceUntilIdle()

        assertTrue(saves.isEmpty())
        assertTrue(state.value === initial)
    }

    /** Real (non-fallback) metadata is never touched, and the fetcher is not even asked. */
    @Test
    fun hydrate_skipsCredentialsWithRealMetadata() = runTest(dispatcher) {
        val real = CredentialMetadata(name = "Personal ID", vct = "urn:eudi:pid:1")
        val store = FakeCredentialStore(mutableListOf(reloadedCredential(1L, metadata = real)))
        val vctmFetcher = mockk<org.siros.sdk.credentials.VctmFetcher>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = null)),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "vctmFetcher" to vctmFetcher,
        )

        hydrate(wallet)
        advanceUntilIdle()

        coVerify(exactly = 0) { vctmFetcher.fetch(any(), any(), any(), any()) }
        assertEquals(real, store.getById(1L)!!.metadata)
    }

    /**
     * Credentials hydrate concurrently: with two slow fetches that each take
     * a (virtual) second, the whole pass takes one second, not two - and
     * Ready is still emitted exactly once, at the end.
     */
    @Test
    fun hydrate_runsCredentialsConcurrently_andEmitsReadyOnce() = runTest(dispatcher) {
        val store = FakeCredentialStore(mutableListOf(reloadedCredential(1L), reloadedCredential(2L)))
        val vctmFetcher = mockk<org.siros.sdk.credentials.VctmFetcher>()
        coEvery { vctmFetcher.fetch(any(), any(), any(), any()) } coAnswers {
            kotlinx.coroutines.delay(1_000)
            null
        }
        val state = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "u", displayName = null, credentials = store.getAll()),
        )
        var emissions = 0
        // Foreground, not backgroundScope: advanceUntilIdle() stops once only
        // background tasks remain, so a background collector would never be
        // resumed for the re-emission it is here to count.
        val collector = launch { state.collect { emissions++ } }
        runCurrent() // subscribe before hydration starts
        val wallet = newWallet(
            "_state" to state,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "vctmFetcher" to vctmFetcher,
        )

        hydrate(wallet)
        val started = testScheduler.currentTime
        advanceUntilIdle()
        val elapsed = testScheduler.currentTime - started

        assertEquals(1_000L, elapsed)
        assertTrue(store.getAll().all { it.metadata?.isFallback == true })
        // Initial value + one re-emission.
        assertEquals(2, emissions)
        collector.cancel()
    }


    // ── Wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319) ──

    /**
     * A login refused with `403 WALLET_SUSPENDED` is a state, not an error:
     * the instance can be reactivated from another device, so the cached
     * account stays on the login screen and nothing local is lost.
     */
    @Test
    fun login_refused_as_suspended_enters_the_blocked_state_and_keeps_the_account() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 — /auth/login/finish",
            errorCode = "WALLET_SUSPENDED",
            code = 403,
            serverMessage = "This device is suspended",
        )
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Disconnected())
        val listener = RecordingLifecycleListener()
        val wallet = lifecycleWallet(stateFlow, accountRegistry, authServerClient, listener)

        wallet.login()
        advanceUntilIdle()

        val blocked = stateFlow.value as WalletState.LifecycleBlocked
        assertEquals(WalletLifecycleRefusal.SUSPENDED, blocked.reason)
        assertEquals("This device is suspended", blocked.message)
        assertEquals(1, blocked.cachedAccounts.size)
        verify(exactly = 0) { accountRegistry.removeAccount(any()) }
        assertEquals(WalletLifecycleRefusal.SUSPENDED to "This device is suspended", listener.blocked)
    }

    /**
     * A `WALLET_REVOKED` carrying no `scope` is a backend that predates the
     * field, and it must be read as the per-instance case: the wallet may well
     * still exist, and forgetting the cached account would destroy the other
     * passkeys that still work. The conservative reading is the safe one.
     */
    @Test
    fun login_refused_as_revoked_keeps_the_cached_account() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 — /auth/login/begin",
            errorCode = "WALLET_REVOKED",
            code = 403,
            serverMessage = "This device was removed",
        )
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Disconnected())
        val wallet = lifecycleWallet(stateFlow, accountRegistry, authServerClient)

        wallet.login()
        advanceUntilIdle()

        val blocked = stateFlow.value as WalletState.LifecycleBlocked
        assertEquals(WalletLifecycleRefusal.REVOKED, blocked.reason)
        assertEquals("This device was removed", blocked.message)
        assertEquals(1, blocked.cachedAccounts.size)
        verify(exactly = 0) { accountRegistry.removeAccount(any()) }
    }

    /**
     * `WALLET_REVOKED` with `scope: "instance"` is the per-instance case said
     * out loud. Under the EUDI specifications revoking one wallet unit ends
     * that unit and nothing else, so the user's other devices and passkeys -
     * and this account on the login screen - survive it.
     */
    @Test
    fun login_refused_as_revoked_with_instance_scope_keeps_the_cached_account() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 \u2014 /auth/login/begin",
            cause = null,
            errorCode = "WALLET_REVOKED",
            code = 403,
            serverMessage = "This wallet instance has been revoked",
            serverScope = "instance",
        )
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Disconnected())
        val wallet = lifecycleWallet(stateFlow, accountRegistry, authServerClient)

        wallet.login()
        advanceUntilIdle()

        val blocked = stateFlow.value as WalletState.LifecycleBlocked
        assertEquals(WalletLifecycleRefusal.REVOKED, blocked.reason)
        assertEquals(1, blocked.cachedAccounts.size)
        verify(exactly = 0) { accountRegistry.removeAccount(any()) }
    }

    /**
     * `WALLET_REVOKED` with `scope: "wallet"` is the only refusal that reaches
     * the whole wallet: every instance is revoked and the server-side data
     * erased, so the vault this account's passkey decrypts no longer exists.
     * Keeping it on the login screen would only produce the same refusal, so
     * this is the one case where the cached account goes.
     */
    @Test
    fun login_refused_as_deactivated_forgets_the_cached_account() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 \u2014 /auth/login/finish",
            cause = null,
            errorCode = "WALLET_REVOKED",
            code = 403,
            serverMessage = "This wallet has been deactivated; a new enrollment is required",
            serverScope = "wallet",
        )
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Disconnected())
        val listener = RecordingLifecycleListener()
        val wallet = lifecycleWallet(
            stateFlow, accountRegistry, authServerClient, listener,
            fields = arrayOf("authTokens" to mockk<AuthTokens>(relaxed = true)),
        )

        // The account the refused operation was for, as its caller captured it
        // when that operation started.
        invokePrivateBoolean(
            wallet, "handleLifecycleRefusal",
            AuthException(
                "AS request failed: 403 \u2014 /auth/login/finish",
                cause = null,
                errorCode = "WALLET_REVOKED",
                code = 403,
                serverMessage = "This wallet has been deactivated; a new enrollment is required",
                serverScope = "wallet",
            ),
            "default:user-1",
        )
        advanceUntilIdle()

        val blocked = stateFlow.value as WalletState.LifecycleBlocked
        assertEquals(WalletLifecycleRefusal.DEACTIVATED, blocked.reason)
        assertEquals(
            "This wallet has been deactivated; a new enrollment is required",
            blocked.message,
        )
        verify(exactly = 1) { accountRegistry.removeAccount("default:user-1") }
        assertEquals(WalletLifecycleRefusal.DEACTIVATED, listener.blocked?.first)
    }

    /**
     * A login offers every cached account's passkeys at once, so the account
     * signed in beforehand is not necessarily the one being refused. The
     * account to forget is the one whose passkey answered the ceremony -
     * reading the active account instead would destroy a wallet the refusal
     * was never about.
     */
    @Test
    fun a_deactivation_forgets_the_account_that_answered_not_the_active_one() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry() // active is default:user-1
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 \u2014 /auth/login/finish",
            cause = null,
            errorCode = "WALLET_REVOKED",
            code = 403,
            serverMessage = null,
            serverScope = "wallet",
        )
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Disconnected())
        val wallet = lifecycleWallet(
            stateFlow, accountRegistry, authServerClient,
            fields = arrayOf("authTokens" to mockk<AuthTokens>(relaxed = true)),
        )

        // The ceremony was answered by a different account than the active one.
        invokePrivateBoolean(
            wallet, "handleLifecycleRefusal",
            AuthException(
                "AS request failed: 403 \u2014 /auth/login/finish",
                cause = null,
                errorCode = "WALLET_REVOKED",
                code = 403,
                serverMessage = null,
                serverScope = "wallet",
            ),
            "default:user-2",
        )
        advanceUntilIdle()

        verify(exactly = 1) { accountRegistry.removeAccount("default:user-2") }
        verify(exactly = 0) { accountRegistry.removeAccount("default:user-1") }
    }

    /**
     * When nothing says which account a deactivation was about, forgetting
     * anything would be a guess at the user's expense. The block still
     * happens; every cached account stays.
     *
     * End to end on purpose: this login is refused at `loginBegin`, before any
     * WebAuthn ceremony ran, so nothing recorded who answered. Reaching for
     * the authenticator's last credential here would name an account from a
     * *previous* login and delete it.
     */
    @Test
    fun a_deactivation_that_names_no_account_forgets_nothing() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 \u2014 /auth/login/begin",
            cause = null,
            errorCode = "WALLET_REVOKED",
            code = 403,
            serverMessage = null,
            serverScope = "wallet",
        )
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Disconnected())
        val wallet = lifecycleWallet(stateFlow, accountRegistry, authServerClient)

        wallet.login()
        advanceUntilIdle()

        val blocked = stateFlow.value as WalletState.LifecycleBlocked
        assertEquals(WalletLifecycleRefusal.DEACTIVATED, blocked.reason)
        verify(exactly = 0) { accountRegistry.removeAccount(any()) }
    }

    /**
     * The backend answers a refusal with the same `{error, scope, message}`
     * body from the wallet API as from the AS passkey endpoint, and a
     * wallet-API failure reaches the SDK as a `BackendApiException` carrying
     * the raw body. Reading only the AS shape would let a refusal met there
     * fall through to a generic error instead of the blocked state.
     */
    @Test
    fun a_refusal_carried_by_the_wallet_api_is_recognised() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws
            org.siros.sdk.credentials.BackendApiException(
                403,
                "Backend API error",
                """{"error":"WALLET_REVOKED","scope":"instance","message":"This wallet instance has been revoked"}""",
            )
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Disconnected())
        val wallet = lifecycleWallet(stateFlow, accountRegistry, authServerClient)

        wallet.login()
        advanceUntilIdle()

        val blocked = stateFlow.value as WalletState.LifecycleBlocked
        assertEquals(WalletLifecycleRefusal.REVOKED, blocked.reason)
        assertEquals("This wallet instance has been revoked", blocked.message)
        verify(exactly = 0) { accountRegistry.removeAccount(any()) }
    }

    /**
     * A scope this SDK does not know is not a licence to erase. An unexpected
     * value falls back to the per-instance reading, exactly as an absent one
     * does, so a future backend that adds a third scope cannot make an older
     * SDK throw away the user's account.
     */
    @Test
    fun login_refused_with_an_unknown_scope_keeps_the_cached_account() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 \u2014 /auth/login/begin",
            cause = null,
            errorCode = "WALLET_REVOKED",
            code = 403,
            serverMessage = "Refused",
            serverScope = "solar-system",
        )
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Disconnected())
        val wallet = lifecycleWallet(stateFlow, accountRegistry, authServerClient)

        wallet.login()
        advanceUntilIdle()

        val blocked = stateFlow.value as WalletState.LifecycleBlocked
        assertEquals(WalletLifecycleRefusal.REVOKED, blocked.reason)
        verify(exactly = 0) { accountRegistry.removeAccount(any()) }
    }

    /**
     * A suspension is per-instance by construction, so a `scope` on it changes
     * nothing - and a (malformed) `scope: "wallet"` on a `WALLET_SUSPENDED`
     * must not be allowed to erase anything either.
     */
    @Test
    fun a_suspension_never_forgets_the_account_whatever_the_scope() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 \u2014 /auth/login/begin",
            cause = null,
            errorCode = "WALLET_SUSPENDED",
            code = 403,
            serverMessage = "Suspended",
            serverScope = "wallet",
        )
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Disconnected())
        val wallet = lifecycleWallet(stateFlow, accountRegistry, authServerClient)

        wallet.login()
        advanceUntilIdle()

        val blocked = stateFlow.value as WalletState.LifecycleBlocked
        assertEquals(WalletLifecycleRefusal.SUSPENDED, blocked.reason)
        verify(exactly = 0) { accountRegistry.removeAccount(any()) }
    }

    /**
     * A suspended instance is reactivated from another device and the app
     * retries [SirosWallet.login], which reuses the same AS session cookie. An
     * unawaited `DELETE /auth/session` scheduled by the block could land after
     * that retry's `loginFinish` and invalidate the session it had just
     * established - so the blocked path tears down locally and never asks the
     * AS to end a session the backend has already refused.
     */
    @Test
    fun a_lifecycle_block_does_not_end_the_server_session() = runTest(dispatcher) {
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "user-1", displayName = "Alice")
        )
        val wallet = lifecycleWallet(
            stateFlow, lifecycleAccountRegistry(), authServerClient,
            fields = arrayOf("authTokens" to mockk<AuthTokens>(relaxed = true)),
        )

        invokePrivateBoolean(
            wallet, "handleLifecycleRefusal",
            AuthException(
                "AS request failed: 403 — /auth/login/begin",
                errorCode = "WALLET_SUSPENDED",
                code = 403,
            ),
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { authServerClient.logout() }

        // The contrast: an explicit logout does end the server session.
        wallet.logout()
        advanceUntilIdle()
        coVerify(exactly = 1) { authServerClient.logout() }
    }

    /** Any other login failure keeps the existing error path. */
    @Test
    fun login_failure_that_is_not_a_lifecycle_refusal_still_becomes_an_error() = runTest(dispatcher) {
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 401 — /auth/login/begin",
            errorCode = "auth_failed",
            code = 401,
        )
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Disconnected())
        val wallet = lifecycleWallet(stateFlow, lifecycleAccountRegistry(), authServerClient)

        wallet.login()
        advanceUntilIdle()

        assertTrue(stateFlow.value.toString(), stateFlow.value is WalletState.Error)
    }

    /**
     * The token cut-off: after a lifecycle change made elsewhere every request
     * is refused with 401, the SDK's reauthentication signal fires, and the
     * SDK itself attempts exactly one login - which the AS refuses with the
     * lifecycle code. The host's own hook still fires, so apps that drive
     * their own prompt see no change in ordering.
     */
    @Test
    fun reauthentication_signal_drives_one_relogin_that_lands_in_the_blocked_state() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 — /auth/login/begin",
            errorCode = "WALLET_SUSPENDED",
            code = 403,
            serverMessage = "Suspended by your provider",
        )
        val stateFlow = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "user-1", displayName = "Alice")
        )
        val listener = RecordingLifecycleListener()
        val authTokens = mockk<AuthTokens>(relaxed = true)
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val wallet = lifecycleWallet(
            stateFlow, accountRegistry, authServerClient, listener,
            "authTokens" to authTokens,
            "engineSession" to engine,
        )

        invokePrivate(wallet, "handleReauthenticationRequired")
        advanceUntilIdle()

        assertTrue(listener.reauthenticationRequired)
        coVerify(atLeast = 1) { authTokens.clear() }
        verify(exactly = 1) { engine.disconnect() }
        coVerify(exactly = 1) { authServerClient.loginBegin() }
        val blocked = stateFlow.value as WalletState.LifecycleBlocked
        assertEquals(WalletLifecycleRefusal.SUSPENDED, blocked.reason)
        assertEquals("Suspended by your provider", blocked.message)
    }

    /**
     * Once per session, not once per call. Requests issued before a cut-off
     * complete long after it - still holding the same [AuthTokens] - and each
     * of their 401s re-enters the signal, so releasing the in-progress flag
     * must not re-open the door for the same session. Only a new session may
     * be cut off again.
     */
    @Test
    fun a_late_401_from_the_session_already_handled_does_not_start_a_second_relogin() = runTest(dispatcher) {
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 — /auth/login/begin",
            errorCode = "WALLET_SUSPENDED",
            code = 403,
        )
        val stateFlow = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "user-1", displayName = "Alice")
        )
        val wallet = lifecycleWallet(
            stateFlow, lifecycleAccountRegistry(), authServerClient,
            fields = arrayOf("authTokens" to mockk<AuthTokens>(relaxed = true)),
        )

        invokePrivate(wallet, "handleReauthenticationRequired")
        advanceUntilIdle()
        // The first attempt has finished; a pre-cut-off request's 401 lands now.
        invokePrivate(wallet, "handleReauthenticationRequired")
        advanceUntilIdle()

        coVerify(exactly = 1) { authServerClient.loginBegin() }
    }

    /**
     * There is nothing to replace once the session is gone, and a silent
     * WebAuthn prompt after an explicit logout would be the wrong answer.
     */
    @Test
    fun no_self_driven_relogin_without_a_session_to_replace() = runTest(dispatcher) {
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        for (state in listOf(
            WalletState.Disconnected(),
            WalletState.Error("boom"),
            WalletState.LifecycleBlocked(WalletLifecycleRefusal.SUSPENDED, null),
        )) {
            val wallet = lifecycleWallet(
                MutableStateFlow(state), lifecycleAccountRegistry(), authServerClient,
                fields = arrayOf("authTokens" to mockk<AuthTokens>(relaxed = true)),
            )
            invokePrivate(wallet, "handleReauthenticationRequired")
            advanceUntilIdle()
        }

        coVerify(exactly = 0) { authServerClient.loginBegin() }
    }

    /**
     * [SirosWallet.destroy] leaves the state alone - a destroyed wallet is not
     * a logged-out one - so the generation bump on its own would still let a
     * re-authentication signal from a coroutine still unwinding pass the guard
     * and log back in after the host tore the wallet down. Connecting is not
     * replaceable either: that is where the *initial* login sits.
     */
    @Test
    fun no_self_driven_relogin_after_destroy_or_while_connecting() = runTest(dispatcher) {
        val authServerClient = mockk<AuthServerClient>(relaxed = true)

        val connecting = lifecycleWallet(
            MutableStateFlow(WalletState.Connecting), lifecycleAccountRegistry(), authServerClient,
            fields = arrayOf("authTokens" to mockk<AuthTokens>(relaxed = true)),
        )
        invokePrivate(connecting, "handleReauthenticationRequired")
        advanceUntilIdle()

        val destroyed = lifecycleWallet(
            MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            lifecycleAccountRegistry(), authServerClient,
            fields = arrayOf(
                "authTokens" to mockk<AuthTokens>(relaxed = true),
                "isDestroyed" to true,
            ),
        )
        invokePrivate(destroyed, "handleReauthenticationRequired")
        advanceUntilIdle()

        coVerify(exactly = 0) { authServerClient.loginBegin() }
    }

    /**
     * Exactly once, never a loop: the 401s the re-login's own requests may
     * provoke re-enter the same signal, and must not start a second attempt.
     */
    @Test
    fun a_repeated_reauthentication_signal_does_not_start_a_second_relogin() = runTest(dispatcher) {
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 — /auth/login/begin",
            errorCode = "WALLET_REVOKED",
            code = 403,
        )
        val stateFlow = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "user-1", displayName = "Alice")
        )
        val wallet = lifecycleWallet(
            stateFlow, lifecycleAccountRegistry(), authServerClient,
            fields = arrayOf("authTokens" to mockk<AuthTokens>(relaxed = true)),
        )

        invokePrivate(wallet, "handleReauthenticationRequired")
        invokePrivate(wallet, "handleReauthenticationRequired")
        advanceUntilIdle()

        coVerify(exactly = 1) { authServerClient.loginBegin() }
    }

    /**
     * Every status write records a cut-off, and the acting token's exemption
     * does not reach `POST /auth/token` or an engine flow start - so the
     * facade re-logs in rather than letting the next flow discover it as a
     * 401. Suspending this device's own instance therefore ends in
     * LifecycleBlocked(SUSPENDED), which is the truthful state.
     */
    @Test
    fun suspending_this_device_relogins_and_lands_in_the_blocked_state() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery {
            apiClient.setWalletInstanceStatus("jkt-self", WalletInstanceStatus.SUSPENDED, "lost phone")
        } returns WalletInstance(id = "jkt-self", status = "suspended")
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        coEvery { authServerClient.loginBegin() } throws AuthException(
            "AS request failed: 403 — /auth/login/begin",
            errorCode = "WALLET_SUSPENDED",
            code = 403,
            serverMessage = "This device is suspended",
        )
        val stateFlow = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "user-1", displayName = "Alice")
        )
        val authTokens = mockk<AuthTokens>(relaxed = true)
        val wallet = lifecycleWallet(
            stateFlow, lifecycleAccountRegistry(), authServerClient,
            fields = arrayOf("apiClient" to apiClient, "authTokens" to authTokens),
        )

        val updated = wallet.setWalletInstanceStatus("jkt-self", WalletInstanceStatus.SUSPENDED, "lost phone")
        advanceUntilIdle()

        assertEquals("suspended", updated.status)
        assertEquals(WalletInstanceStatus.SUSPENDED, updated.statusEnum)
        coVerify(atLeast = 1) { authTokens.clear() }
        coVerify(exactly = 1) { authServerClient.loginBegin() }
        assertEquals(
            WalletLifecycleRefusal.SUSPENDED,
            (stateFlow.value as WalletState.LifecycleBlocked).reason,
        )
    }

    /**
     * deactivateWallet reports what the backend actually did and forgets the
     * local account - the vault it decrypts no longer exists. It does not
     * re-login: there is nothing left to log in to.
     */
    @Test
    fun deactivate_wallet_returns_the_outcome_and_forgets_the_account() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.revokeAllWalletInstances("device stolen") } returns
            DeactivationOutcome(revoked = 2, complete = true)
        val authServerClient = mockk<AuthServerClient>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "user-1", displayName = "Alice")
        )
        val wallet = lifecycleWallet(
            stateFlow, accountRegistry, authServerClient,
            fields = arrayOf("apiClient" to apiClient, "authTokens" to mockk<AuthTokens>(relaxed = true)),
        )

        val outcome = wallet.deactivateWallet("device stolen")
        advanceUntilIdle()

        assertEquals(2, outcome.revoked)
        assertTrue(outcome.complete)
        verify(exactly = 1) { accountRegistry.removeAccount("default:user-1") }
        coVerify(exactly = 0) { authServerClient.loginBegin() }
    }

    /**
     * An erasure the backend could not finish still deactivated the wallet -
     * the revocations stand and the keys are gone or going - so the local
     * account is forgotten either way; `complete` is only what the app tells
     * the user.
     */
    @Test
    fun deactivate_wallet_forgets_the_account_even_when_the_erasure_is_incomplete() = runTest(dispatcher) {
        val accountRegistry = lifecycleAccountRegistry()
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.revokeAllWalletInstances(null) } returns
            DeactivationOutcome(revoked = 2, complete = false)
        val stateFlow = MutableStateFlow<WalletState>(
            WalletState.Ready(userId = "user-1", displayName = "Alice")
        )
        val wallet = lifecycleWallet(
            stateFlow, accountRegistry, mockk<AuthServerClient>(relaxed = true),
            fields = arrayOf("apiClient" to apiClient, "authTokens" to mockk<AuthTokens>(relaxed = true)),
        )

        val outcome = wallet.deactivateWallet()
        advanceUntilIdle()

        assertEquals(false, outcome.complete)
        verify(exactly = 1) { accountRegistry.removeAccount("default:user-1") }
    }

    /**
     * The facade marks the row that is this installation by comparing the
     * backend's instance ids to the instance-key thumbprint it already sends
     * as `wallet_instance_id` (the WIA's `cnf.jkt`).
     */
    @Test
    fun list_wallet_instances_marks_this_device_from_the_instance_key_thumbprint() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.listWalletInstances() } returns listOf(
            WalletInstance(id = "jkt-self", status = "active"),
            WalletInstance(id = "jkt-other", status = "suspended"),
        )
        val wallet = lifecycleWallet(
            MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            lifecycleAccountRegistry(),
            mockk<AuthServerClient>(relaxed = true),
            fields = arrayOf("apiClient" to apiClient),
        )
        setField(wallet, "cachedWia", fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "jkt-self", attestationSource = null))
        setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)

        val instances = wallet.listWalletInstances()

        assertEquals("jkt-self", wallet.thisInstanceId)
        assertTrue(instances.first { it.id == "jkt-self" }.isThisDevice)
        assertEquals(false, instances.first { it.id == "jkt-other" }.isThisDevice)
        // The thumbprint was already known, so no attestation round trip.
        coVerify(exactly = 0) { apiClient.requestWIAChallenge() }
    }

    /**
     * A `credential_id` the backend refuses as not the caller's own would,
     * if the SDK gave up, leave this instance with no attestation at all -
     * and the first link recorded for an instance wins, so guessing another
     * id could lock the real passkey out of the per-device gate for good.
     * Retry once without the link and drop the stale id.
     */
    @Test
    fun wia_generation_retries_without_the_passkey_link_when_the_backend_refuses_it() = runTest(dispatcher) {
        val sessionStore = mockk<SessionStore>(relaxed = true)
        every { sessionStore.instanceKeyId } returns "instance-key-1"
        every { sessionStore.credentialId } returns "stale-passkey"
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery {
            keystore.generateKeyProof(keyId = any(), typ = any(), issuer = any(), audience = any(), extraClaims = any())
        } returns "pop-jwt"
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.requestWIAChallenge() } returns buildJsonObject { put("challenge", "chal-1") }
        coEvery {
            apiClient.generateWIA(any(), "chal-1", any(), any(), "stale-passkey")
        } throws BackendApiException(403, "API request failed: 403", """{"error":"CREDENTIAL_NOT_OWNED"}""")
        val wiaJwt = fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "jkt-self", attestationSource = null)
        coEvery { apiClient.generateWIA(any(), "chal-1", any(), any(), null) } returns wiaJwt

        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "sessionStore" to sessionStore,
            "keystore" to keystore,
            "apiClient" to apiClient,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                redirectUri = "siros-sample://callback",
            ),
            "json" to Json { ignoreUnknownKeys = true },
        )

        val method = wallet::class.declaredMemberFunctions.first { it.name == "ensureWalletInstanceAttestation" }
        method.isAccessible = true
        val wia = kotlinx.coroutines.runBlocking { method.callSuspend(wallet) }

        assertEquals(wiaJwt, wia)
        verify(exactly = 1) { sessionStore.credentialId = null }
        coVerify(exactly = 1) { apiClient.generateWIA(any(), "chal-1", any(), any(), "stale-passkey") }
        coVerify(exactly = 1) { apiClient.generateWIA(any(), "chal-1", any(), any(), null) }
    }

    /** A listener that records the lifecycle callbacks under test. */
    private class RecordingLifecycleListener : WalletEventListener {
        var reauthenticationRequired = false
        var blocked: Pair<WalletLifecycleRefusal, String?>? = null
        override suspend fun onCredentialSelectionRequired(request: PresentationRequest): List<Long> = emptyList()
        override fun onReauthenticationRequired() { reauthenticationRequired = true }
        override fun onWalletLifecycleBlocked(reason: WalletLifecycleRefusal, message: String?) {
            blocked = reason to message
        }
    }

    private fun lifecycleAccountRegistry(): AccountRegistry {
        val account = CachedAccount(
            userId = "user-1",
            tenantId = "default",
            displayName = "Alice",
            backendUrl = "https://wallet.example.com",
            passkeys = listOf(CachedPasskey(credentialId = "cred-1", prfSalt = "c2FsdA==")),
        )
        val registry = mockk<AccountRegistry>(relaxed = true)
        every { registry.listAccounts() } returns listOf(account)
        every { registry.listLoginableAccounts() } returns listOf(account)
        every { registry.findAccount(any()) } returns account
        every { registry.activeAccountId } returns "default:user-1"
        return registry
    }

    /**
     * A wallet wired for the lifecycle paths: NEW_AS mode (so `login()` goes
     * straight to the AS instead of probing for the legacy backend) and every
     * collaborator those paths touch.
     */
    private fun lifecycleWallet(
        stateFlow: MutableStateFlow<WalletState>,
        accountRegistry: AccountRegistry,
        authServerClient: AuthServerClient,
        listener: WalletEventListener? = null,
        vararg fields: Pair<String, Any?>,
    ): SirosWallet {
        val values = mutableMapOf<String, Any?>(
            "_state" to stateFlow,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "accountRegistry" to accountRegistry,
            "authServerClient" to authServerClient,
            "sessionStore" to mockk<SessionStore>(relaxed = true),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                redirectUri = "siros-sample://callback",
            ),
            "json" to Json { ignoreUnknownKeys = true },
        )
        if (listener != null) values["eventListener"] = listener
        fields.forEach { (name, value) -> values[name] = value }
        val wallet = newWallet(*values.toList().toTypedArray())
        setField(wallet, "authMode", authModeNewAs())
        return wallet
    }

    /** `SirosWallet.AuthMode.NEW_AS` — a private nested enum. */
    private fun authModeNewAs(): Any =
        Class.forName("org.siros.sdk.wallet.SirosWallet\$AuthMode")
            .enumConstants
            .first { (it as Enum<*>).name == "NEW_AS" }

    /** [SirosWallet.handleLifecycleRefusal] is a private suspend function. */
    private suspend fun invokePrivateBoolean(
        target: Any,
        name: String,
        arg: Throwable?,
        accountId: String? = null,
    ): Boolean {
        val method = target::class.declaredMemberFunctions.first { it.name == name }
        method.isAccessible = true
        return method.callSuspend(target, arg, accountId) as Boolean
    }

    private fun invokePrivate(target: Any, name: String) {
        val method = target.javaClass.getDeclaredMethod(name)
        method.isAccessible = true
        method.invoke(target)
    }

    /**
     * The behaviour that actually matters, end to end: a credential accepted
     * *because* the `vct#integrity` heal found the issuer's document must be
     * **stored described by that document**, not by the stale one the flow had
     * resolved before issuance.
     *
     * Checking only what `verifyVctIntegrity` returns would pass even if the
     * flow-completion path ignored it and built the metadata from
     * `activeVctm` - which is precisely the regression this guards, and the
     * shape the bug in #191 took in the first place.
     */
    @Test
    fun flowComplete_stores_the_credential_described_by_the_healed_document() = runTest(dispatcher) {
        val issuersDocument =
            """{"vct":"urn:eudi:pid:1","display":[{"locale":"en-US","name":"PID"}]}"""
        val staleDocument =
            """{"vct":"urn:eudi:pid:1","display":[{"locale":"en-US","name":"PID (old)"}]}"""
        val pin = "sha256-" + java.util.Base64.getEncoder().encodeToString(
            java.security.MessageDigest.getInstance("SHA-256").digest(issuersDocument.toByteArray()),
        )
        val payload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            """{"vct":"urn:eudi:pid:1","vct#integrity":"$pin","exp":9999999999}"""
                .toByteArray(Charsets.UTF_8),
        )
        val credential = "eyJhbGciOiJub25lIn0.$payload."

        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.isUnlocked } returns true
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        mockEngineConstructor(flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1",
                    displayName = "Alice",
                    flowId = "flow-heal",
                    flowType = "issuance",
                    status = "in_progress",
                    credentials = emptyList(),
                )
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to mockk<SessionStore>(relaxed = true),
            "apiClient" to apiClient,
            // What the flow resolved before issuance: the stale document.
            "activeVctmDocument" to org.siros.sdk.credentials.VctmDocument(
                raw = staleDocument,
                vctm = Json { ignoreUnknownKeys = true }
                    .decodeFromString(org.siros.sdk.credentials.Vctm.serializer(), staleDocument),
            ),
            "activeVctm" to Json { ignoreUnknownKeys = true }
                .decodeFromString(org.siros.sdk.credentials.Vctm.serializer(), staleDocument),
            "activeOffer" to org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid_1",
                credentialIssuerIdentifier = "https://issuer.example",
                credentialName = "PID from the offer",
                issuerName = "Issuer",
                vct = "urn:eudi:pid:1",
            ),
            // Every source serves the document the issuer actually signed over.
            "vctmFetcher" to org.siros.sdk.credentials.VctmFetcher(httpGet = { issuersDocument }),
        )

        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(
                flowId = "flow-heal",
                credentials = listOf(CredentialResult(format = "dc+sd-jwt", credential = credential)),
            )
        )
        // The re-resolution hops to Dispatchers.IO, which the test scheduler
        // does not control, so advanceUntilIdle() alone can return before it -
        // same wait as requestAttestation_includesNativeAttestation's.
        repeat(20) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            advanceUntilIdle()
        }

        val stored = store.getAll()
        assertEquals("the credential is accepted: the pinned document was found", 1, stored.size)
        assertEquals(
            "stored with the document the issuer pinned, not the stale one it would have been named by",
            "PID",
            stored.first().metadata?.name,
        )
    }

    private fun newWallet(vararg fields: Pair<String, Any?>): SirosWallet {
        val wallet = allocateInstance(SirosWallet::class.java) as SirosWallet
        val values = fields.toMap(mutableMapOf())
        val stateFlow = values["_state"] as? MutableStateFlow<WalletState>
        if (stateFlow != null && "state" !in values) {
            values["state"] = stateFlow.asStateFlow()
        }
        if ("terminatedFlowIds" !in values) {
            values["terminatedFlowIds"] = mutableSetOf<String>()
        }
        // allocateInstance bypasses property initializers entirely, so
        // pendingMatchResultsByFlow's default (empty map) never runs unless
        // set here explicitly - without this, any collector that touches it
        // (match_request/sign_presentation/flow_complete/flow_errors) NPEs.
        if ("pendingMatchResultsByFlow" !in values) {
            values["pendingMatchResultsByFlow"] = mutableMapOf<String, List<CredentialMatcher.MatchResult>>()
        }
        // allocateInstance bypasses property initializers entirely, so
        // credentialConsumptionPolicy's default (NEVER_CONSUME) never runs
        // unless set here explicitly - matches every existing test's
        // expectation of today's actual (pre-this-feature) behavior.
        // Same reason as pendingMatchResultsByFlow above: allocateInstance
        // skips the initializer, and every terminal issuance path
        // (flow_complete/flow_error/reportSignFailure/cancelCurrentFlow)
        // now discards this flow's ZK issuance preparation, so a null map
        // NPEs there.
        if ("zkPreparationsByFlow" !in values) {
            values["zkPreparationsByFlow"] =
                java.util.concurrent.ConcurrentHashMap<String, org.siros.sdk.credentials.ZkIssuancePreparation>()
        }
        if ("credentialConsumptionPolicy" !in values) {
            values["credentialConsumptionPolicy"] = CredentialConsumptionPolicy.NEVER_CONSUME
        }
        values.forEach { (name, value) -> setField(wallet, name, value) }
        // allocateInstance bypasses property initializers entirely, so a
        // `by lazy { ... }` property's synthetic backing field (a Lazy<T>,
        // not the computed value itself) is never initialized either -
        // touching readerTrustRootCertificates/issuerTrustRootCertificates
        // without this NPEs with "Cannot invoke Lazy.getValue() because ...
        // is null", not a normal lazy-recompute. Force each one to its
        // usual empty-config default here so evaluateReaderTrust/
        // evaluateIssuerTrust's local-fallback path is actually reachable
        // in tests; a test that needs non-empty roots overrides the
        // delegate field directly instead.
        if ("issuerTrustRootCertificates\$delegate" !in values) {
            setField(wallet, "issuerTrustRootCertificates\$delegate", lazy { emptyList<java.security.cert.X509Certificate>() })
        }
        if ("readerTrustRootCertificates\$delegate" !in values) {
            setField(wallet, "readerTrustRootCertificates\$delegate", lazy { emptyList<java.security.cert.X509Certificate>() })
        }
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

    private fun invokeHandleTrustEvaluation(
        wallet: SirosWallet,
        engine: WalletEngineSession,
        flowId: String,
        payload: JsonObject,
    ) {
        val method = wallet.javaClass.getDeclaredMethod(
            "handleTrustEvaluation",
            WalletEngineSession::class.java,
            String::class.java,
            JsonObject::class.java,
        )
        method.isAccessible = true
        method.invoke(wallet, engine, flowId, payload)
    }

    private fun invokeCurrentWalletInstanceId(wallet: SirosWallet): String? {
        val method = wallet::class.declaredMemberFunctions.first { it.name == "currentWalletInstanceId" }
        method.isAccessible = true
        return method.call(wallet) as String?
    }

    private fun invokeConnectEngine(wallet: SirosWallet, appToken: String) {
        // connectEngine is a private suspend fun — use Kotlin reflection's callSuspend
        val method = wallet::class.declaredMemberFunctions.first { it.name == "connectEngine" }
        method.isAccessible = true
        kotlinx.coroutines.runBlocking {
            method.callSuspend(wallet, appToken)
        }
    }

    /** DCQL asking for one SD-JWT VC type, as the engine relays it over WMP. */
    private fun vctQueryPayload(vct: String): JsonObject = buildJsonObject {
        putJsonObject("dcql_query") {
            putJsonArray("credentials") {
                add(buildJsonObject {
                    put("id", "q-vct")
                    put("format", "dc+sd-jwt")
                    putJsonObject("meta") {
                        putJsonArray("vct_values") { add(JsonPrimitive(vct)) }
                    }
                })
            }
        }
    }

    private fun invokeWmpMatchRequest(
        wallet: SirosWallet,
        flowId: String,
        payload: JsonObject,
    ): org.siros.sdk.transport.wmp.openid4x.MatchResult {
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpMatchRequest" }
        method.isAccessible = true
        return kotlinx.coroutines.runBlocking {
            method.callSuspend(wallet, flowId, payload)
        } as org.siros.sdk.transport.wmp.openid4x.MatchResult
    }

    private fun mockEngineConstructor(
        signRequests: MutableSharedFlow<SignRequestMessage> = MutableSharedFlow(),
        matchRequests: MutableSharedFlow<MatchRequestMessage> = MutableSharedFlow(),
        progressFlow: MutableSharedFlow<FlowProgressMessage> = MutableSharedFlow(),
        flowComplete: MutableSharedFlow<FlowCompleteMessage> = MutableSharedFlow(),
        flowErrors: MutableSharedFlow<FlowErrorMessage> = MutableSharedFlow(),
    ): WalletEngineSession {
        val engine = mockk<WalletEngineSession>()
        every { engine.connect(any(), any(), any()) } just runs
        coEvery { engine.awaitConnected(any()) } just runs
        coEvery { engine.forceReconnect() } just runs
        every { engine.state } returns MutableStateFlow(WalletEngineSession.State.CONNECTED)
        every { engine.sendSignResponse(any(), any(), any(), any()) } just runs
        every { engine.sendMatchResponse(any(), any(), any()) } just runs
        every { engine.sendCredentialsMatched(any(), any(), any()) } just runs
        every { engine.sendFlowAction(any(), any(), any()) } just runs
        every { engine.signRequests() } returns signRequests
        every { engine.matchRequests() } returns matchRequests
        every { engine.flowProgress() } returns progressFlow
        every { engine.flowComplete() } returns flowComplete
        every { engine.flowErrors() } returns flowErrors
        SirosWallet.createEngineSession = { _, _ -> engine }
        return engine
    }

    private fun allocateInstance(clazz: Class<*>): Any {
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val unsafeField = unsafeClass.getDeclaredField("theUnsafe")
        unsafeField.isAccessible = true
        val unsafe = unsafeField.get(null)
        val allocateInstance = unsafeClass.getMethod("allocateInstance", Class::class.java)
        return allocateInstance.invoke(unsafe, clazz)
    }

    private class FakeCredentialStore(
        private val credentials: MutableList<StoredCredential>,
        /** When set, [save] throws it instead of storing — a host store that refuses. */
        private val saveFailure: Exception? = null,
    ) : CredentialStore {
        override suspend fun getAll(): List<StoredCredential> = credentials.toList()

        override suspend fun getById(id: Long): StoredCredential? = credentials.find { it.id == id }

        override suspend fun save(credential: StoredCredential) {
            saveFailure?.let { throw it }
            credentials.removeAll { it.id == credential.id }
            credentials.add(credential)
        }

        override suspend fun update(credential: StoredCredential) {
            save(credential)
        }

        override suspend fun delete(id: Long) {
            credentials.removeAll { it.id == id }
        }

        override suspend fun clear() {
            credentials.clear()
        }
    }

    companion object
}
