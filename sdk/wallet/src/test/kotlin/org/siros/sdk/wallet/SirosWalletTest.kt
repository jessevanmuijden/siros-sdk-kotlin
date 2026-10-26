package org.siros.sdk.wallet

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.coVerifyOrder
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
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlin.reflect.full.callSuspend
import kotlin.reflect.full.declaredMemberFunctions
import kotlin.reflect.jvm.isAccessible
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.TestScope
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
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
import org.siros.sdk.credentials.interop.HolderBinding
import org.siros.sdk.credentials.interop.InteropProfile
import org.siros.sdk.credentials.TransactionDataError
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
import org.siros.sdk.transport.engine.IssuerTrustReport
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
        // Every czkSetup wallet's scope records what escapes a launch (its scope has no other handler, like the real one): an
        // unexpected failure of a signing coroutine fails the test that caused it, not only the two that inspect the recorder.
        val escaped = czkUncaught.toList()
        czkUncaught.clear()
        assertTrue("an exception escaped a wallet coroutine: $escaped", escaped.isEmpty())
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
    fun deleteCredential_unsupportedSchemaVersion_persistsAndUploadsNothingAndIsReported() = runBlocking {
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        val listener = mockk<WalletEventListener>(relaxed = true)
        val existing = """{"prfKeys":[],"jwe":"existing"}"""
        every { keystore.isUnlocked } returns true
        every { sessionStore.privateDataJwe } returns existing
        coEvery { keystore.exportEncryptedContainer() } throws
            org.siros.sdk.credentials.UnsupportedSchemaVersionException(
                "S.schemaVersion 5", org.siros.sdk.credentials.UnsupportedSchemaVersionException.Kind.STATE_VERSION, 5,
            )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
        )

        wallet.deleteCredential(999L)

        verify(exactly = 0) { sessionStore.privateDataJwe = any() }
        coVerify(exactly = 0) { apiClient.updatePrivateData(any()) }
        verify(exactly = 1) { listener.onFlowError("sync", match { it.contains("does not support") }, null) }
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
    fun handleTrustEvaluation_resourceIdEqualsSubjectId_forEveryVerifierIdentityShape() = runTest(dispatcher) {
        // go-trust refuses a full evaluation whose resource.id differs from subject.id (a 502 from the backend proxy), so the
        // verifier-trust request the zkp_req redirect route depends on must carry the SAME id in both, prefixed or not.
        for (subject in listOf("x509_san_dns:rp.example", "decentralized_identifier:did:web:rp.example", "https://rp.example/verifier", "verifier-123")) {
            val engine = mockk<WalletEngineSession>(relaxed = true)
            val apiClient = mockk<BackendApiClient>()
            val request = slot<JsonObject>()
            coEvery { apiClient.evaluateTrust(capture(request)) } returns buildJsonObject { put("decision", true) }
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "apiClient" to apiClient,
                "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            )
            invokeHandleTrustEvaluation(
                wallet, engine, "flow-id",
                buildJsonObject {
                    putJsonObject("request") {
                        put("subject_id", subject)
                        put("subject_type", "credential_verifier")
                        putJsonObject("key_material") {
                            put("type", "x5c")
                            putJsonArray("x5c") { add(JsonPrimitive("cert-1")) }
                        }
                    }
                },
            )
            advanceUntilIdle()
            val sid = request.captured["subject"]!!.jsonObject["id"]?.jsonPrimitive?.content
            assertEquals(subject, sid)
            assertEquals(subject, sid?.let { request.captured["resource"]!!.jsonObject["id"]?.jsonPrimitive?.content })
        }
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

    @Test
    fun handleTrustEvaluation_whenTheSocketRefusesTheFailureReply_nothingEscapesTheLaunch() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        every { engine.sendTrustResult(any(), any(), any()) } throws IllegalStateException("Not connected")
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws IllegalStateException("trust backend offline")
        val escaped = mutableListOf<Throwable>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob() + kotlinx.coroutines.CoroutineExceptionHandler { _, e -> escaped += e }),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        )
        invokeHandleTrustEvaluation(
            wallet, engine, "flow-refused",
            buildJsonObject { putJsonObject("request") { put("subject_id", "x"); put("subject_type", "credential_issuer"); putJsonObject("key_material") { put("type", "x5c"); putJsonArray("x5c") { add(JsonPrimitive("c")) } } } },
        )
        advanceUntilIdle()
        verify(exactly = 1) { engine.sendTrustResult("flow-refused", false, "trust backend offline") }
        assertEquals(emptyList<Throwable>(), escaped)
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
            put("decision", true)
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
                    put("resolution_subject_id", "did:web:verifier.example.com")
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
     * Regression (review finding): /v1/resolve is itself an AuthZEN
     * evaluation - a denied response (decision: false) can still carry
     * trust_metadata (populated independently of the decision), so a
     * genuinely-verifying signature must NOT be enough on its own; the
     * decision must be explicit true too, mirroring go-wallet-backend's own
     * ResolveDID path.
     */
    @Test
    fun handleTrustEvaluation_fails_closed_when_resolve_decision_is_not_true() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val verifierKey = ECKeyGenerator(Curve.P_256).keyID("did:web:verifier.example.com#key-1").generate()
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:verifier.example.com#key-1").build(),
            JWTClaimsSet.Builder().claim("client_id", "did:web:verifier.example.com").build(),
        )
        signedJwt.sign(ECDSASigner(verifierKey))

        coEvery { apiClient.resolveKey("did:web:verifier.example.com") } returns buildJsonObject {
            put("decision", false)
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:verifier.example.com#key-1")
                            put("publicKeyJwk", Json.parseToJsonElement(verifierKey.toPublicJWK().toJSONString()))
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
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-denied",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", signedJwt.serialize())
                    put("resolution_subject_id", "did:web:verifier.example.com")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) {
            engine.sendTrustResult(
                "flow-denied",
                false,
                match { it != null && it.contains("not decided true") },
            )
        }
    }

    /**
     * Regression (review finding): a DID ISSUER's requires_resolution
     * carries no request_jwt at all - OID4VCI issuance has no signed
     * request object to verify one against. Unconditionally requiring
     * request_jwt (as an earlier version of this fix did) rejected every
     * DID issuer before ever calling /v1/resolve.
     */
    @Test
    fun handleTrustEvaluation_resolves_issuer_did_key_material_without_request_jwt() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val issuerKey = ECKeyGenerator(Curve.P_256).keyID("did:web:issuer.example.com#key-1").generate()

        coEvery { apiClient.resolveKey("did:web:issuer.example.com") } returns buildJsonObject {
            put("decision", true)
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:issuer.example.com#key-1")
                            put("publicKeyJwk", Json.parseToJsonElement(issuerKey.toPublicJWK().toJSONString()))
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
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-issuer",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:issuer.example.com")
                    put("subject_type", "credential_issuer")
                    put("requires_resolution", true)
                    put("resolution_subject_id", "did:web:issuer.example.com")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { apiClient.resolveKey("did:web:issuer.example.com") }
        val capturedResource = slot<JsonObject>()
        coVerify(exactly = 1) {
            apiClient.evaluateTrust(match { request ->
                capturedResource.captured = request["resource"] as JsonObject
                request["resource"]?.toString()?.contains("\"type\":\"jwk\"") == true
            })
        }
        // resolveIssuerDidKeyMaterial's array must be forwarded as a FLAT
        // jwk array (one entry per resolved verification method), never
        // wrapped in another array of one the way a single verifier jwk is
        // (review finding: this test previously only checked resource.type,
        // so it would still pass if the jwk were omitted or nested wrong).
        val keyArray = capturedResource.captured["key"] as JsonArray
        assertEquals(1, keyArray.size)
        assertEquals("EC", (keyArray[0] as JsonObject)["kty"]?.jsonPrimitive?.contentOrNull)
        verify(exactly = 1) { engine.sendTrustResult("flow-issuer", true, null) }
    }

    /**
     * Regression (review finding): resolveIssuerDidKeyMaterial duplicates
     * the security-critical decision check resolveDidKeyMaterial already
     * has its own test for - without a DEDICATED issuer-path test, removing
     * or weakening that check in the issuer branch specifically would
     * leave every issuer test green.
     */
    @Test
    fun handleTrustEvaluation_fails_closed_when_issuer_resolve_decision_is_not_true() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val issuerKey = ECKeyGenerator(Curve.P_256).keyID("did:web:issuer.example.com#key-1").generate()

        coEvery { apiClient.resolveKey("did:web:issuer.example.com") } returns buildJsonObject {
            put("decision", false)
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:issuer.example.com#key-1")
                            put("publicKeyJwk", Json.parseToJsonElement(issuerKey.toPublicJWK().toJSONString()))
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
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-issuer-denied",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:issuer.example.com")
                    put("subject_type", "credential_issuer")
                    put("requires_resolution", true)
                    put("resolution_subject_id", "did:web:issuer.example.com")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) {
            engine.sendTrustResult(
                "flow-issuer-denied",
                false,
                match { it != null && it.contains("not decided true") },
            )
        }
    }

    /**
     * Same coverage as
     * [handleTrustEvaluation_resolves_issuer_did_key_material_without_request_jwt]
     * but for the WMP transport's handleWmpTrustEvaluation, which never had
     * requires_resolution/request_jwt/resolution_subject_id support at all
     * (review finding) - a did:-scheme subject routed over WMP
     * (WalletConfig.useWmpProtocol) silently evaluated with no key material.
     */
    @Test
    fun handleWmpTrustEvaluation_resolves_issuer_did_key_material_without_request_jwt() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val issuerKey = ECKeyGenerator(Curve.P_256).keyID("did:web:issuer.example.com#key-1").generate()

        coEvery { apiClient.resolveKey("did:web:issuer.example.com") } returns buildJsonObject {
            put("decision", true)
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:issuer.example.com#key-1")
                            put("publicKeyJwk", Json.parseToJsonElement(issuerKey.toPublicJWK().toJSONString()))
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
        )

        val result = invokeHandleWmpTrustEvaluation(
            wallet,
            "flow-wmp-issuer",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:issuer.example.com")
                    put("subject_type", "credential_issuer")
                    put("requires_resolution", true)
                    put("resolution_subject_id", "did:web:issuer.example.com")
                }
            }
        )

        coVerify(exactly = 1) { apiClient.resolveKey("did:web:issuer.example.com") }
        val capturedResource = slot<JsonObject>()
        coVerify(exactly = 1) {
            apiClient.evaluateTrust(match { request ->
                capturedResource.captured = request["resource"] as JsonObject
                request["resource"]?.toString()?.contains("\"type\":\"jwk\"") == true
            })
        }
        // Same review finding as the legacy-engine issuer test: assert the
        // FLAT jwk array shape, not just resource.type.
        val keyArray = capturedResource.captured["key"] as JsonArray
        assertEquals(1, keyArray.size)
        assertEquals("EC", (keyArray[0] as JsonObject)["kty"]?.jsonPrimitive?.contentOrNull)
        assertTrue(result.trusted)
    }

    /**
     * Regression (review finding): the WMP transport's
     * handleWmpTrustEvaluation had no VERIFIER-path resolution coverage at
     * all (only the issuer path above) - proves request_jwt is required,
     * the kid-selected resolved jwk is forwarded to /v1/evaluate, and the
     * result is trusted.
     */
    @Test
    fun handleWmpTrustEvaluation_resolves_verifier_did_key_material_with_request_jwt() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val verifierKey = ECKeyGenerator(Curve.P_256).keyID("did:web:verifier.example.com#key-1").generate()
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:verifier.example.com#key-1").build(),
            JWTClaimsSet.Builder().claim("client_id", "did:web:verifier.example.com").build(),
        )
        signedJwt.sign(ECDSASigner(verifierKey))

        coEvery { apiClient.resolveKey("did:web:verifier.example.com") } returns buildJsonObject {
            put("decision", true)
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:verifier.example.com#key-1")
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
        )

        val result = invokeHandleWmpTrustEvaluation(
            wallet,
            "flow-wmp-verifier",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", signedJwt.serialize())
                    put("resolution_subject_id", "did:web:verifier.example.com")
                }
            }
        )

        coVerify(exactly = 1) { apiClient.resolveKey("did:web:verifier.example.com") }
        coVerify(exactly = 1) {
            apiClient.evaluateTrust(match { request ->
                request["resource"]?.toString()?.contains("\"type\":\"jwk\"") == true
            })
        }
        assertTrue(result.trusted)
    }

    @Test
    fun handleWmpTrustEvaluation_fails_closed_when_verifier_requires_resolution_but_no_request_jwt() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        )

        val result = invokeHandleWmpTrustEvaluation(
            wallet,
            "flow-wmp-verifier-no-jwt",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("resolution_subject_id", "did:web:verifier.example.com")
                }
            }
        )

        coVerify(exactly = 0) { apiClient.resolveKey(any()) }
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        assertFalse(result.trusted)
        assertTrue(result.reason?.contains("request_jwt") == true)
    }

    @Test
    fun handleWmpTrustEvaluation_fails_closed_when_resolve_decision_is_not_true() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val verifierKey = ECKeyGenerator(Curve.P_256).keyID("did:web:verifier.example.com#key-1").generate()
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:verifier.example.com#key-1").build(),
            JWTClaimsSet.Builder().claim("client_id", "did:web:verifier.example.com").build(),
        )
        signedJwt.sign(ECDSASigner(verifierKey))

        coEvery { apiClient.resolveKey("did:web:verifier.example.com") } returns buildJsonObject {
            put("decision", false)
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:verifier.example.com#key-1")
                            put("publicKeyJwk", Json.parseToJsonElement(verifierKey.toPublicJWK().toJSONString()))
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
        )

        val result = invokeHandleWmpTrustEvaluation(
            wallet,
            "flow-wmp-denied",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", signedJwt.serialize())
                    put("resolution_subject_id", "did:web:verifier.example.com")
                }
            }
        )

        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        assertFalse(result.trusted)
        assertTrue(result.reason?.contains("not decided true") == true)
    }

    /**
     * go-wallet-backend#401's resolution_subject_id carries the bare DID for
     * /v1/resolve, distinct from subject_id - which, for an OpenID4VP 1.0
     * `decentralized_identifier:`-prefixed client_id, is NOT itself a
     * resolvable DID. Passing subject_id to /v1/resolve here would send the
     * still-prefixed value and fail to resolve; evaluateTrust must still see
     * the unstripped subject_id, unchanged.
     */
    @Test
    fun handleTrustEvaluation_uses_resolution_subject_id_not_subject_id() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val verifierKey = ECKeyGenerator(Curve.P_256).keyID("did:web:verifier.example.com#key-1").generate()
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:verifier.example.com#key-1").build(),
            JWTClaimsSet.Builder().claim("client_id", "did:web:verifier.example.com").build(),
        )
        signedJwt.sign(ECDSASigner(verifierKey))

        coEvery { apiClient.resolveKey("did:web:verifier.example.com") } returns buildJsonObject {
            put("decision", true)
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:verifier.example.com#key-1")
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
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-did-prefixed",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "decentralized_identifier:did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", signedJwt.serialize())
                    put("resolution_subject_id", "did:web:verifier.example.com")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { apiClient.resolveKey("did:web:verifier.example.com") }
        coVerify(exactly = 1) {
            apiClient.evaluateTrust(match { request ->
                request["subject"]?.toString()?.contains("decentralized_identifier:did:web:verifier.example.com") == true
            })
        }
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
            put("decision", true)
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
                    put("resolution_subject_id", "did:web:verifier.example.com")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 1) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) { engine.sendTrustResult("flow-did-eddsa", true, null) }
    }

    /**
     * Regression (review finding): the JWT's kid names ONE specific
     * verification method (#key-1), but a DIFFERENT method in the SAME
     * resolved document (#key-2) actually signed it. This must fail closed
     * - key-2 must never be tried as a fallback just because it's also
     * present in the document. Trying every remaining method here would
     * accept a signature under a method the kid never named.
     */
    @Test
    fun handleTrustEvaluation_fails_closed_when_signature_verifies_under_a_different_method_than_kid() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val key1 = ECKeyGenerator(Curve.P_256).keyID("did:web:verifier.example.com#key-1").generate()
        val key2 = ECKeyGenerator(Curve.P_256).keyID("did:web:verifier.example.com#key-2").generate()
        // Signed by key2, but the header's kid names key1.
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:verifier.example.com#key-1").build(),
            JWTClaimsSet.Builder().claim("client_id", "did:web:verifier.example.com").build(),
        )
        signedJwt.sign(ECDSASigner(key2))

        coEvery { apiClient.resolveKey("did:web:verifier.example.com") } returns buildJsonObject {
            put("decision", true)
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:verifier.example.com#key-1")
                            put("publicKeyJwk", Json.parseToJsonElement(key1.toPublicJWK().toJSONString()))
                        }
                        addJsonObject {
                            put("id", "did:web:verifier.example.com#key-2")
                            put("publicKeyJwk", Json.parseToJsonElement(key2.toPublicJWK().toJSONString()))
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
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-kid-mismatch",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", signedJwt.serialize())
                    put("resolution_subject_id", "did:web:verifier.example.com")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) {
            engine.sendTrustResult(
                "flow-kid-mismatch",
                false,
                match { it != null && it.contains("kid-matching") },
            )
        }
    }

    /**
     * Regression (review finding): comparing ONLY the fragment (after `#`)
     * lets `did:other#key-1` and `did:subject#key-1` collide - a resolved
     * document containing a verification method for a DIFFERENT DID with
     * the SAME fragment as the kid must not be matched. Only the full,
     * normalized id may match.
     */
    @Test
    fun handleTrustEvaluation_fails_closed_when_fragment_matches_a_different_dids_verification_method() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val otherDidKey = ECKeyGenerator(Curve.P_256).keyID("did:web:other.example.com#key-1").generate()
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID("did:web:verifier.example.com#key-1").build(),
            JWTClaimsSet.Builder().claim("client_id", "did:web:verifier.example.com").build(),
        )
        signedJwt.sign(ECDSASigner(otherDidKey))

        // The resolved document for did:web:verifier.example.com contains
        // ONLY a verification method belonging to a DIFFERENT DID
        // (did:web:other.example.com) that happens to share the "#key-1"
        // fragment - a real document would never legitimately do this, but
        // a fragment-only comparison would still match it.
        coEvery { apiClient.resolveKey("did:web:verifier.example.com") } returns buildJsonObject {
            put("decision", true)
            putJsonObject("context") {
                putJsonObject("trust_metadata") {
                    putJsonArray("verificationMethod") {
                        addJsonObject {
                            put("id", "did:web:other.example.com#key-1")
                            put("publicKeyJwk", Json.parseToJsonElement(otherDidKey.toPublicJWK().toJSONString()))
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
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-fragment-collision",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", signedJwt.serialize())
                    put("resolution_subject_id", "did:web:verifier.example.com")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) {
            engine.sendTrustResult(
                "flow-fragment-collision",
                false,
                match { it != null && it.contains("No verification method") },
            )
        }
    }

    /**
     * Regression (review finding): a request_jwt with no kid at all must be
     * rejected outright, not resolved against an arbitrary/first
     * verification method.
     */
    @Test
    fun handleTrustEvaluation_fails_closed_when_request_jwt_has_no_kid() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val verifierKey = ECKeyGenerator(Curve.P_256).keyID(null).generate()
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).build(),
            JWTClaimsSet.Builder().claim("client_id", "did:web:verifier.example.com").build(),
        )
        signedJwt.sign(ECDSASigner(verifierKey))

        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-no-kid",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", signedJwt.serialize())
                    put("resolution_subject_id", "did:web:verifier.example.com")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { apiClient.resolveKey(any()) }
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) {
            engine.sendTrustResult(
                "flow-no-kid",
                false,
                match { it != null && it.contains("kid") },
            )
        }
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
            put("decision", true)
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
                    put("resolution_subject_id", "did:web:verifier.example.com")
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
                    put("resolution_subject_id", "did:web:verifier.example.com")
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

    /**
     * Regression: go-wallet-backend#401's own TrustEvaluationRequest.Validate()
     * makes resolution_subject_id mandatory whenever requires_resolution is
     * true, so an engine that omits it is itself non-conformant - falling
     * back to the (possibly decentralized_identifier:-prefixed) subject_id
     * would silently attempt resolution with the wrong identifier instead of
     * surfacing that clearly.
     */
    @Test
    fun handleTrustEvaluation_fails_closed_when_requires_resolution_but_no_resolution_subject_id() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        )

        invokeHandleTrustEvaluation(
            wallet,
            engine,
            "flow-did-missing-resolution-subject-id",
            buildJsonObject {
                putJsonObject("request") {
                    put("subject_id", "decentralized_identifier:did:web:verifier.example.com")
                    put("subject_type", "credential_verifier")
                    put("requires_resolution", true)
                    put("request_jwt", "header.payload.sig")
                }
            }
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { apiClient.resolveKey(any()) }
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
        verify(exactly = 1) {
            engine.sendTrustResult(
                "flow-did-missing-resolution-subject-id",
                false,
                match { it != null && it.contains("resolution_subject_id") },
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
     * The whole resumption after the browser: the authorization step hands off, the app comes back with a code, the engine
     * WebSocket is reconnected, ONE stateless flow_start is sent, and the engine completes the issuance under a NEW flow id.
     * The credential is stored and the completion is reported for the new id; the log names the reconnect and pairs the new
     * flow id with the one it resumed (and shows nothing secret).
     */
    @Test
    fun resumptionAfterTheBrowser_completesUnderANewFlowId_storesTheCredential_andLogsTheContinuation() = runTest(dispatcher) {
        val logs = mutableListOf<String>()
        val tree = object : timber.log.Timber.Tree() {
            override fun log(priority: Int, tag: String?, message: String, t: Throwable?) { logs += message }
        }
        timber.log.Timber.plant(tree)
        try {
            val progressFlow = MutableSharedFlow<FlowProgressMessage>()
            val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
            val listener = mockk<WalletEventListener>(relaxed = true)
            val keystore = org.siros.sdk.keystore.JweKeystore()
            keystore.unlock(ByteArray(32) { it.toByte() }, ByteArray(0), ByteArray(32) { 5 }, "info".toByteArray())
            val store = KeystoreMirroringStore(keystore, mirror = true)
            val sessionStore = mockk<SessionStore>(relaxed = true)
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            every { sessionStore.privateDataJwe } returns null
            coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
            val engine = mockEngineConstructor(progressFlow = progressFlow, flowComplete = completeFlow)
            every { engine.resumeIssuance(any(), any(), any(), any(), any()) } just runs
            every { engine.sendCredentialNotification(any(), any(), any(), any()) } just runs
            val resuming = java.util.concurrent.ConcurrentLinkedQueue<String>()
            val continuations = java.util.concurrent.ConcurrentHashMap<String, String>()
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", tenantId = "tenant-1", redirectUri = "siros://callback"),
                "credentialStore" to store,
                "keystore" to keystore,
                "sessionStore" to sessionStore,
                "apiClient" to apiClient,
                "eventListener" to listener,
                "pendingAuthorizations" to mutableMapOf<String, Any?>(),
                "resumingFlowIds" to resuming,
                "flowContinuations" to continuations,
                "json" to Json { ignoreUnknownKeys = true },
            )
            invokeConnectEngine(wallet, "app-token")
            advanceUntilIdle()
            progressFlow.emit(
                FlowProgressMessage(
                    flowId = "flow-old",
                    step = "authorization_required",
                    payload = buildJsonObject {
                        put("authorization_url", "https://issuer.example.com/auth?state=st-1")
                        put("expected_redirect_uri", "siros://callback")
                        put("state", "st-1")
                        put("code_verifier", "verifier-SECRET")
                        putJsonObject("credential_offer") { put("credential_issuer", "https://issuer.example.com") }
                    },
                ),
            )
            advanceUntilIdle()

            wallet.completeAuthorization(flowId = "flow-old", code = "auth-code-SECRET", state = "st-1")
            advanceUntilIdle()
            coVerify(exactly = 1) { engine.forceReconnect() }
            verify(exactly = 1) { engine.resumeIssuance(any(), any(), "siros://callback", "auth-code-SECRET", "verifier-SECRET") }
            assertEquals(listOf("flow-old"), resuming.toList())

            // The engine answers the stateless flow_start under a NEW flow id.
            completeFlow.emit(
                FlowCompleteMessage(
                    flowId = "flow-new",
                    credentials = listOf(CredentialResult(format = "dc+sd-jwt", credential = NymTestCredentials.sdJwt(sscValues = emptyList()), notificationId = "n-1")),
                ),
            )
            advanceUntilIdle()

            assertEquals(1, store.getAll().size)
            verify(exactly = 1) { listener.onFlowComplete("flow-new", any()) }
            verify(exactly = 0) { listener.onFlowError(any(), any(), any()) }
            assertEquals(mapOf("flow-new" to "flow-old"), continuations.toMap())
            assertTrue(resuming.isEmpty())
            assertTrue(logs.toString(), logs.any { it.contains("reconnecting the engine WebSocket") })
            assertTrue(logs.toString(), logs.any { it.contains("Engine WebSocket reconnected") })
            assertTrue(logs.toString(), logs.any { it.contains("Flow flow-old") && it.contains("NEW flow flow-new") })
            assertTrue(logs.toString(), logs.any { it.contains("Flow flow-new complete") && it.contains("resumption of flow flow-old") })
            // Neither the authorization code nor the code verifier is logged.
            logs.forEach { assertFalse(it, it.contains("SECRET")) }
        } finally {
            timber.log.Timber.uproot(tree)
        }
    }

    /** A failed reconnect leaves no continuation behind. */
    @Test
    fun resumptionAfterTheBrowser_aFailedReconnect_isReportedAndLeavesNoPendingContinuation() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        coEvery { engine.forceReconnect() } throws IllegalStateException("socket gone")
        val resuming = java.util.concurrent.ConcurrentLinkedQueue<String>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", tenantId = "tenant-1", redirectUri = "siros://callback"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
            "pendingAuthorizations" to mutableMapOf<String, Any?>(),
            "resumingFlowIds" to resuming,
            "flowContinuations" to java.util.concurrent.ConcurrentHashMap<String, String>(),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        progressFlow.emit(
            FlowProgressMessage(
                flowId = "flow-old", step = "authorization_required",
                payload = buildJsonObject {
                    put("authorization_url", "https://issuer.example.com/auth?state=st-1")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "st-1")
                },
            ),
        )
        advanceUntilIdle()
        wallet.completeAuthorization(flowId = "flow-old", code = "c", state = "st-1")
        advanceUntilIdle()
        verify(exactly = 1) { listener.onFlowError("flow-old", "socket gone", any()) }
        assertTrue(resuming.isEmpty())
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
        every { keystore.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
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
                authorizationDetails = any(),
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
        coEvery { defaultKeystore.isWscdOnboarded() } returns true
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
            verify(exactly = 1) {
            engine.startIssuance(
                offer = offerJson,
                credentialOfferUri = null,
                redirectUri = "siros-sample://callback",
                authorizationDetails = any(),
            )
        }
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
        verify(exactly = 1) {
            engine.startIssuance(
                offer = offerJson,
                credentialOfferUri = null,
                redirectUri = "siros-sample://callback",
                authorizationDetails = any(),
            )
        }
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

        verify(exactly = 2) {
            engine.startIssuance(
                offer = offerJson,
                credentialOfferUri = null,
                redirectUri = "siros-sample://callback",
                authorizationDetails = any(),
            )
        }
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
            every { keystore.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
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
                    authorizationDetails = any(),
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
            every { keystore.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
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
            every { keystore.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
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
        every { keystore.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
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

    // ---- sign_client_auth: a proof that was asked for and could not be made is never answered with a bare key id ----

    private val ca = StringBuilder()
    private val caTree = object : timber.log.Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
            if (priority >= android.util.Log.WARN) ca.append(message).append('\n')
        }
    }

    /** Runs one DPoP-only sign_client_auth against [keystore] and returns the (dpopKeyId, dpopProof) of the reply. */
    private suspend fun kotlinx.coroutines.test.TestScope.signClientAuthReply(
        keystore: KeystoreManager,
        keyIdHint: String? = null,
        config: WalletConfig = WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
        htm: String? = "POST",
        htu: String? = "https://as.example.com/token",
    ): Pair<String?, String?> {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        val replies = mutableListOf<Pair<String?, String?>>()
        every {
            engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } answers {
            replies += (args[8] as String?) to (args[9] as String?)
        }
        val sessionStore = mockk<SessionStore>(relaxed = true)
        every { sessionStore.instanceKeyId } returns "instance-key-1"
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "sessionStore" to sessionStore,
            "keystore" to keystore,
            "apiClient" to mockk<BackendApiClient>(relaxed = true),
            "config" to config,
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-x", messageId = "msg-x", action = "sign_client_auth",
                params = SignRequestParams(htm = htm, htu = htu, keyId = keyIdHint),
            ),
        )
        repeat(10) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(100) }
            advanceUntilIdle()
        }
        assertEquals("exactly one sign_response", 1, replies.size)
        return replies.single()
    }

    private fun caKeystore(unlocked: Boolean = true, proof: () -> String): KeystoreManager {
        val ks = mockk<KeystoreManager>(relaxed = true)
        every { ks.isUnlocked } returns unlocked
        every { ks.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
        coEvery { ks.generateDPoPProof(keyId = any(), htm = any(), htu = any(), nonce = any(), accessTokenHash = any()) } answers { proof() }
        return ks
    }

    @Test
    fun signClientAuth_success_namesTheKeyAndCarriesTheProof() = runTest(dispatcher) {
        val (keyId, proof) = signClientAuthReply(caKeystore { "dpop-jwt" })
        assertEquals("instance-key-1", keyId)
        assertEquals("dpop-jwt", proof)
    }

    @Test
    fun signClientAuth_aLockedKeystore_isAnsweredWithoutAKeyId_andLogsTheReason() = runTest(dispatcher) {
        timber.log.Timber.plant(caTree)
        try {
            val ks = caKeystore(unlocked = false) { throw org.siros.sdk.credentials.KeystoreException("Keystore is locked") }
            val (keyId, proof) = signClientAuthReply(ks, keyIdHint = "old-key")
            assertNull("a key id without a proof is the misleading 'no DPoP proof' error", keyId)
            assertNull(proof)
            assertTrue(ca.toString(), ca.contains("sign_client_auth for flow flow-x") && ca.contains("keystore_locked"))
            assertTrue(ca.toString(), ca.contains("answering WITHOUT a key id"))
        } finally {
            timber.log.Timber.uproot(caTree)
        }
    }

    @Test
    fun signClientAuth_aKeyThatIsNotThere_isAnsweredWithoutAKeyId_andNamesTheException() = runTest(dispatcher) {
        timber.log.Timber.plant(caTree)
        try {
            val ks = caKeystore { throw org.siros.sdk.credentials.KeystoreException("Key not found: old-key") }
            val (keyId, proof) = signClientAuthReply(ks, keyIdHint = "old-key")
            assertNull(keyId)
            assertNull(proof)
            assertTrue(ca.toString(), ca.contains("KeystoreException: Key not found: old-key"))
        } finally {
            timber.log.Timber.uproot(caTree)
        }
    }

    @Test
    fun signClientAuth_aKeystoreWithoutDpopSupport_isAnsweredWithoutAKeyId() = runTest(dispatcher) {
        timber.log.Timber.plant(caTree)
        try {
            val ks = caKeystore { throw UnsupportedOperationException("generateDPoPProof not supported by this keystore") }
            val (keyId, proof) = signClientAuthReply(ks)
            assertNull(keyId)
            assertNull(proof)
            assertTrue(ca.toString(), ca.contains("UnsupportedOperationException"))
        } finally {
            timber.log.Timber.uproot(caTree)
        }
    }

    @Test
    fun signClientAuth_theDpopKeyComesFromTheDefaultKeystore_notTheOneIssuanceResolves() = runTest(dispatcher) {
        // availableKeystores holds another keystore (what resolveEffectiveKeystoreForIssuance may pick): it is never asked.
        val other = mockk<KeystoreManager>(relaxed = true)
        coEvery { other.generateDPoPProof(any(), any(), any(), any(), any()) } throws IllegalStateException("must not be used")
        val default = caKeystore { "dpop-jwt" }
        val (keyId, proof) = signClientAuthReply(
            default,
            config = WalletConfig(
                backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback",
                availableKeystores = mapOf("other" to other, "default" to default),
            ),
        )
        assertEquals("instance-key-1", keyId)
        assertEquals("dpop-jwt", proof)
        coVerify(exactly = 0) { other.generateDPoPProof(any(), any(), any(), any(), any()) }
    }

    @Test
    fun signClientAuth_whenNoProofWasAsked_aKeyIdWithoutAProofIsStillTheAnswer() = runTest(dispatcher) {
        val (keyId, proof) = signClientAuthReply(caKeystore { "unused" }, htm = null, htu = null)
        assertEquals("instance-key-1", keyId)
        assertNull(proof)
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
        coEvery { keystore.isWscdOnboarded() } returns true
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

    @Test
    fun requestBackendKeyAttestation_sendsTheClaimOfTheKeystoreThatHoldsTheKeysOnly() = runTest(dispatcher) {
        // (resolved keystore, claims) -> the plugin that must be sent. "Resolved" is the keystore the issuance uses: here the
        // wallet's default one, which is registered under its id in availableKeystores.
        data class Case(val resolved: String, val claims: Map<String, String>, val expected: String?)
        val cases = listOf(
            Case("fido2", mapOf("softkey" to "soft"), null), // claim only for the software one, issuance resolves FIDO2: nothing
            Case("softkey", mapOf("softkey" to "soft"), "soft"), // and the reverse
            Case("softkey", mapOf("fido2" to "fido2"), null), // never another keystore's claim
            Case("fido2", mapOf("softkey" to "soft", "fido2" to "fido2"), "fido2"), // each keystore its own
            Case("softkey", emptyMap(), null), // no claim configured
        )
        for (c in cases) {
            val signFlow = MutableSharedFlow<SignRequestMessage>()
            fun ks(): KeystoreManager = mockk<KeystoreManager>().also {
                coEvery { it.isWscdOnboarded() } returns true
                coEvery { it.generateKeypairs(1) } returns listOf(KeypairInfo(keyId = "key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
                coEvery { it.attestationChain("key-1") } returns null
                coEvery { it.securityProperties("key-1") } returns null
            }
            val keystores = mapOf("softkey" to ks(), "fido2" to ks())
            val apiClient = mockk<BackendApiClient>(relaxed = true)
            val sentPlugin = slot<String?>()
            coEvery { apiClient.requestKeyAttestation(any(), any(), any(), any(), any(), captureNullable(sentPlugin)) } returns "jwt"
            mockEngineConstructor(signRequests = signFlow)
            val wallet = newWallet(
                "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
                "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                "config" to WalletConfig(backendUrl = "https://wallet.example.com", availableKeystores = keystores, wscdPluginClaims = c.claims),
                "keystore" to keystores.getValue(c.resolved),
            )
            invokeConnectEngine(wallet, "app-token")
            setField(wallet, "apiClient", apiClient)
            setField(wallet, "cachedWia", fakeWiaJwt(System.currentTimeMillis() / 1000 + 3600, jkt = "test-jkt", attestationSource = "ios_app_attest"))
            setField(wallet, "cachedWiaExpiresAt", System.currentTimeMillis() / 1000 + 3600)
            advanceUntilIdle()
            signFlow.emit(
                SignRequestMessage(
                    flowId = "flow-plugin", action = "generate_proof",
                    params = SignRequestParams(audience = "aud-1", nonce = "nonce-1", count = 1, proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} }),
                ),
            )
            advanceUntilIdle()
            coVerify(exactly = 1) { apiClient.requestKeyAttestation(any(), any(), any(), any(), any(), any()) }
            assertEquals("resolved=${c.resolved} claims=${c.claims}", c.expected, sentPlugin.captured)
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
        coEvery { keystore.isWscdOnboarded() } returns true
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
        coEvery { keystore.isWscdOnboarded() } returns true
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
        coEvery { fido2Keystore.isWscdOnboarded() } returns true
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

    @Test
    fun requestBackendKeyAttestation_sendsTheClaimOfThePolicySelectedKeystore_notTheDefaultsClaim() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        // A SOFTWARE default keystore; the policy selects FIDO2 for a credential type that requires the high tier.
        val defaultKeystore = mockk<KeystoreManager>()
        val fido2Keystore = mockk<KeystoreManager>()
        coEvery { fido2Keystore.isWscdOnboarded() } returns true
        val keypairs = listOf(KeypairInfo(keyId = "fido2-key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { fido2Keystore.generateKeypairs(1) } returns keypairs
        coEvery { fido2Keystore.attestationChain(any()) } returns null
        coEvery { fido2Keystore.securityProperties("fido2-key-1") } returns null
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        val sentPlugin = slot<String?>()
        coEvery { apiClient.requestKeyAttestation(any(), any(), any(), any(), any(), captureNullable(sentPlugin)) } returns "jwt"
        mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            // DISTINCT claims: the default's is "soft", the selected one's is "fido2".
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                availableKeystores = mapOf("softkey" to defaultKeystore, "fido2" to fido2Keystore),
                wscdPluginClaims = mapOf("softkey" to "soft", "fido2" to "fido2"),
            ),
            "keystore" to defaultKeystore,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
        )
        setField(wallet, "activeOffer", org.siros.sdk.credentials.CredentialOffer(
            credentialConfigurationId = "pid", credentialIssuerIdentifier = "https://issuer.example.com", credentialName = "PID", issuerName = "Issuer",
        ))
        setField(wallet, "activeVctm", org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = "iso_18045_high"))
        invokeConnectEngine(wallet, "app-token")
        setField(wallet, "apiClient", apiClient)
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sign", action = "generate_proof",
                params = SignRequestParams(audience = "https://issuer.example.com", nonce = "nonce-1", count = 1, proofTypesSupported = buildJsonObject { putJsonObject("attestation") {} }),
            ),
        )
        advanceUntilIdle()
        coVerify(exactly = 1) { fido2Keystore.generateKeypairs(1) }
        assertEquals("the claim of the keystore that generated the keys (FIDO2), not the default's", "fido2", sentPlugin.captured)
    }

    // -------- the credential catalog as the baseline key-storage tier --------

    private class CatalogFixture(val wallet: SirosWallet, val soft: KeystoreManager, val fido2: KeystoreManager)

    /** A wallet whose default keystore is the SOFT one and which also has an (onboarded unless said otherwise) FIDO2 keystore. */
    private fun catalogFixture(
        catalog: org.siros.sdk.credentials.CredentialTierCatalog?,
        issuerTier: String?,
        fido2Onboarded: Boolean = true,
        withOffer: Boolean = true,
        policy: WscdSelectionPolicy = WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
    ): CatalogFixture {
        val soft = mockk<KeystoreManager>(relaxed = true)
        coEvery { soft.isWscdOnboarded() } returns true
        val fido2 = mockk<KeystoreManager>(relaxed = true)
        coEvery { fido2.isWscdOnboarded() } returns fido2Onboarded
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                availableKeystores = mapOf("softkey" to soft, "fido2" to fido2),
                credentialTierCatalog = catalog,
            ),
            "keystore" to soft,
            "wscdSelectionPolicy" to policy,
        )
        if (withOffer) {
            setField(wallet, "activeOffer", org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "pid", credentialIssuerIdentifier = "https://issuer.example.com", credentialName = "PID", issuerName = "Issuer",
            ))
            setField(wallet, "activeVctm", org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = issuerTier))
        }
        return CatalogFixture(wallet, soft, fido2)
    }

    private fun catalogOf(answer: org.siros.sdk.credentials.CatalogTier) = org.siros.sdk.credentials.CredentialTierCatalog { answer }
    private fun known(tier: String) = catalogOf(org.siros.sdk.credentials.CatalogTier.Known(tier))

    /** The keystore [SirosWallet] resolves for the active issuance, or the exception that refused it. */
    private fun resolveKeystore(wallet: SirosWallet): Result<KeystoreManager> = runCatching {
        val method = wallet::class.declaredMemberFunctions.first { it.name == "resolveEffectiveKeystoreForIssuance" }
        method.isAccessible = true
        try {
            kotlinx.coroutines.runBlocking { method.callSuspend(wallet) as KeystoreManager }
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.targetException
        }
    }

    @Test
    fun catalogTier_isTheBaseline_whenTheIssuerDeclaresNone_theGdcPidGap() {
        // The issuer's metadata says nothing: before, the SOFT default was used. The catalog says high: FIDO2 is.
        val f = catalogFixture(known("iso_18045_high"), issuerTier = null)
        assertSame(f.fido2, resolveKeystore(f.wallet).getOrThrow())
    }

    @Test
    fun theIssuerMayRaiseTheCatalogTier_butNeverLowerIt() {
        // catalog basic + issuer high: high (the soft keystore would not do)
        val raised = catalogFixture(known("iso_18045_basic"), issuerTier = "iso_18045_high")
        assertSame(raised.fido2, resolveKeystore(raised.wallet).getOrThrow())
        // catalog high + issuer basic: still high
        val notLowered = catalogFixture(known("iso_18045_high"), issuerTier = "iso_18045_basic")
        assertSame(notLowered.fido2, resolveKeystore(notLowered.wallet).getOrThrow())
    }

    @Test
    fun withoutACatalog_onlyTheIssuersTierCounts_asBefore() {
        val f = catalogFixture(null, issuerTier = null)
        assertSame("no tier at all: the default keystore, as before", f.soft, resolveKeystore(f.wallet).getOrThrow())
    }

    @Test
    fun aTierTheCatalogCannotGive_refusesAndNeverFallsBackToTheSoftKeystore() {
        for (catalog in listOf(
            catalogOf(org.siros.sdk.credentials.CatalogTier.NotListed),
            catalogOf(org.siros.sdk.credentials.CatalogTier.Unavailable),
            org.siros.sdk.credentials.CredentialTierCatalog { throw IllegalStateException("catalog crashed") },
            known("iso_18045_ultra"), // not a known tier
        )) {
            val f = catalogFixture(catalog, issuerTier = null)
            val e = resolveKeystore(f.wallet).exceptionOrNull()
            assertTrue("expected a refusal, got $e", e is KeyStorageTierUndeterminedException)
        }
        // an issuer tier alone does not stand in for a catalog that cannot answer
        val f = catalogFixture(catalogOf(org.siros.sdk.credentials.CatalogTier.Unavailable), issuerTier = "iso_18045_basic")
        assertTrue(resolveKeystore(f.wallet).exceptionOrNull() is KeyStorageTierUndeterminedException)
    }

    @Test
    fun aCatalogTierNoOnboardedPluginMeets_refuses_notTheSoftKeystore() {
        val f = catalogFixture(known("iso_18045_high"), issuerTier = null, fido2Onboarded = false)
        val e = resolveKeystore(f.wallet).exceptionOrNull()
        assertTrue("expected NoOnboardedWscdException, got $e", e is NoOnboardedWscdException)
    }

    @Test
    fun aUserOverrideCannotGoBelowTheCatalogTier() {
        val policy = WscdSelectionPolicy(
            tofuStore = InMemoryWscdTofuStore(),
            userOverrideStore = object : WscdUserOverrideStore {
                override fun get(issuer: String, credentialType: String): String? = null
                override fun put(issuer: String, credentialType: String, pluginId: String) {}
                override fun getGlobal(): String? = "softkey"
                override fun setGlobal(pluginId: String) {}
            },
        )
        val f = catalogFixture(known("iso_18045_high"), issuerTier = null, policy = policy)
        assertSame("the soft override does not meet the catalog tier", f.fido2, resolveKeystore(f.wallet).getOrThrow())
    }

    @Test
    fun theResumedAuthorizationPath_hasNoActiveOffer_andWithACatalogIsRefused_notServedBySoft() {
        val f = catalogFixture(known("iso_18045_high"), issuerTier = null, withOffer = false)
        assertTrue(resolveKeystore(f.wallet).exceptionOrNull() is KeyStorageTierUndeterminedException)
    }

    @Test
    fun resumingAfterTheBrowser_restoresTheOfferContext_soTheCatalogTierApplies() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        every { engine.resumeIssuance(any(), any(), any(), any(), any()) } just runs
        coEvery { engine.awaitConnected(any()) } just runs
        val soft = mockk<KeystoreManager>(relaxed = true)
        coEvery { soft.isWscdOnboarded() } returns true
        val fido2 = mockk<KeystoreManager>(relaxed = true)
        coEvery { fido2.isWscdOnboarded() } returns true
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com", tenantId = "tenant-1", redirectUri = "siros://callback",
                availableKeystores = mapOf("softkey" to soft, "fido2" to fido2),
                credentialTierCatalog = known("iso_18045_high"),
            ),
            "keystore" to soft,
            "wscdSelectionPolicy" to WscdSelectionPolicy(tofuStore = InMemoryWscdTofuStore()),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to mockk<WalletEventListener>(relaxed = true),
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
                    put("authorization_url", "https://issuer.example.com/auth?state=s")
                    put("expected_redirect_uri", "siros://callback")
                    put("state", "s")
                    put("code_verifier", "v")
                    putJsonObject("credential_offer") {
                        put("credential_issuer", "https://issuer.example.com")
                        putJsonArray("credential_configuration_ids") { add(kotlinx.serialization.json.JsonPrimitive("eu.europa.ec.eudi.pid_mdoc")) }
                    }
                },
            )
        )
        advanceUntilIdle()
        // the original flow was ended locally in the meantime: no offer context
        setField(wallet, "activeOffer", null)
        assertNull(getField(wallet, "activeOffer"))

        wallet.completeAuthorization(flowId = "flow-auth", code = "code", state = "s")
        advanceUntilIdle()

        val offer = getField(wallet, "activeOffer") as org.siros.sdk.credentials.CredentialOffer
        assertEquals("eu.europa.ec.eudi.pid_mdoc", offer.credentialConfigurationId)
        assertEquals("https://issuer.example.com", offer.credentialIssuerIdentifier)
        // and the catalog tier now decides: FIDO2, not the soft default
        assertSame(fido2, resolveKeystore(wallet).getOrThrow())
    }

    /** Both fido2 and r2ps are eligible for the tier but only r2ps is onboarded: it is used, fido2 never touched. */
    @Test
    fun requestBackendKeyAttestation_fallsOverToOnboardedPlugin_whenOtherEligiblePluginNotOnboarded() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>()
        val fido2Keystore = mockk<KeystoreManager>()
        coEvery { fido2Keystore.isWscdOnboarded() } returns false
        val r2psKeystore = mockk<KeystoreManager>()
        coEvery { r2psKeystore.isWscdOnboarded() } returns true
        val keypairs = listOf(KeypairInfo(keyId = "r2ps-key-1", publicKeyJWK = buildJsonObject { put("kty", "EC") }))
        coEvery { r2psKeystore.generateKeypairs(1) } returns keypairs
        coEvery { r2psKeystore.attestationChain(any()) } returns null
        coEvery { r2psKeystore.securityProperties("r2ps-key-1") } returns null
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
            availableKeystores = mapOf("softkey" to defaultKeystore, "fido2" to fido2Keystore, "r2ps" to r2psKeystore),
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

        coVerify(exactly = 1) { r2psKeystore.generateKeypairs(1) }
        coVerify(exactly = 0) { defaultKeystore.generateKeypairs(any()) }
        coVerify(exactly = 0) { fido2Keystore.generateKeypairs(any()) }
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
        coEvery { fido2Keystore.isWscdOnboarded() } returns true
        coEvery { fido2Keystore.generateProof(audience = any(), nonce = any(), freshKey = any(), holderBinding = any()) } returns "fido2-signed-proof-jwt"
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

        coVerify(exactly = 1) {
            fido2Keystore.generateProof(
                audience = "https://issuer.example.com", nonce = "nonce-1", freshKey = false,
                // HAIP is the wallet default, so the proof carries the key.
                holderBinding = HolderBinding.EMBEDDED_JWK,
            )
        }
        coVerify(exactly = 0) { defaultKeystore.generateProof(any(), any(), any(), any()) }
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
     * fido2 is tier-sufficient but no WSCD token has been onboarded: issuance must fail with
     * [NoOnboardedWscdException] before any key is generated (and so before any PIN is requested),
     * with no fallback to the default keystore and no sign response.
     */
    @Test
    fun requestBackendKeyAttestation_refusesBeforeAnyKeyOrPin_whenNoEligibleWscdOnboarded() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>(relaxed = true)
        val fido2Keystore = mockk<KeystoreManager>()
        coEvery { fido2Keystore.isWscdOnboarded() } returns false
        val apiClient = mockk<BackendApiClient>(relaxed = true)
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

        coVerify(exactly = 1) { fido2Keystore.isWscdOnboarded() }
        coVerify(exactly = 0) { fido2Keystore.generateKeypairs(any()) }
        coVerify(exactly = 0) { fido2Keystore.generateKeyAttestation(any(), any()) }
        coVerify(exactly = 0) { defaultKeystore.generateKeypairs(any()) }
        coVerify(exactly = 0) { engine.sendSignResponse(any(), any(), any(), any()) }
    }

    /**
     * The wallet's own default keystore (no availableKeystores) has no onboarded WSCD: issuance must fail with
     * [WscdAuthenticatorNotPresentException] before any key is generated (and so before any PIN is
     * requested), with no fallback to the default keystore and no sign response.
     */
    @Test
    fun requestBackendKeyAttestation_refusesBeforeAnyKeyOrPin_whenDefaultKeystoreNotOnboarded() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { defaultKeystore.isWscdOnboarded() } returns false
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        val engine = mockEngineConstructor(signRequests = signFlow)
        val config = WalletConfig(
            backendUrl = "https://wallet.example.com",
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

        coVerify(exactly = 1) { defaultKeystore.isWscdOnboarded() }
        coVerify(exactly = 0) { defaultKeystore.generateKeypairs(any()) }
        coVerify(exactly = 0) { engine.sendSignResponse(any(), any(), any(), any()) }
    }

    /**
     * The credential declares NO tier, but a global user override names fido2, which is not onboarded:
     * the policy returns the override, and the gate must still refuse before any key generation / PIN.
     */
    @Test
    fun requestBackendKeyAttestation_refusesBeforeAnyKeyOrPin_whenOverrideNamesNonOnboardedPlugin_evenWithNoRequiredTier() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val defaultKeystore = mockk<KeystoreManager>(relaxed = true)
        val fido2Keystore = mockk<KeystoreManager>()
        coEvery { fido2Keystore.isWscdOnboarded() } returns false
        val apiClient = mockk<BackendApiClient>(relaxed = true)
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
            "wscdSelectionPolicy" to WscdSelectionPolicy(
                tofuStore = InMemoryWscdTofuStore(),
                userOverrideStore = object : WscdUserOverrideStore {
                    override fun get(issuer: String, credentialType: String): String? = null
                    override fun put(issuer: String, credentialType: String, pluginId: String) {}
                    override fun getGlobal(): String? = "fido2"
                    override fun setGlobal(pluginId: String) {}
                },
            ),
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
            org.siros.sdk.credentials.Vctm(vct = "urn:eu.europa.ec.eudi:pid:1", requiredKeyStorage = null),
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

        coVerify(exactly = 1) { fido2Keystore.isWscdOnboarded() }
        coVerify(exactly = 0) { fido2Keystore.generateKeypairs(any()) }
        coVerify(exactly = 0) { fido2Keystore.generateKeyAttestation(any(), any()) }
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
        coEvery { fido2Keystore.isWscdOnboarded() } returns true
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
        coEvery { fido2Keystore.isWscdOnboarded() } returns true
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
            every { keystore.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
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
            every { keystore.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
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
            every { keystore.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
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
        every { keystore.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
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

    // ── Issuance trust gate: an untrusted issuer's credential is never stored ──

    private fun mdocResult(notificationId: String? = null) = CredentialResult(
        format = "mso_mdoc",
        credential = "bm90LWFuLW1kb2M",
        notificationId = notificationId,
    )

    /** Runs the issuance policy with the REAL evaluateIssuerTrust behind the mdoc check. */
    private suspend fun gateFor(wallet: SirosWallet, cert: java.security.cert.X509Certificate): String? =
        issuanceTrustRefusal(listOf(mdocResult()), engineTrust = null) {
            wallet.evaluateIssuerTrust(listOf(cert.encoded), docType = null)
        }

    @Test
    fun issuanceGate_remoteDecisionTrue_isAccepted() = runTest(dispatcher) {
        val cert = issuerNamingFixtureCert()
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", JsonPrimitive(true)) }
        assertNull(gateFor(issuerWalletWithLocalRoot(apiClient, cert), cert))
    }

    @Test
    fun issuanceGate_remoteDecisionFalse_isRefused_evenWithLocalRootThatWouldAccept() = runTest(dispatcher) {
        val cert = issuerNamingFixtureCert()
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", JsonPrimitive(false)) }
        assertNotNull(gateFor(issuerWalletWithLocalRoot(apiClient, cert), cert))
    }

    @Test
    fun issuanceGate_unreachableWithNoLocalRoots_isRefused() = runTest(dispatcher) {
        val cert = issuerNamingFixtureCert()
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws NetworkException("offline")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )
        assertNotNull(gateFor(wallet, cert))
    }

    @Test
    fun issuanceGate_unreachableWithPositiveLocalValidation_isAccepted() = runTest(dispatcher) {
        val cert = issuerNamingFixtureCert()
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws NetworkException("offline")
        assertNull(gateFor(issuerWalletWithLocalRoot(apiClient, cert), cert))
    }

    @Test
    fun issuanceGate_unreachableWithLocalValidationNegative_isRefused() = runTest(dispatcher) {
        val cert = issuerNamingFixtureCert()
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws NetworkException("offline")
        // Root configured, but it is not this certificate's issuer.
        val otherRoot = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(
            checkNotNull(javaClass.getResourceAsStream("/mdoc-issuer-identity/http_uri.pem")),
        ) as java.security.cert.X509Certificate
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", issuerTrustRootCertificatesPem = listOf("unused")),
            "issuerTrustRootCertificates\$delegate" to lazy { listOf(otherRoot) },
        )
        assertNotNull(gateFor(wallet, cert))
    }

    @Test
    fun issuanceGate_backend4xx_isRefused() = runTest(dispatcher) {
        val cert = issuerNamingFixtureCert()
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws BackendApiException(403, "API request failed: 403", "")
        assertNotNull(gateFor(issuerWalletWithLocalRoot(apiClient, cert), cert))
    }

    @Test
    fun issuanceGate_missingOrUnverifiableIssuerAuth_isRefused() = runTest(dispatcher) {
        val refusal = issuanceTrustRefusal(listOf(mdocResult()), engineTrust = null) { null }
        assertNotNull(refusal)
        assertTrue(refusal!!.contains("issuerAuth"))
    }

    @Test
    fun issuanceGate_engineReportedUntrusted_isRefusedEvenForNonMdoc() = runTest(dispatcher) {
        val sdJwt = CredentialResult(format = "dc+sd-jwt", credential = "x")
        val untrusted = TrustResult(trusted = false, reason = "not in registry")
        val trusted = TrustResult(trusted = true)
        assertNotNull(issuanceTrustRefusal(listOf(sdJwt), untrusted) { null })
        assertNull(issuanceTrustRefusal(listOf(sdJwt), trusted) { null })
        assertNull(issuanceTrustRefusal(listOf(sdJwt), null) { null })
    }

    /** Wires a wallet to a mock engine, runs [emit], and returns what was observably touched. */
    private class RefusalHarness(
        val store: FakeCredentialStore,
        val listener: WalletEventListener,
        val apiClient: BackendApiClient,
        val engine: WalletEngineSession,
        val state: MutableStateFlow<WalletState>,
        val wallet: SirosWallet,
    )

    private fun TestScope.refusalHarness(
        progress: MutableSharedFlow<FlowProgressMessage>,
        complete: MutableSharedFlow<FlowCompleteMessage>,
        existing: List<StoredCredential> = emptyList(),
        configure: (SirosWallet) -> Unit = {},
    ): RefusalHarness {
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(existing.toMutableList())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        every { keystore.isUnlocked } returns true
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"x"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        val engine = mockEngineConstructor(progressFlow = progress, flowComplete = complete)
        every { engine.sendCredentialNotification(any(), any(), any(), any()) } just runs
        val state = MutableStateFlow<WalletState>(
            WalletState.FlowActive(
                userId = "u", displayName = "A", flowId = "f1", flowType = "issuance",
                status = "in_progress", credentials = emptyList(),
            ),
        )
        val wallet = newWallet(
            "_state" to state,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
        )
        configure(wallet)
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        return RefusalHarness(store, listener, apiClient, engine, state, wallet)
    }

    @Test
    fun flowComplete_unverifiableMdoc_isRefused_nothingStoredCapturedOrSynced() = runTest(dispatcher) {
        val progress = MutableSharedFlow<FlowProgressMessage>()
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        val h = refusalHarness(progress, complete)

        complete.emit(
            FlowCompleteMessage(
                flowId = "f1",
                credentials = listOf(mdocResult(notificationId = "notif-1")),
                refreshToken = "secret-refresh-token",
            ),
        )
        advanceUntilIdle()

        assertTrue(runBlocking { h.store.getAll() }.isEmpty())
        coVerify(exactly = 0) { h.apiClient.updatePrivateData(any()) }
        verify(exactly = 1) {
            h.engine.sendCredentialNotification(
                flowId = "f1",
                notificationId = "notif-1",
                event = CredentialNotificationEvent.FAILURE,
                eventDescription = "issuer_not_trusted",
            )
        }
        verify(exactly = 0) {
            h.engine.sendCredentialNotification(any(), any(), CredentialNotificationEvent.ACCEPTED, any())
        }
        verify(exactly = 1) { h.listener.onIssuerNotTrusted("f1", any(), any()) }
        verify(exactly = 1) { h.listener.onFlowError("f1", ISSUER_NOT_TRUSTED_MESSAGE, any()) }
        verify(exactly = 0) { h.listener.onFlowComplete(any(), any()) }
        verify(exactly = 0) { h.listener.onCredentialReceived(any()) }
        assertTrue(h.state.value is WalletState.Ready)
    }

    // ── End-to-end with a genuinely signed mdoc (no hook): decode, parse,
    // verify the issuerAuth signature, evaluate, then store or refuse.

    private fun fixtureText(name: String) =
        String(checkNotNull(javaClass.getResourceAsStream("/mdoc-issuance/$name")).readBytes())

    private fun fixtureIssuerCert(): java.security.cert.X509Certificate =
        java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(fixtureText("issuer-cert.pem").byteInputStream()) as java.security.cert.X509Certificate

    private fun fixtureIssuerKey(): java.security.PrivateKey {
        val b64 = fixtureText("issuer-key.pem").lines().filter { !it.startsWith("-----") }.joinToString("")
        return java.security.KeyFactory.getInstance("EC")
            .generatePrivate(java.security.spec.PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(b64)))
    }

    private fun derToRaw(der: ByteArray): ByteArray {
        var i = 3
        val rLen = der[i].toInt(); i++
        val r = der.copyOfRange(i, i + rLen); i += rLen + 1
        val sLen = der[i].toInt(); i++
        val s = der.copyOfRange(i, i + sLen)
        fun fix(b: ByteArray) = ByteArray(32).also { out ->
            val t = b.dropWhile { it == 0.toByte() }.toByteArray()
            System.arraycopy(t, 0, out, 32 - t.size, t.size)
        }
        return fix(r) + fix(s)
    }

    /** A bare IssuerSigned mdoc, base64url, signed with the fixture key (optionally tampered / without x5chain). */
    private fun signedMdoc(tamper: Boolean = false, withChain: Boolean = true, untaggedMso: Boolean = false): String {
        val docType = "org.iso.18013.5.1.mDL"
        val mso = com.upokecenter.cbor.CBORObject.NewMap()
        mso[com.upokecenter.cbor.CBORObject.FromObject("docType")] = com.upokecenter.cbor.CBORObject.FromObject(docType)
        val payload = if (untaggedMso) {
            com.upokecenter.cbor.CBORObject.FromObject(mso.EncodeToBytes()).EncodeToBytes()
        } else {
            com.upokecenter.cbor.CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes()
        }
        val protectedBytes = com.upokecenter.cbor.CBORObject.NewMap()
            .also { it[com.upokecenter.cbor.CBORObject.FromObject(1)] = com.upokecenter.cbor.CBORObject.FromObject(-7) }
            .EncodeToBytes()
        val sigStructure = com.upokecenter.cbor.CBORObject.NewArray().also {
            it.Add(com.upokecenter.cbor.CBORObject.FromObject("Signature1"))
            it.Add(com.upokecenter.cbor.CBORObject.FromObject(protectedBytes))
            it.Add(com.upokecenter.cbor.CBORObject.FromObject(ByteArray(0)))
            it.Add(com.upokecenter.cbor.CBORObject.FromObject(payload))
        }.EncodeToBytes()
        val signature = java.security.Signature.getInstance("SHA256withECDSA").run {
            initSign(fixtureIssuerKey()); update(sigStructure); derToRaw(sign())
        }
        if (tamper) signature[0] = (signature[0].toInt() xor 0x01).toByte()
        val unprotected = com.upokecenter.cbor.CBORObject.NewMap()
        if (withChain) {
            unprotected[com.upokecenter.cbor.CBORObject.FromObject(33)] =
                com.upokecenter.cbor.CBORObject.FromObject(fixtureIssuerCert().encoded)
        }
        val issuerAuth = com.upokecenter.cbor.CBORObject.NewArray().also {
            it.Add(com.upokecenter.cbor.CBORObject.FromObject(protectedBytes))
            it.Add(unprotected)
            it.Add(com.upokecenter.cbor.CBORObject.FromObject(payload))
            it.Add(com.upokecenter.cbor.CBORObject.FromObject(signature))
        }
        val item = com.upokecenter.cbor.CBORObject.NewMap().also {
            it[com.upokecenter.cbor.CBORObject.FromObject("digestID")] = com.upokecenter.cbor.CBORObject.FromObject(0)
            it[com.upokecenter.cbor.CBORObject.FromObject("random")] = com.upokecenter.cbor.CBORObject.FromObject(ByteArray(16))
            it[com.upokecenter.cbor.CBORObject.FromObject("elementIdentifier")] = com.upokecenter.cbor.CBORObject.FromObject("family_name")
            it[com.upokecenter.cbor.CBORObject.FromObject("elementValue")] = com.upokecenter.cbor.CBORObject.FromObject("Doe")
        }
        val tagged = com.upokecenter.cbor.CBORObject.FromObjectAndTag(item.EncodeToBytes(), 24)
        val ns = com.upokecenter.cbor.CBORObject.NewMap().also {
            it[com.upokecenter.cbor.CBORObject.FromObject("org.iso.18013.5.1")] =
                com.upokecenter.cbor.CBORObject.NewArray().also { a -> a.Add(tagged) }
        }
        val bare = com.upokecenter.cbor.CBORObject.NewMap().also {
            it[com.upokecenter.cbor.CBORObject.FromObject("nameSpaces")] = ns
            it[com.upokecenter.cbor.CBORObject.FromObject("issuerAuth")] = issuerAuth
        }
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bare.EncodeToBytes())
    }

    private fun TestScope.signedMdocHarness(
        complete: MutableSharedFlow<FlowCompleteMessage>,
        evaluate: suspend () -> JsonObject,
    ): RefusalHarness {
        val h = refusalHarness(MutableSharedFlow(), complete) { wallet ->
            val api = mockk<BackendApiClient>()
            coEvery { api.evaluateTrust(any()) } coAnswers { evaluate() }
            setField(wallet, "apiClient", api)
            setField(wallet, "config", WalletConfig(backendUrl = "https://wallet.example.com"))
        }
        return h
    }

    @Test
    fun flowComplete_signedMdocWithPositiveBackendDecision_isStoredAndAccepted() = runTest(dispatcher) {
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        val h = signedMdocHarness(complete) { buildJsonObject { put("decision", JsonPrimitive(true)) } }

        complete.emit(FlowCompleteMessage(flowId = "f1", credentials = listOf(
            CredentialResult(format = "mso_mdoc", credential = signedMdoc(), notificationId = "n"),
        )))
        advanceUntilIdle()

        assertEquals(1, runBlocking { h.store.getAll() }.size)
        verify(exactly = 1) { h.engine.sendCredentialNotification("f1", "n", CredentialNotificationEvent.ACCEPTED, any()) }
        verify(exactly = 0) { h.listener.onIssuerNotTrusted(any(), any(), any()) }
    }

    @Test
    fun flowComplete_signedMdocWithUntaggedByteStringMso_isStillAccepted() = runTest(dispatcher) {
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        val h = signedMdocHarness(complete) { buildJsonObject { put("decision", JsonPrimitive(true)) } }

        complete.emit(FlowCompleteMessage(flowId = "f1", credentials = listOf(
            CredentialResult(format = "mso_mdoc", credential = signedMdoc(untaggedMso = true)),
        )))
        advanceUntilIdle()

        assertEquals(1, runBlocking { h.store.getAll() }.size)
    }

    @Test
    fun flowComplete_signedMdocWithNegativeBackendDecision_isRefused() = runTest(dispatcher) {
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        val h = signedMdocHarness(complete) { buildJsonObject { put("decision", JsonPrimitive(false)) } }

        complete.emit(FlowCompleteMessage(flowId = "f1", credentials = listOf(
            CredentialResult(format = "mso_mdoc", credential = signedMdoc(), notificationId = "n"),
        )))
        advanceUntilIdle()

        assertTrue(runBlocking { h.store.getAll() }.isEmpty())
        verify(exactly = 1) { h.listener.onIssuerNotTrusted("f1", any(), any()) }
    }

    @Test
    fun flowComplete_signedMdocWithTamperedSignature_isRefusedWithoutAskingTheBackend() = runTest(dispatcher) {
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        var asked = 0
        val h = signedMdocHarness(complete) { asked++; buildJsonObject { put("decision", JsonPrimitive(true)) } }

        complete.emit(FlowCompleteMessage(flowId = "f1", credentials = listOf(
            CredentialResult(format = "mso_mdoc", credential = signedMdoc(tamper = true)),
        )))
        advanceUntilIdle()

        assertTrue(runBlocking { h.store.getAll() }.isEmpty())
        assertEquals(0, asked)
        verify(exactly = 1) { h.listener.onIssuerNotTrusted("f1", any(), any()) }
    }

    @Test
    fun flowComplete_signedMdocWithoutCertificateChain_isRefused() = runTest(dispatcher) {
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        val h = signedMdocHarness(complete) { buildJsonObject { put("decision", JsonPrimitive(true)) } }

        complete.emit(FlowCompleteMessage(flowId = "f1", credentials = listOf(
            CredentialResult(format = "mso_mdoc", credential = signedMdoc(withChain = false)),
        )))
        advanceUntilIdle()

        assertTrue(runBlocking { h.store.getAll() }.isEmpty())
        verify(exactly = 1) { h.listener.onIssuerNotTrusted("f1", any(), any()) }
    }

    @Test
    fun flowComplete_envelopeDocTypeDifferentFromSignedMso_isRefusedWithoutAskingTheBackend() = runTest(dispatcher) {
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        var asked = 0
        val h = signedMdocHarness(complete) { asked++; buildJsonObject { put("decision", JsonPrimitive(true)) } }
        // Wrap the validly signed (mDL) IssuerSigned in a DeviceResponse-style
        // envelope that claims another docType.
        val bare = com.upokecenter.cbor.CBORObject.DecodeFromBytes(java.util.Base64.getUrlDecoder().decode(signedMdoc()))
        val document = com.upokecenter.cbor.CBORObject.NewMap().also {
            it[com.upokecenter.cbor.CBORObject.FromObject("docType")] = com.upokecenter.cbor.CBORObject.FromObject("eu.europa.ec.eudi.pid.1")
            it[com.upokecenter.cbor.CBORObject.FromObject("issuerSigned")] = bare
        }
        val envelope = com.upokecenter.cbor.CBORObject.NewMap().also {
            it[com.upokecenter.cbor.CBORObject.FromObject("documents")] =
                com.upokecenter.cbor.CBORObject.NewArray().also { a -> a.Add(document) }
        }
        val wrapped = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(envelope.EncodeToBytes())

        complete.emit(FlowCompleteMessage(flowId = "f1", credentials = listOf(
            CredentialResult(format = "mso_mdoc", credential = wrapped),
        )))
        advanceUntilIdle()

        assertTrue(runBlocking { h.store.getAll() }.isEmpty())
        assertEquals(0, asked)
        verify(exactly = 1) { h.listener.onIssuerNotTrusted("f1", any(), any()) }
    }

    /** Logout ends the session generation: a completion pending on trust must neither store nor refuse. */
    @Test
    fun flowComplete_sessionEndedWhileTrustCheckPending_touchesNothing() = runTest(dispatcher) {
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        val gate = kotlinx.coroutines.CompletableDeferred<TrustResult?>()
        val h = refusalHarness(MutableSharedFlow(), complete) { wallet ->
            wallet.mdocIssuanceTrustHook = { gate.await() }
        }
        complete.emit(FlowCompleteMessage(flowId = "f1", credentials = listOf(mdocResult(notificationId = "n"))))
        advanceUntilIdle()
        val bump = SirosWallet::class.java.getDeclaredMethod("bumpSessionGeneration")
        bump.isAccessible = true
        bump.invoke(h.wallet)
        gate.complete(TrustResult(trusted = false, reason = "late denial"))
        advanceUntilIdle()

        assertTrue(runBlocking { h.store.getAll() }.isEmpty())
        verify(exactly = 0) { h.listener.onIssuerNotTrusted(any(), any(), any()) }
        verify(exactly = 0) { h.engine.sendCredentialNotification(any(), any(), any(), any()) }
    }

    @Test
    fun flowComplete_engineReportedUntrustedIssuer_isRefusedForSdJwt() = runTest(dispatcher) {
        val testCredential = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val progress = MutableSharedFlow<FlowProgressMessage>()
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        val h = refusalHarness(progress, complete)

        complete.emit(
            FlowCompleteMessage(
                flowId = "f1",
                credentials = listOf(CredentialResult(format = "dc+sd-jwt", credential = testCredential, notificationId = "n")),
                issuerTrust = IssuerTrustReport("https://issuer.example", trusted = false, framework = null, reason = "no"),
            ),
        )
        advanceUntilIdle()

        assertTrue(runBlocking { h.store.getAll() }.isEmpty())
        coVerify(exactly = 0) { h.apiClient.updatePrivateData(any()) }
        verify(exactly = 1) { h.listener.onIssuerNotTrusted("f1", "https://issuer.example", any()) }
        verify(exactly = 1) {
            h.engine.sendCredentialNotification("f1", "n", CredentialNotificationEvent.FAILURE, any())
        }
    }

    @Test
    fun flowComplete_engineReportedTrustedIssuer_storesSdJwt() = runTest(dispatcher) {
        val testCredential = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val progress = MutableSharedFlow<FlowProgressMessage>()
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        val h = refusalHarness(progress, complete)

        complete.emit(
            FlowCompleteMessage(
                flowId = "f1",
                credentials = listOf(CredentialResult(format = "dc+sd-jwt", credential = testCredential)),
                issuerTrust = IssuerTrustReport("https://issuer.example", trusted = true, framework = "x", reason = null),
            ),
        )
        advanceUntilIdle()

        assertEquals(1, runBlocking { h.store.getAll() }.size)
        verify(exactly = 0) { h.listener.onIssuerNotTrusted(any(), any(), any()) }
    }

    /**
     * Review finding: the trust check suspends on the network. If the flow is
     * cancelled meanwhile (issuance state reset, a new flow may own it), the
     * stale completion must neither store nor reset anything.
     */
    @Test
    fun flowComplete_cancelledWhileTrustCheckPending_touchesNothing() = runTest(dispatcher) {
        val progress = MutableSharedFlow<FlowProgressMessage>()
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        val gate = kotlinx.coroutines.CompletableDeferred<TrustResult?>()
        val h = refusalHarness(progress, complete) { wallet ->
            wallet.mdocIssuanceTrustHook = { gate.await() }
        }

        complete.emit(
            FlowCompleteMessage(
                flowId = "f1",
                credentials = listOf(mdocResult(notificationId = "n")),
                refreshToken = "rt",
            ),
        )
        advanceUntilIdle()
        // cancelCurrentFlow()-equivalent while the check is pending.
        val reset = SirosWallet::class.java.getDeclaredMethod("resetIssuanceGuards")
        reset.isAccessible = true
        reset.invoke(h.wallet)
        gate.complete(TrustResult(trusted = false, reason = "late"))
        advanceUntilIdle()

        assertTrue(runBlocking { h.store.getAll() }.isEmpty())
        verify(exactly = 0) { h.listener.onIssuerNotTrusted(any(), any(), any()) }
        verify(exactly = 0) { h.listener.onFlowError(any(), any(), any()) }
        verify(exactly = 0) { h.engine.sendCredentialNotification(any(), any(), any(), any()) }
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
        every { engine.startIssuance(any(), any(), any(), any(), any(), any()) } just runs
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
        coEvery { keystore.isWscdOnboarded() } returns true
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "nonce-1", freshKey = any(), holderBinding = any()) } returns "proof-jwt"
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

        coVerify(exactly = 1) { keystore.generateProof(audience = "aud-1", nonce = "nonce-1", freshKey = false, holderBinding = HolderBinding.EMBEDDED_JWK) }
        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-sign",
                proofs = listOf(ProofObject(proofType = "jwt", jwt = "proof-jwt")),
                messageId = null,
            )
        }
    }

    // ---- holder commitments (org.siros.psc) in the proof JWT; https://github.com/SUNET/vc/issues/823 ----

    /** A keystore that is also a [org.siros.sdk.keystore.HolderWitnessSource]; records what it was asked. */
    private fun pscKeystore(asked: MutableList<Pair<String, String>>): KeystoreManager {
        val ks = mockk<KeystoreManager>(moreInterfaces = arrayOf(org.siros.sdk.keystore.HolderWitnessSource::class))
        coEvery { ks.isWscdOnboarded() } returns true
        val src = ks as org.siros.sdk.keystore.HolderWitnessSource
        every { src.privateSeedCommitment(any(), any()) } answers {
            val t = firstArg<String>(); val i = secondArg<String>()
            asked += t to i
            java.security.MessageDigest.getInstance("SHA-256").digest("$t|$i".toByteArray(Charsets.UTF_8))
        }
        return ks
    }

    private fun pscClaimFor(type: String, issuer: String): String = java.util.Base64.getUrlEncoder().withoutPadding()
        .encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest("$type|$issuer".toByteArray(Charsets.UTF_8)))

    private suspend fun kotlinx.coroutines.test.TestScope.generateProofWithCommitments(
        keystore: KeystoreManager,
        params: SignRequestParams,
        listener: WalletEventListener? = null,
        config: WalletConfig = WalletConfig(backendUrl = "https://wallet.example.com"),
        extraFields: Array<Pair<String, Any?>> = emptyArray(),
    ): SirosWallet {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        mockEngineConstructor(signRequests = signFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to config,
            "keystore" to keystore,
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
            *extraFields,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(SignRequestMessage(flowId = "flow-psc", action = "generate_proof", params = params))
        advanceUntilIdle()
        return wallet
    }

    @Test
    fun generateProof_withHolderCommitments_signsTheClaimForTheExactIssuerString() = runTest(dispatcher) {
        val logged = StringBuilder()
        val tree = object : timber.log.Timber.Tree() {
            override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
                logged.append(message).append('\n')
                t?.let { logged.append(it.toString()).append('\n') }
            }
        }
        timber.log.Timber.plant(tree)
        try {
            val asked = mutableListOf<Pair<String, String>>()
            val keystore = pscKeystore(asked)
            val captured = slot<Map<String, String>>()
            coEvery { keystore.generateProof(any(), any(), any(), any(), capture(captured)) } returns "proof-jwt"
            generateProofWithCommitments(
                keystore,
                SignRequestParams(
                    audience = "https://issuer.example/", nonce = "n-1",
                    holderCommitments = listOf("psc"), credentialType = "urn:eudi:pid:1",
                    credentialIssuer = "https://issuer.example/",
                ),
            )
            assertEquals(mapOf("org.siros.psc" to pscClaimFor("urn:eudi:pid:1", "https://issuer.example/")), captured.captured)
            // The trailing slash is part of the issuer string: the commitment for the
            // slash-less spelling is a different value and was never asked for.
            assertNotEquals(pscClaimFor("urn:eudi:pid:1", "https://issuer.example"), captured.captured.getValue("org.siros.psc"))
            assertEquals(listOf("urn:eudi:pid:1" to "https://issuer.example/"), asked)
            assertFalse("the commitment must never be logged", logged.contains(captured.captured.getValue("org.siros.psc")))
        } finally {
            timber.log.Timber.uproot(tree)
        }
    }

    @Test
    fun generateProof_withHolderCommitments_everyProofOfABatchCarriesTheClaim() = runTest(dispatcher) {
        val keystore = pscKeystore(mutableListOf())
        val captured = mutableListOf<Map<String, String>>()
        coEvery { keystore.generateProof(any(), any(), any(), any(), capture(captured)) } returns "proof-jwt"
        generateProofWithCommitments(
            keystore,
            SignRequestParams(
                audience = "aud-1", nonce = "n-1", count = 3, holderCommitments = listOf("psc"),
                credentialType = "eu.europa.ec.eudi.nym_auth.1", credentialIssuer = "https://issuer.example",
            ),
        )
        assertEquals(3, captured.size)
        assertTrue(captured.all { it == mapOf("org.siros.psc" to pscClaimFor("eu.europa.ec.eudi.nym_auth.1", "https://issuer.example")) })
    }

    private fun auxEntry(path: String = """["psc"]""", required: Boolean = true, type: String = "hash_commitment", alg: String = "sha-256") =
        Json.parseToJsonElement("""{"type":"$type","alg":"$alg","path":$path,"required":$required,"extra":"kept-verbatim"}""").jsonObject

    @Test
    fun generateProof_withAuxiliaryDataToIssuer_signsOneAuxiliaryDataClaimIdenticalInEveryProof() = runTest(dispatcher) {
        val asked = mutableListOf<Pair<String, String>>()
        val keystore = pscKeystore(asked)
        val captured = mutableListOf<Map<String, kotlinx.serialization.json.JsonElement>>()
        coEvery { keystore.generateProofWithJsonClaims(any(), any(), any(), any(), capture(captured)) } returns "proof-jwt"
        generateProofWithCommitments(
            keystore,
            SignRequestParams(
                audience = "aud-1", nonce = "n-1", count = 3, credentialType = "urn:t", credentialIssuer = "https://issuer.example/",
                auxiliaryDataToIssuer = listOf(auxEntry()),
            ),
        )
        assertEquals(3, captured.size)
        assertEquals("one value for every proof", 1, captured.toSet().size)
        assertEquals(setOf("auxiliary_data"), captured.first().keys)
        val e = (captured.first().getValue("auxiliary_data") as JsonArray).single().jsonObject
        assertEquals(listOf("psc"), e["path"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(pscClaimFor("urn:t", "https://issuer.example/"), e["commitment"]!!.jsonPrimitive.content)
        assertEquals("derived once, for the exact issuer string", listOf("urn:t" to "https://issuer.example/"), asked)
    }

    private val offerWithVct = org.siros.sdk.credentials.CredentialOffer(
        credentialConfigurationId = "cfg-id", credentialIssuerIdentifier = "https://offer-issuer.example", credentialName = "n",
        issuerName = "i", vct = "urn:real:vct",
    )

    @Test
    fun startIssuanceByOffer_resolvesTheAuxiliarySelectionAtStart_forAnOfferBuiltIndependently() = runTest(dispatcher) {
        val issuer = "https://issuer.example"
        val metadata = buildJsonObject {
            put("credential_issuer", JsonPrimitive(issuer))
            putJsonObject("credential_configurations_supported") {
                putJsonObject("pid") {
                    put("format", JsonPrimitive("dc+sd-jwt"))
                    put("auxiliary_data_supported", Json.parseToJsonElement("""{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"encoding":"base64url"}]}"""))
                }
            }
        }
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.resolveIssuer(any(), any()) } returns buildJsonObject {
            putJsonObject("context") { put("trust_metadata", metadata) }
        }
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val selections = java.util.concurrent.ConcurrentHashMap<Pair<String, String>, org.siros.sdk.credentials.AuxiliarySelection.Selected>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "engineSession" to engine,
            "apiClient" to apiClient,
            "secretSeedAdvertised" to selections, // a FRESH wallet: no listing or display lookup happened before
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        // An offer the sample's full-reissuance fallback builds on its own, not through any resolve call.
        val offer = org.siros.sdk.credentials.CredentialOffer("pid", issuer, "PID", issuerName = "I")
        wallet.startIssuanceByOffer(offer)
        advanceUntilIdle()
        val selected = selections[issuer to "pid"]
        assertNotNull("the selection was recorded at issuance start", selected)
        assertEquals(org.siros.sdk.credentials.AuxiliaryDataV01.id, selected!!.shape.id)
    }

    @Test
    fun startIssuanceByOffer_abortsWhenTheCurrentAdvertisementIsMalformed_evenForAnOfferListedBefore() = runTest(dispatcher) {
        val issuer = "https://issuer.example"
        val metadata = buildJsonObject {
            put("credential_issuer", JsonPrimitive(issuer))
            putJsonObject("credential_configurations_supported") {
                putJsonObject("pid") {
                    put("format", JsonPrimitive("dc+sd-jwt"))
                    // An empty advertisement object: malformed (the offer was valid when it was listed, the CURRENT metadata is not).
                    put("auxiliary_data_supported", buildJsonObject {})
                }
            }
        }
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.resolveIssuer(any(), any()) } returns buildJsonObject { putJsonObject("context") { put("trust_metadata", metadata) } }
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val selections = java.util.concurrent.ConcurrentHashMap<Pair<String, String>, org.siros.sdk.credentials.AuxiliarySelection.Selected>()
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A"))
        val wallet = newWallet(
            "_state" to stateFlow,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "engineSession" to engine,
            "apiClient" to apiClient,
            "secretSeedAdvertised" to selections,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        val offer = org.siros.sdk.credentials.CredentialOffer("pid", issuer, "PID", issuerName = "I")
        try {
            wallet.startIssuanceByOffer(offer)
            org.junit.Assert.fail("issuance started although the advertisement is malformed")
        } catch (e: WalletException) {
            assertEquals("auxiliary_data_advertisement_malformed", e.errorCode)
        }
        advanceUntilIdle()
        verify(exactly = 0) { engine.startIssuance(any(), any(), any(), any(), any(), any()) }
        assertEquals("a new issuance can start afterwards", false, getField(wallet, "issuanceInFlight"))
    }

    @Test
    fun aCancelledIssuanceStartsLateMetadataLookup_neverOverwritesTheRetrysAdapterSelection() = runTest(dispatcher) {
        val issuer = "https://issuer.example"
        fun metadataWith(advert: kotlinx.serialization.json.JsonElement) = buildJsonObject {
            put("credential_issuer", JsonPrimitive(issuer))
            putJsonObject("credential_configurations_supported") {
                putJsonObject("pid") {
                    put("format", JsonPrimitive("dc+sd-jwt"))
                    put("auxiliary_data_supported", advert)
                }
            }
        }
        val valid = metadataWith(Json.parseToJsonElement("""{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"encoding":"base64url"}]}"""))
        val malformed = metadataWith(buildJsonObject {})
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        var call = 0
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.resolveIssuer(any(), any()) } coAnswers {
            val n = ++call
            // The FIRST attempt's lookup hangs; it is released after the user cancelled and restarted, with a different answer.
            if (n == 1) gate.await()
            buildJsonObject { putJsonObject("context") { put("trust_metadata", if (n == 1) malformed else valid) } }
        }
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val selections = java.util.concurrent.ConcurrentHashMap<Pair<String, String>, org.siros.sdk.credentials.AuxiliarySelection.Selected>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "engineSession" to engine,
            "apiClient" to apiClient,
            "secretSeedAdvertised" to selections,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        val offer = org.siros.sdk.credentials.CredentialOffer("pid", issuer, "PID", issuerName = "I")
        // Real time (the start does real IO work on its own dispatcher): wait until the lookup number [n] has been made.
        suspend fun untilLookup(n: Int) = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
            kotlinx.coroutines.withTimeout(10_000) { while (call < n) kotlinx.coroutines.delay(10) }
        }
        val first = async { runCatching { wallet.startIssuanceByOffer(offer) } }
        untilLookup(1)
        wallet.cancelCurrentFlow()
        val second = async { runCatching { wallet.startIssuanceByOffer(offer) } }
        untilLookup(2)
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) { kotlinx.coroutines.delay(200) }
        assertEquals(org.siros.sdk.credentials.AuxiliaryDataV01.id, selections[issuer to "pid"]!!.shape.id)
        gate.complete(Unit) // the cancelled attempt's lookup finally answers, with a MALFORMED advertisement
        advanceUntilIdle()
        val firstFailure = first.await().exceptionOrNull()
        assertTrue("the cancelled attempt unwinds as a cancellation, not a refusal: $firstFailure", firstFailure is kotlinx.coroutines.CancellationException)
        assertEquals(
            "the retry's selection survived the late answer of the cancelled attempt",
            org.siros.sdk.credentials.AuxiliaryDataV01.id, selections[issuer to "pid"]?.shape?.id,
        )
        second.await()
    }

    @Test
    fun aCancelledRawOfferStartsLateDisplayLookup_neverOverwritesTheRetrysAdapterSelection() = runTest(dispatcher) {
        val issuer = "https://issuer.example"
        fun metadataWith(advert: kotlinx.serialization.json.JsonElement) = buildJsonObject {
            put("credential_issuer", JsonPrimitive(issuer))
            putJsonObject("credential_configurations_supported") {
                putJsonObject("pid") {
                    put("format", JsonPrimitive("dc+sd-jwt"))
                    put("auxiliary_data_supported", advert)
                }
            }
        }
        val valid = metadataWith(Json.parseToJsonElement("""{"to_wallet":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"encoding":"base64url"}]}"""))
        val differentValid = metadataWith(Json.parseToJsonElement("""{"to_issuer":[{"type":"hash_commitment","alg":"sha-256","path":["psc"],"encoding":"base64url"}]}"""))
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        var call = 0
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.resolveIssuer(any(), any()) } coAnswers {
            val n = ++call
            if (n == 1) gate.await() // the FIRST attempt's display lookup hangs and is released after the retry recorded its own
            buildJsonObject { putJsonObject("context") { put("trust_metadata", if (n == 1) differentValid else valid) } }
        }
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val selections = java.util.concurrent.ConcurrentHashMap<Pair<String, String>, org.siros.sdk.credentials.AuxiliarySelection.Selected>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "engineSession" to engine,
            "apiClient" to apiClient,
            "secretSeedAdvertised" to selections,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        val offerJson = """{"credential_issuer":"$issuer","credential_configuration_ids":["pid"]}"""
        suspend fun untilLookup(n: Int) = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
            kotlinx.coroutines.withTimeout(10_000) { while (call < n) kotlinx.coroutines.delay(10) }
        }
        val first = async { runCatching { wallet.startIssuance(offerJson) } }
        untilLookup(1)
        wallet.cancelCurrentFlow()
        val second = async { runCatching { wallet.startIssuance(offerJson) } }
        untilLookup(2)
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) { kotlinx.coroutines.delay(200) }
        val retrys = selections[issuer to "pid"]
        assertEquals("the retry recorded its own selection", listOf(listOf("ssc")), retrys!!.advertisement.toWallet.map { it.path })
        gate.complete(Unit) // the cancelled attempt's lookup answers late, with a DIFFERENT valid advertisement
        advanceUntilIdle()
        first.await()
        assertEquals(
            "the late display lookup of the cancelled start did not overwrite the retry's selection",
            listOf(listOf("ssc")), selections[issuer to "pid"]!!.advertisement.toWallet.map { it.path },
        )
        second.await()
    }

    @Test
    fun aRawOfferWhoseCurrentAdvertisementIsMalformed_isRefusedAfterTheEpochCheck_andLeavesNoStaleSelection() = runTest(dispatcher) {
        val issuer = "https://issuer.example"
        val metadata = buildJsonObject {
            put("credential_issuer", JsonPrimitive(issuer))
            putJsonObject("credential_configurations_supported") {
                putJsonObject("pid") {
                    put("format", JsonPrimitive("dc+sd-jwt"))
                    put("auxiliary_data_supported", buildJsonObject {}) // malformed NOW
                }
            }
        }
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.resolveIssuer(any(), any()) } returns buildJsonObject { putJsonObject("context") { put("trust_metadata", metadata) } }
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val selections = java.util.concurrent.ConcurrentHashMap<Pair<String, String>, org.siros.sdk.credentials.AuxiliarySelection.Selected>()
        // An earlier, now stale, valid selection for the same issuer/configuration.
        selections[issuer to "pid"] = org.siros.sdk.credentials.AuxiliarySelection.Selected(
            org.siros.sdk.credentials.AuxiliaryDataV01,
            org.siros.sdk.credentials.AuxiliaryAdvertisement(listOf(org.siros.sdk.credentials.AuxiliaryAdvertisement.Slot(listOf("ssc"), "sha-256", false, "base64url")), emptyList()),
        )
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "engineSession" to engine,
            "apiClient" to apiClient,
            "secretSeedAdvertised" to selections,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
        )
        try {
            wallet.startIssuance("""{"credential_issuer":"$issuer","credential_configuration_ids":["pid"]}""")
            org.junit.Assert.fail("issuance started although the advertisement is malformed")
        } catch (e: WalletException) {
            assertEquals("auxiliary_data_advertisement_malformed", e.errorCode)
        }
        advanceUntilIdle()
        verify(exactly = 0) { engine.startIssuance(any(), any(), any(), any(), any(), any()) }
        assertEquals("the stale selection was cleared", null, selections[issuer to "pid"])
        assertEquals(false, getField(wallet, "issuanceInFlight"))
    }

    @Test
    fun generateProof_auxiliaryData_derivesFromTheOffersVctAndIssuerWhenTheRequestOmitsThem_andRecordsThatIssuer() = runTest(dispatcher) {
        val asked = mutableListOf<Pair<String, String>>()
        val keystore = pscKeystore(asked)
        coEvery { keystore.generateProofWithJsonClaims(any(), any(), any(), any(), any()) } returns "proof-jwt"
        val wallet = generateProofWithCommitments(
            keystore,
            // An EMPTY issuer counts as absent for the derivation, and the flow must record the string that was used.
            SignRequestParams(audience = "aud", nonce = "n", credentialType = null, credentialIssuer = "", auxiliaryDataToIssuer = listOf(auxEntry())),
            extraFields = arrayOf("activeOffer" to offerWithVct),
        )
        assertEquals(listOf("urn:real:vct" to "https://offer-issuer.example"), asked)
        @Suppress("UNCHECKED_CAST")
        assertEquals(mapOf("flow-psc" to "https://offer-issuer.example"), getField(wallet, "pscIssuerByFlow") as Map<String, String>)
    }

    @Test
    fun generateProof_auxiliaryData_rememberTheCommitmentsSoTheCompletionCanBeCheckedAgainstThem() = runTest(dispatcher) {
        val keystore = pscKeystore(mutableListOf())
        coEvery { keystore.generateProofWithJsonClaims(any(), any(), any(), any(), any()) } returns "proof-jwt"
        val wallet = generateProofWithCommitments(
            keystore,
            SignRequestParams(audience = "aud", nonce = "n", credentialType = "urn:t", credentialIssuer = "https://i.example", auxiliaryDataToIssuer = listOf(auxEntry())),
        )
        @Suppress("UNCHECKED_CAST")
        val kept = (getField(wallet, "holderCommitmentsByFlow") as Map<String, List<org.siros.sdk.credentials.HolderCommitment>>)["flow-psc"]!!
        assertEquals(listOf(listOf("psc")), kept.map { it.path })
        assertEquals(pscClaimFor("urn:t", "https://i.example"), java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(kept.single().commitment))
    }

    @Test
    fun wmpCompletion_ofAV01IssuanceIsCheckedWithTheOffersConfigurationId_notAsUnadvertised() = runTest(dispatcher) {
        val flowId = "flow-wmp-v01"
        val opening = "8f3b2c9e41d07a65b1e2f4c3d9a08176".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val b64 = { x: String -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(x.toByteArray()) }
        val disclosure = b64("""["salt","ssc","JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0"]""")
        val digest = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(disclosure.toByteArray(Charsets.US_ASCII)))
        val credential = b64("""{"alg":"none"}""") + "." + b64("""{"_sd_alg":"sha-256","_sd":["$digest"]}""") + ".sig~$disclosure~"
        val blind = BlindIssuance()
        val jwk = blind.offer(flowId, org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A128GCM", false))!!
        val body = buildJsonObject {
            put("credentials", kotlinx.serialization.json.JsonArray(listOf(buildJsonObject { put("credential", JsonPrimitive(credential)) })))
            put("notification_id", JsonPrimitive("n9"))
            put("credential_metadata", Json.parseToJsonElement("""{"auxiliary_data":[{"type":"hash_commitment","alg":"sha-256","path":["ssc"],"opening":"${java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(opening)}"}]}"""))
        }
        blind.open(flowId, issuerEncrypt(jwk, "ECDH-ES", "A128GCM", body.toString()), deferred = false)
        val selections = java.util.concurrent.ConcurrentHashMap<Pair<String, String>, org.siros.sdk.credentials.AuxiliarySelection.Selected>()
        selections["https://issuer.example" to "pid"] = org.siros.sdk.credentials.AuxiliarySelection.Selected(
            org.siros.sdk.credentials.AuxiliaryDataV01,
            org.siros.sdk.credentials.AuxiliaryAdvertisement(listOf(org.siros.sdk.credentials.AuxiliaryAdvertisement.Slot(listOf("ssc"), "sha-256")), emptyList()),
        )
        val wallet = newWallet(
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to org.siros.sdk.keystore.JweKeystore(),
            "blindIssuance" to blind,
            "secretSeedAdvertised" to selections,
            "activeOffer" to org.siros.sdk.credentials.CredentialOffer("pid", "https://issuer.example", "n", issuerName = "i"),
        )
        val result = Json.parseToJsonElement(
            """{"credentials":[{"format":"dc+sd-jwt"}],"credential_response_encrypted":true,"credential_issuer":"https://issuer.example"}""",
        ).jsonObject
        assertEquals(null, wallet.wmpDeliveredMetadataRefusal(flowId, result))
    }

    @Test
    fun generateProof_withARequiredAuxiliaryEntryItCannotAnswer_isRefusedAndNoProofIsMade() = runTest(dispatcher) {
        val keystore = pscKeystore(mutableListOf())
        // A keystore that WOULD make a proof (without the claim): the refusal must come from the wallet, not from a missing stub.
        coEvery { keystore.generateProof(audience = any(), nonce = any(), freshKey = any(), holderBinding = any()) } returns "proof-jwt"
        val listener = mockk<WalletEventListener>(relaxed = true)
        generateProofWithCommitments(
            keystore,
            SignRequestParams(
                audience = "aud-1", nonce = "n-1", credentialType = "urn:t", credentialIssuer = "https://issuer.example/",
                auxiliaryDataToIssuer = listOf(auxEntry(alg = "sha-512")),
            ),
            listener,
        )
        verify(exactly = 1) { listener.onFlowError("flow-psc", any(), any()) }
        coVerify(exactly = 0) { keystore.generateProof(audience = any(), nonce = any(), freshKey = any(), holderBinding = any()) }
        coVerify(exactly = 0) { keystore.generateProofWithJsonClaims(any(), any(), any(), any(), any()) }
    }

    @Test
    fun anInvalidProofWithAnAuxiliaryDataDetail_isTypedNonRetryableAndLeaksNoFreeText() = runTest(dispatcher) {
        val errorFlow = MutableSharedFlow<FlowErrorMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        mockEngineConstructor(flowErrors = errorFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        val cases = mapOf(
            "auxiliary_data: the key proofs carry different auxiliary_data" to AuxiliaryDataRefusedException.Reason.PROOFS_DIFFER,
            "auxiliary_data: the entry for [psc] is required" to AuxiliaryDataRefusedException.Reason.ENTRY_REQUIRED,
            "auxiliary_data: to_issuer lists no entry for [x]" to AuxiliaryDataRefusedException.Reason.NO_SUCH_ENTRY,
            "auxiliary_data: alg must be sha-256" to AuxiliaryDataRefusedException.Reason.ALG,
            "auxiliary_data: the entry for [psc] carries only type, alg, path and commitment" to AuxiliaryDataRefusedException.Reason.ENTRY_MEMBERS,
            "auxiliary_data: the commitment must be a base64url sha-256 hash" to AuxiliaryDataRefusedException.Reason.COMMITMENT_FORMAT,
            "auxiliary_data: something new SECRET-FREE-TEXT" to AuxiliaryDataRefusedException.Reason.OTHER,
        )
        var n = 0
        for ((text, reason) in cases) {
            val flow = "flow-aux-${n++}"
            errorFlow.emit(FlowErrorMessage(flowId = flow, error = org.siros.sdk.transport.engine.FlowError(code = "INVALID_PROOF", message = "invalid_proof: $text")))
            advanceUntilIdle()
            val err = slot<AuxiliaryDataRefusedException>()
            verify(exactly = 1) { listener.onAuxiliaryDataRefused(flow, capture(err)) }
            assertEquals(reason, err.captured.reason)
            assertFalse(err.captured.retryable)
            assertFalse("no issuer free text in the exception", err.captured.message!!.contains("SECRET-FREE-TEXT"))
            verify(exactly = 0) { listener.onFlowError(flow, any(), any()) }
        }
        // An invalid_proof WITHOUT the auxiliary_data prefix is an ordinary flow error.
        errorFlow.emit(FlowErrorMessage(flowId = "flow-plain", error = org.siros.sdk.transport.engine.FlowError(code = "INVALID_PROOF", message = "invalid_proof: nonce mismatch")))
        advanceUntilIdle()
        verify(exactly = 1) { listener.onFlowError("flow-plain", any(), any()) }
    }

    @Test
    fun auxiliaryDataConflict_isTypedNonRetryableAndNotAlsoAGenericError() = runTest(dispatcher) {
        val errorFlow = MutableSharedFlow<FlowErrorMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        mockEngineConstructor(flowErrors = errorFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        errorFlow.emit(
            FlowErrorMessage(
                flowId = "flow-c",
                error = org.siros.sdk.transport.engine.FlowError(
                    code = "AUXILIARY_DATA_CONFLICT", message = "conflict",
                    details = buildJsonObject { put("error", JsonPrimitive("auxiliary_data_conflict")) },
                ),
            )
        )
        advanceUntilIdle()
        val err = slot<AuxiliaryDataConflictException>()
        verify(exactly = 1) { listener.onAuxiliaryDataConflict("flow-c", capture(err)) }
        assertFalse(err.captured.retryable)
        verify(exactly = 0) { listener.onFlowError("flow-c", any(), any()) }
    }

    @Test
    fun freshRegistration_unlocksTheOtherKeystoresFromTheContainerItExported() = runTest(dispatcher) {
        val container = "exported-container".toByteArray()
        val default = mockk<KeystoreManager>(relaxed = true)
        coEvery { default.isWscdOnboarded() } returns true
        coEvery { default.exportEncryptedContainer() } returns container
        val other = mockk<KeystoreManager>(relaxed = true)
        val wallet = newWallet(
            "keystore" to default,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                availableKeystores = mapOf("default" to default, "other" to other),
            ),
        )
        val method = SirosWallet::class.declaredMemberFunctions.first { it.name == "initialiseKeystoresForNewAccount" }
        method.isAccessible = true
        val returned = method.callSuspend(wallet, ByteArray(32), ByteArray(8), ByteArray(32), ByteArray(32), ByteArray(32)) as ByteArray?
        assertTrue(returned.contentEquals(container))
        // Not the empty container: that is a different, never-saved root.
        coVerify(exactly = 1) { other.unlock(any(), container, any(), any(), any()) }
        coVerify(exactly = 0) { other.unlock(any(), match { it.isEmpty() }, any(), any(), any()) }
        // The default keystore was exported after setCredentialId, before the others unlocked.
        coVerifyOrder {
            default.unlock(any(), match { it.isEmpty() }, any(), any(), any())
            default.exportEncryptedContainer()
            other.unlock(any(), container, any(), any(), any())
        }
    }

    @Test
    fun issuedCredential_isStoredUnderTheIssuerStringTheCommitmentWasDerivedFor_evenWithoutAnOffer() = runTest(dispatcher) {
        val testCredential = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9."
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val store = FakeCredentialStore(mutableListOf())
        val keystore = pscKeystore(mutableListOf())
        every { keystore.isUnlocked } returns true
        coEvery { keystore.generateProof(any(), any(), any(), any(), any()) } returns "proof-jwt"
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"x"}""".toByteArray()
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        mockEngineConstructor(signRequests = signFlow, flowComplete = completeFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to mockk<SessionStore>(relaxed = true),
            "apiClient" to apiClient,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        // activeOffer is null (the issuer metadata could not be fetched): the only record of the issuer is the sign request.
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-i", action = "generate_proof",
                params = SignRequestParams(
                    audience = "https://issuer.example/", nonce = "n", holderCommitments = listOf("psc"),
                    credentialType = "urn:t", credentialIssuer = "https://issuer.example/",
                ),
            )
        )
        advanceUntilIdle()
        completeFlow.emit(
            FlowCompleteMessage(flowId = "flow-i", credentials = listOf(CredentialResult(format = "dc+sd-jwt", credential = testCredential)))
        )
        advanceUntilIdle()
        assertEquals("https://issuer.example/", store.getAll().single().credentialIssuerIdentifier)
    }

    @Test
    fun generateProof_withoutHolderCommitments_usesTheFourArgumentForm() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.isWscdOnboarded() } returns true
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "n-1", freshKey = any(), holderBinding = any()) } returns "proof-jwt"
        generateProofWithCommitments(keystore, SignRequestParams(audience = "aud-1", nonce = "n-1"))
        coVerify(exactly = 1) { keystore.generateProof(audience = "aud-1", nonce = "n-1", freshKey = false, holderBinding = any()) }
        coVerify(exactly = 0) { keystore.generateProof(any(), any(), any(), any(), any()) }
    }

    @Test
    fun generateProof_withHolderCommitments_refusesWhenTheKeystoreCannotDeriveOne() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.isWscdOnboarded() } returns true
        val listener = mockk<WalletEventListener>(relaxed = true)
        var ended = 0
        generateProofWithCommitments(
            keystore,
            SignRequestParams(
                audience = "aud-1", nonce = "n-1", holderCommitments = listOf("psc"),
                credentialType = "t", credentialIssuer = "https://issuer.example",
            ),
            listener,
            WalletConfig(backendUrl = "https://wallet.example.com", onWscdOperationEnd = { ended++ }),
        )
        // The hardware-operation cleanup still ran on the refusal path.
        assertEquals(1, ended)
        // The flow is failed, visibly, rather than answered with a proof lacking the claim.
        verify(exactly = 1) { listener.onFlowError("flow-psc", any(), any()) }
        // Not even the plain form: the proof is not made without the claim the issuer asked for.
        coVerify(exactly = 0) { keystore.generateProof(any(), any(), any(), any()) }
        coVerify(exactly = 0) { keystore.generateProof(any(), any(), any(), any(), any()) }
    }

    @Test
    fun pscConflict_isTypedAndNotAlsoAGenericError() = runTest(dispatcher) {
        val errorFlow = MutableSharedFlow<FlowErrorMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val conflict = slot<PseudonymCommitmentConflictException>()
        every { listener.onPseudonymCommitmentConflict("flow-c", capture(conflict)) } just runs
        mockEngineConstructor(flowErrors = errorFlow)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        errorFlow.emit(
            FlowErrorMessage(
                flowId = "flow-c",
                error = FlowError(code = "PSC_CONFLICT", message = "org.siros.psc_conflict: a different psc is on record"),
            )
        )
        advanceUntilIdle()
        assertEquals("org.siros.psc_conflict: a different psc is on record", conflict.captured.issuerMessage)
        verify(exactly = 0) { listener.onFlowError(any(), any(), any()) }
        assertTrue(wallet.state.value is WalletState.Ready)

        // Any other code stays a generic flow error.
        errorFlow.emit(FlowErrorMessage(flowId = "flow-d", error = FlowError(code = "OTHER", message = "boom")))
        advanceUntilIdle()
        verify(exactly = 1) { listener.onFlowError("flow-d", "boom", null) }
    }

    @Test
    fun pscConflict_defaultListenerForwardsTheIssuerTextToOnFlowError() {
        var seen: Pair<String, String>? = null
        val listener = object : WalletEventListener {
            override suspend fun onCredentialSelectionRequired(request: PresentationRequest): List<Long> = emptyList()
            override fun onFlowError(flowId: String, errorMessage: String, redirectUri: String?) {
                seen = flowId to errorMessage
            }
        }
        listener.onPseudonymCommitmentConflict("f", PseudonymCommitmentConflictException("org.siros.psc_conflict: x"))
        assertEquals("f" to "org.siros.psc_conflict: x", seen)
    }

    /** A `jwt`-proof-type proof-of-possession JWT with the given `kid` embedded in its `jwk` header, matching what [KeystoreManager.generateProof] actually produces. */
    private fun fakeProofJwt(kid: String): String {
        val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        val header = """{"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","kid":"$kid","x":"eA","y":"eQ"}}"""
        val payload = """{"aud":"aud-1","nonce":"nonce-1"}"""
        return "${encoder.encodeToString(header.toByteArray())}.${encoder.encodeToString(payload.toByteArray())}.sig"
    }

    /**
     * A configured per-issuer override must apply to that issuer and nothing
     * that merely looks like it. A raw string prefix matches
     * `https://issuer.example.evil` (a different domain) and
     * `https://issuer.example@evil.com/x` (where the familiar-looking part is
     * only userinfo), either of which hands one issuer's configuration to
     * somebody else.
     */
    @Test
    fun interopProfileFor_matchesOnOriginAndPathBoundary_notRawStringPrefix() = runTest(dispatcher) {
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                interopProfile = InteropProfile.HAIP,
                issuerInteropProfiles = mapOf("https://issuer.example" to InteropProfile.DIIP),
            ),
        )
        val profileFor = { issuer: String? ->
            SirosWallet::class.java.getDeclaredMethod("interopProfileFor", String::class.java)
                .apply { isAccessible = true }
                .invoke(wallet, issuer) as InteropProfile
        }

        assertEquals(InteropProfile.DIIP, profileFor("https://issuer.example"))
        assertEquals(InteropProfile.DIIP, profileFor("https://issuer.example/oid4vci"))
        assertEquals("a different domain", InteropProfile.HAIP, profileFor("https://issuer.example.evil"))
        assertEquals("userinfo, not the host", InteropProfile.HAIP, profileFor("https://issuer.example@evil.com/x"))
        assertEquals("a different scheme", InteropProfile.HAIP, profileFor("http://issuer.example"))
        assertEquals("a sibling path", InteropProfile.HAIP, profileFor("https://issuer.example.co/x"))
        // An explicit default port addresses the same issuer, so the override
        // must still apply - URI.getPort() reporting -1 for the implicit form
        // is a detail of the parser, not a different host.
        assertEquals(InteropProfile.DIIP, profileFor("https://issuer.example:443/oid4vci"))
        assertEquals("a non-default port", InteropProfile.HAIP, profileFor("https://issuer.example:8443"))
    }

    /** The DIIP counterpart of [fakeProofJwt]: the key is named by a `kid` header, not embedded. */
    private fun fakeDiipProofJwt(kid: String): String {
        val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        val header = """{"typ":"openid4vci-proof+jwt","alg":"ES256","kid":"$kid"}"""
        val payload = """{"aud":"aud-1","nonce":"nonce-1","iss":"${kid.substringBefore('#')}"}"""
        return "${encoder.encodeToString(header.toByteArray())}.${encoder.encodeToString(payload.toByteArray())}.sig"
    }

    /**
     * The same failure mode as the test below, for the OTHER proof shape: a
     * DIIP proof carries no `jwk` header at all, so reading the key id only
     * out of an embedded `jwk` silently leaves `StoredCredential.kid` null for
     * every DIIP-issued credential.
     */
    @Test
    fun connectEngine_signRequest_recordsAttestedKeyIdFromDiipKidHeader() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.isWscdOnboarded() } returns true
        val kid = "did:jwk:eyJrdHkiOiJFQyJ9#0"
        coEvery {
            keystore.generateProof(audience = "aud-1", nonce = "nonce-1", freshKey = any(), holderBinding = any())
        } returns fakeDiipProofJwt(kid)
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

        assertEquals(listOf(kid), getField(wallet, "activeAttestedKeyIds"))
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
        coEvery { keystore.isWscdOnboarded() } returns true
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "nonce-1", freshKey = any(), holderBinding = any()) } returns fakeProofJwt("sw-0")
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
        coEvery { keystore.isWscdOnboarded() } returns true
        coEvery {
            keystore.generateProof(audience = "aud-1", nonce = "nonce-1", freshKey = true, holderBinding = any())
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
        coEvery { keystore.isWscdOnboarded() } returns true
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
        coVerify(exactly = 0) { keystore.generateProof(any(), any(), any(), any()) }
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
        coEvery { keystore.isWscdOnboarded() } returns true
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
        coEvery { keystore.isWscdOnboarded() } returns true
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
        coEvery { keystore.isWscdOnboarded() } returns true
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
        coEvery { keystore.isWscdOnboarded() } returns true
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "nonce-1", freshKey = any(), holderBinding = any()) } returns "proof-jwt"
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
        coVerify(exactly = 1) { keystore.generateProof(audience = "aud-1", nonce = "nonce-1", freshKey = false, holderBinding = HolderBinding.EMBEDDED_JWK) }
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
    fun credentialSelection_whenTheSocketRefusesEveryFrame_theFallbackDeclineIsBestEffort_andNothingEscapes() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        every { engine.sendCredentialsMatched(any(), any(), any()) } throws IllegalStateException("Not connected")
        every { engine.sendFlowAction(any(), any(), any()) } throws IllegalStateException("Not connected")
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        val escaped = mutableListOf<Throwable>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice", credentials = store.getAll())),
            "scope" to CoroutineScope(dispatcher + SupervisorJob() + kotlinx.coroutines.CoroutineExceptionHandler { _, e -> escaped += e }),
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
                flowId = "flow-refused",
                step = "credential_selection",
                payload = buildJsonObject {
                    putJsonObject("dcql_query") {
                        putJsonArray("credentials") {
                            add(buildJsonObject {
                                put("id", "q-pid"); put("format", "dc+sd-jwt")
                                putJsonObject("meta") { putJsonArray("vct_values") { add(JsonPrimitive("urn:x")) } }
                            })
                        }
                    }
                },
            )
        )
        advanceUntilIdle()
        // The no-match answer was refused by the socket, the fallback decline was tried, and its failure was logged, not thrown.
        verify(atLeast = 1) { engine.sendFlowAction("flow-refused", "decline", any()) }
        assertEquals(emptyList<Throwable>(), escaped)
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
    fun handleDCAPIRequest_circuitZkUnsignedRequest_isRefusedBeforeTrustEvaluation() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )
        val requestJson = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
            put("nonce", "n")
            putJsonObject("dcql_query") {
                putJsonArray("credentials") { add(buildJsonObject { put("id", "q"); put("format", "zkp_req") }) }
            }
        })

        val e = org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
            kotlinx.coroutines.runBlocking { wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example") }
        }

        assertEquals("openid4vp-v1-unsigned", e.protocol)
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
    }

    @Test
    fun handleDCAPIRequest_requiredMode_refusesSignedRequestWithoutExpectedOriginsBeforeTrust() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
            "dcApiExpectedOriginsMode" to org.siros.sdk.wallet.dcapi.ExpectedOriginsMode.REQUIRED,
        )
        val ecKey = com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate()
        val jwt = com.nimbusds.jwt.SignedJWT(
            com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256).jwk(ecKey.toPublicJWK()).build(),
            com.nimbusds.jwt.JWTClaimsSet.Builder().claim("nonce", "n").build(),
        ).also { it.sign(com.nimbusds.jose.crypto.ECDSASigner(ecKey)) }
        val requestJson = wrapDCAPIRequest("openid4vp-v1-signed", buildJsonObject { put("request", jwt.serialize()) })

        org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
            kotlinx.coroutines.runBlocking { wallet.handleDCAPIRequest(requestJson, origin = "https://relying-party.example") }
        }
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
    }

    private fun signedCircuitZkRequest(origin: String, extraQueries: String = "", circuitQueryId: String? = "q"): String {
        val ecKey = com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).generate()
        val claims = com.nimbusds.jwt.JWTClaimsSet.parse(
            """{"client_id":"x509_san_dns:rp.example","nonce":"n","expected_origins":["$origin"],""" +
                """"dcql_query":{"credentials":[{${circuitQueryId?.let { "\"id\":\"$it\"," } ?: ""}"format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"test.doctype.1"}}$extraQueries]}}"""
        )
        val jwt = com.nimbusds.jwt.SignedJWT(
            com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256).jwk(ecKey.toPublicJWK()).build(), claims,
        ).also { it.sign(com.nimbusds.jose.crypto.ECDSASigner(ecKey)) }
        return wrapDCAPIRequest("openid4vp-v1-signed", buildJsonObject { put("request", jwt.serialize()) })
    }

    /** What the wallet builds when the host configures no prover: the catalog prover with no native half, over an empty catalog. */
    private fun defaultCatalogProverHolder(): Lazy<org.siros.sdk.keystore.CatalogCircuitZkProver> = lazy {
        org.siros.sdk.keystore.CatalogCircuitZkProver(org.siros.sdk.credentials.ZkCircuitClient(sources = emptyList()), null)
    }

    private fun circuitZkWallet(support: org.siros.sdk.credentials.CircuitZkSupport?, keystore: KeystoreManager): SirosWallet {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val store = FakeCredentialStore(mutableListOf(
            StoredCredential(
                id = 1L, format = "mso_mdoc", raw = "raw",
                metadata = CredentialMetadata(doctype = "test.doctype.1"), batchId = 1L, instanceId = 0,
            ),
        ))
        return newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
            "circuitZkSupport" to support,
            "defaultCircuitZkProverHolder" to defaultCatalogProverHolder(),
        )
    }

    private fun fittingSupport() = org.siros.sdk.credentials.CircuitZkSupport(
        planner = { _, _ -> org.siros.sdk.credentials.CircuitZkPlanResult.Plan(org.siros.sdk.credentials.CircuitZkPlan(emptyList())) },
        circuits = {
            listOf(org.siros.sdk.credentials.CircuitZkCircuit("sys", "c1", setOf("test.doctype.1"), functions = emptySet()))
        },
    )

    @Test
    fun handleDCAPIRequest_matchedCircuitZk_isAnsweredWithAccessDeniedAndNeverSigns() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        val wallet = circuitZkWallet(fittingSupport(), keystore)

        org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
            kotlinx.coroutines.runBlocking {
                wallet.handleDCAPIRequest(signedCircuitZkRequest("https://rp.example"), origin = "https://rp.example")
            }
        }
        coVerify(exactly = 0) { keystore.signVpToken(any(), any(), any(), any()) }
    }

    @Test
    fun handleDCAPIRequest_circuitZkWithTheFlagOff_matchesNothing() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        val wallet = circuitZkWallet(null, keystore)

        // Nothing matches, and the answer is the silent access-denied, never the
        // "no credential matches" text that would reach the verifier.
        val e = org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
            kotlinx.coroutines.runBlocking {
                wallet.handleDCAPIRequest(signedCircuitZkRequest("https://rp.example"), origin = "https://rp.example")
            }
        }
        assertEquals("DC API request refused (protocol=openid4vp-v1-signed)", e.message)
        coVerify(exactly = 0) { keystore.signVpToken(any(), any(), any(), any()) }
    }

    @Test
    fun handleDCAPIRequest_mixedCircuitZkAndOrdinaryQuery_withTheFlagOff_isRefusedNotPartlyAnswered() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        val wallet = circuitZkWallet(null, keystore)

        val mixed = signedCircuitZkRequest(
            "https://rp.example",
            extraQueries = """,{"id":"p","format":"mso_mdoc","meta":{"source_format":"mso_mdoc","doctype_value":"test.doctype.1"}}""",
        )
        val e = org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
            kotlinx.coroutines.runBlocking { wallet.handleDCAPIRequest(mixed, origin = "https://rp.example") }
        }
        assertEquals("DC API request refused (protocol=openid4vp-v1-signed)", e.message)
        coVerify(exactly = 0) { keystore.signVpToken(any(), any(), any(), any()) }
    }

    @Test
    fun handleDCAPIRequest_circuitZkQueryWithoutAnId_withTheFlagOff_isRefusedNotPartlyAnswered() = runTest(dispatcher) {
        // The matcher drops a query with no string id, so no circuit_zk result is left to look at; the request
        // still contains the query and must not be answered by its ordinary sibling alone.
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        val wallet = circuitZkWallet(null, keystore)

        val request = signedCircuitZkRequest(
            "https://rp.example",
            extraQueries = """,{"id":"p","format":"mso_mdoc","meta":{"source_format":"mso_mdoc","doctype_value":"test.doctype.1"}}""",
            circuitQueryId = null,
        )
        val e = org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
            kotlinx.coroutines.runBlocking { wallet.handleDCAPIRequest(request, origin = "https://rp.example") }
        }
        assertEquals("DC API request refused (protocol=openid4vp-v1-signed)", e.message)
        coVerify(exactly = 0) { keystore.signVpToken(any(), any(), any(), any()) }
    }

    @Test
    fun handleDCAPIRequest_circuitZkValidatorRefusal_neverLeaksTheRuleId() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        val base = fittingSupport()
        val wallet = circuitZkWallet(
            org.siros.sdk.credentials.CircuitZkSupport(
                base.planner,
                { org.siros.sdk.credentials.CircuitZkVerdict.AccessDenied("secret-rule-id-123") },
                base.circuits,
            ),
            keystore,
        )
        val e = org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
            kotlinx.coroutines.runBlocking {
                wallet.handleDCAPIRequest(signedCircuitZkRequest("https://rp.example"), origin = "https://rp.example")
            }
        }
        assertFalse(e.message!!.contains("secret-rule-id-123"))
        assertFalse(e.toString().contains("secret-rule-id-123"))
        coVerify(exactly = 0) { keystore.signVpToken(any(), any(), any(), any()) }
    }

    // ── circuit_zk over the DC API (fake trust, planner, prover and signer; test CA) ──

    private object CzkFixtures {
        const val DOCTYPE = "eu.europa.ec.eudi.nym_auth.1"
        const val OTHER_DOCTYPE = "org.example.other.1"
        const val ORIGIN = "https://rp.example"
        val root = ByteArray(32) { (it * 5 + 1).toByte() }
        fun resource(name: String) = checkNotNull(CzkFixtures::class.java.getResourceAsStream("/circuitzk/$name")) { name }.readBytes().decodeToString()
        private fun pemDer(pem: String) = java.util.Base64.getMimeDecoder().decode(pem.lines().filter { !it.startsWith("-----") }.joinToString(""))
        val leafDer: ByteArray by lazy { pemDer(resource("leaf.pem")) }
        val caDer: ByteArray by lazy { pemDer(resource("ca.pem")) }
        val leafKey: java.security.interfaces.ECPrivateKey by lazy {
            java.security.KeyFactory.getInstance("EC").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pemDer(resource("leaf-key.pem")))) as java.security.interfaces.ECPrivateKey
        }
        fun hkdf(info: ByteArray, length: Int): ByteArray {
            fun mac(k: ByteArray, d: ByteArray) = javax.crypto.Mac.getInstance("HmacSHA256").apply { init(javax.crypto.spec.SecretKeySpec(k, "HmacSHA256")) }.doFinal(d)
            return mac(mac(ByteArray(32), root), info + byteArrayOf(1)).copyOf(length)
        }
        /**
         * The Credential Issuer Identifier the fixtures store with their credentials, WITH a trailing slash on purpose:
         * the device seed (and so psc) is derived from the string exactly as stored, so a normalised form would not match.
         */
        const val ISSUER = "https://issuer.example/"

        /** An independent `lp(x)` of privatedata-spec 5.4.1: 2-byte big-endian length, then the UTF-8 bytes. */
        private fun lp(x: String) = x.toByteArray().let { byteArrayOf((it.size shr 8).toByte(), it.size.toByte()) + it }

        fun seedFor(docType: String, issuer: String) = hkdf("org.siros.private_seed/v2".toByteArray() + lp(docType) + lp(issuer), 16)
        val seed get() = seedFor(DOCTYPE, ISSUER)
        val psc get() = pscFor(DOCTYPE)
        fun pscFor(docType: String, issuer: String = ISSUER) = java.security.MessageDigest.getInstance("SHA-256").digest(seedFor(docType, issuer))

        fun mdoc(
            psc: ByteArray = this.psc, birth: String = "2000-06-15", docType: String = DOCTYPE, ssc: ByteArray = ByteArray(32) { 9 },
            /** Further elements of the doctype namespace (a claim a predicate can be about). */
            extra: List<Pair<String, com.upokecenter.cbor.CBORObject>> = emptyList(),
        ): String {
            fun c(o: Any) = com.upokecenter.cbor.CBORObject.FromObject(o)
            fun item(id: Long, name: String, v: com.upokecenter.cbor.CBORObject): com.upokecenter.cbor.CBORObject {
                val m = com.upokecenter.cbor.CBORObject.NewMap()
                m[c("digestID")] = c(id); m[c("random")] = c(ByteArray(16)); m[c("elementIdentifier")] = c(name); m[c("elementValue")] = v
                return com.upokecenter.cbor.CBORObject.FromObjectAndTag(m.EncodeToBytes(), 24)
            }
            val items = com.upokecenter.cbor.CBORObject.NewArray()
            items.Add(item(0, "birth_date", com.upokecenter.cbor.CBORObject.FromObjectAndTag(birth, 1004)))
            items.Add(item(1, "ssc", c(ssc)))
            items.Add(item(2, "psc", c(psc)))
            extra.forEachIndexed { i, (name, v) -> items.Add(item(3L + i, name, v)) }
            val ns = com.upokecenter.cbor.CBORObject.NewMap(); ns[c(docType)] = items
            val mso = com.upokecenter.cbor.CBORObject.NewMap(); mso[c("docType")] = c(docType)
            val unprotected = com.upokecenter.cbor.CBORObject.NewMap(); unprotected[c(33)] = c(leafDer)
            val auth = com.upokecenter.cbor.CBORObject.NewArray()
            auth.Add(c(ByteArray(0))); auth.Add(unprotected)
            auth.Add(c(com.upokecenter.cbor.CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes())); auth.Add(c(ByteArray(64)))
            val signed = com.upokecenter.cbor.CBORObject.NewMap(); signed[c("nameSpaces")] = ns; signed[c("issuerAuth")] = auth
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signed.EncodeToBytes())
        }
    }

    /** A request signed with the test leaf key and carrying the test chain in `x5c`. */
    private fun czkRequest(
        clientId: String = "x509_san_dns:rp.example",
        origins: String? = """["${CzkFixtures.ORIGIN}"]""",
        protocol: String = "openid4vp-v1-signed",
        signed: Boolean = true,
        nonce: String = "czk-nonce-1",
        queryIds: List<String> = listOf("q"),
        /** The `doctype_value` of each query, in order; the nym_auth doctype for all when null. */
        queryDoctypes: List<String>? = null,
        /** A raw `transaction_data` JSON array to carry, or none. */
        transactionData: String? = null,
        /** Raw credential-query JSON objects appended after the circuit_zk queries, each led by a comma. */
        extraQueries: String = "",
    ): String {
        val query = """{"credentials":[""" + queryIds.withIndex().joinToString(",") { (i, id) ->
            """{"id":"$id","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"${queryDoctypes?.get(i) ?: CzkFixtures.DOCTYPE}"}}"""
        } + "$extraQueries]}"
        val claims = com.nimbusds.jwt.JWTClaimsSet.parse(
            """{"client_id":"$clientId","nonce":"$nonce","response_mode":"dc_api","dcql_query":$query""" +
                (origins?.let { ""","expected_origins":$it""" } ?: "") +
                (transactionData?.let { ""","transaction_data":$it""" } ?: "") + "}"
        )
        if (!signed) {
            return wrapDCAPIRequest("openid4vp-v1-unsigned", Json.parseToJsonElement(claims.toString()).jsonObject)
        }
        val header = com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
            .x509CertChain(listOf(com.nimbusds.jose.util.Base64.encode(CzkFixtures.leafDer), com.nimbusds.jose.util.Base64.encode(CzkFixtures.caDer)))
            .build()
        val jwt = com.nimbusds.jwt.SignedJWT(header, claims).also { it.sign(com.nimbusds.jose.crypto.ECDSASigner(CzkFixtures.leafKey)) }
        return wrapDCAPIRequest(protocol, buildJsonObject { put("request", jwt.serialize()) })
    }

    private class CzkSetup(
        val wallet: SirosWallet,
        val apiClient: BackendApiClient,
        val history: MutableList<PresentationRecord>,
        val prover: CountingCzkProver,
        val trustRequests: MutableList<JsonObject> = mutableListOf(),
        /** Every consent request the wallet asked, in order. */
        val consents: MutableList<org.siros.sdk.credentials.PresentationConsentRequest> = mutableListOf(),
        /** The order of the steps that touch a secret or the user: `consent`, `seed`, `sign`, `prove`. */
        val events: MutableList<String> = mutableListOf(),
    )

    private class CountingCzkProver(val inner: org.siros.sdk.keystore.CircuitZkProver) : org.siros.sdk.keystore.CircuitZkProver {
        var calls = 0
        var events: MutableList<String>? = null
        /** When set, the prover asks the signer for a signature first, like a real one. */
        var signs = false
        /** The last input the prover was given (its session transcript, for one). */
        var lastInput: org.siros.sdk.keystore.CircuitZkProveInput? = null
        val inputs = mutableListOf<org.siros.sdk.keystore.CircuitZkProveInput>()
        override val isFake get() = inner.isFake
        override suspend fun prove(input: org.siros.sdk.keystore.CircuitZkProveInput): org.siros.sdk.keystore.CircuitZkProveOutput {
            calls++
            lastInput = input
            inputs += input
            events?.add("prove")
            if (signs) input.signer.sign(-7, byteArrayOf(1, 2, 3))
            return inner.prove(input)
        }
    }

    /** What escaped a signing launch of a czkSetup wallet (its scope has no other handler, like the real one). */
    private val czkUncaught = mutableListOf<Throwable>()

    private fun czkSetup(
        functions: List<org.siros.sdk.credentials.CircuitZkFunction> = listOf(
            org.siros.sdk.credentials.CircuitZkFunction(
                "pseudonym", "n",
                Json.parseToJsonElement("""{"config":"known-offender-matching-psc","ver":1,"prf":"sha-256"}""").jsonObject,
            ),
        ),
        /** Default: the PDP supplies the x509_san_dns identifier (the bare DNS name, as go-trust derives it). */
        trust: suspend () -> JsonObject = czkIds("x509_san_dns" to "rp.example"),
        /** The wallet's ORDERED supported verifier-id types. */
        types: List<String> = VerifierIdTypeOrder.DEFAULT,
        /** Optional host-registered sources; the PDP's AuthZEN source is always tried first per type. */
        sources: List<VerifierIdSource> = emptyList(),
        psc: ByteArray = CzkFixtures.psc,
        birth: String = "2000-06-15",
        flagOn: Boolean = true,
        localOnlyTrust: Boolean = false,
        /** Replaces the default single credential (id 1). */
        credentials: List<StoredCredential>? = null,
        /** Further doctypes the (single) circuit serves. */
        extraDocTypes: Set<String> = emptySet(),
        /** The circuit declares these `capabilities`, so only the matcher ([serving]) can select it. */
        capabilities: String? = null,
        serving: org.siros.sdk.credentials.CircuitZkServing? = null,
        /** Replaces the wallet's seed source (the allocated test wallet has none). */
        secretSeedSource: CredentialSecretSeedSource? = null,
        /** No prover is configured, so the wallet uses its default (the catalog prover without a native half). */
        defaultProver: Boolean = false,
        /** The user's answer to the presentation consent; the default consents. */
        consent: suspend (org.siros.sdk.credentials.PresentationConsentRequest) -> Boolean = { true },
        /** No presentation consent handler is registered at all. */
        noConsentHandler: Boolean = false,
        /** The prover asks the signer for a signature, like a real one. */
        proverSigns: Boolean = false,
        /** The request offers the test circuit (`system_id_values` / `proof_system_values`); false: it states no list. */
        offersCircuit: Boolean = true,
        /** Replaces the fake prover (which knows only the rulebook functions). */
        innerProver: org.siros.sdk.keystore.CircuitZkProver? = null,
        /** Plans each query differently: the functions of the query at this index (overrides [functions]). */
        functionsPerQuery: ((Int) -> List<org.siros.sdk.credentials.CircuitZkFunction>)? = null,
        /** The predicate functions the wallet can describe; null is the wallet's default (age_check only). */
        predicates: org.siros.sdk.credentials.PredicateFunctions? = null,
        /** Functions (id) the circuit and the validator accept besides the rulebook ones: their rules are empty. */
        extraFunctions: Set<String> = emptySet(),
        /** Called with the client_metadata the planner is given for each query. */
        onPlan: (JsonObject?) -> Unit = {},
    ): CzkSetup {
        var plannedQueries = 0
        val consents = mutableListOf<org.siros.sdk.credentials.PresentationConsentRequest>()
        val events = mutableListOf<String>()
        val apiClient = mockk<BackendApiClient>()
        val trustRequests = mutableListOf<JsonObject>()
        coEvery { apiClient.evaluateTrust(any()) } coAnswers { trustRequests += firstArg<JsonObject>(); trust() }
        val keystore = mockk<KeystoreManager>(moreInterfaces = arrayOf(org.siros.sdk.keystore.HolderWitnessSource::class))
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("kid", "ES256", 0L))
        coEvery { keystore.sign(any(), any(), any()) } coAnswers { events += "sign"; ByteArray(64) }
        val seedSource = org.siros.sdk.keystore.FixedRootHolderWitnessSource(CzkFixtures.root)
        every { (keystore as org.siros.sdk.keystore.HolderWitnessSource).circuitZkPresenter(any(), any(), any(), any(), any(), any(), any()) } answers {
            seedSource.circuitZkPresenter(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6))
        }
        val store = FakeCredentialStore((credentials ?: listOf(
            StoredCredential(id = 1L, format = "mso_mdoc", raw = CzkFixtures.mdoc(psc, birth), credentialIssuerIdentifier = CzkFixtures.ISSUER,
                metadata = CredentialMetadata(name = "Nym"), batchId = 1L, instanceId = 0),
        )).toMutableList())
        val registry = VerifierIdRegistry(types, sources)
        val circuits = org.siros.sdk.credentials.CircuitZkCircuitSource {
            listOf(org.siros.sdk.credentials.CircuitZkCircuit("sys", "c1", setOf(CzkFixtures.DOCTYPE) + extraDocTypes, functions = setOf("pseudonym", "age_check") + extraFunctions, capabilities = capabilities))
        }
        val support = org.siros.sdk.credentials.CircuitZkSupport(
            // The plan's raw query is the query itself (its doctype_value is what the presenter checks the credential against).
            // The request offers the test circuit (a response states an offered circuit_id and proof_system).
            planner = { query, cm ->
                onPlan(cm)
                val fs = functionsPerQuery?.invoke(plannedQueries++) ?: functions
                org.siros.sdk.credentials.CircuitZkPlanResult.Plan(
                    org.siros.sdk.credentials.CircuitZkPlan(
                        fs,
                        if (offersCircuit) org.siros.sdk.credentials.CircuitZkCircuitFilter(listOf("sys"), listOf("c1")) else null,
                        raw = query,
                    ),
                )
            },
            validator = if (extraFunctions.isEmpty()) defaultCircuitZkValidator(circuits) else org.siros.sdk.credentials.RulebookCircuitZkValidator(
                rules = extraFunctions.fold(org.siros.sdk.credentials.CircuitZkRuleSet.rulebookV04()) { r, id ->
                    r.withFunction(id, org.siros.sdk.credentials.CircuitZkFunctionRules(null, "$id-count", emptyList()))
                },
                circuits = circuits,
            ),
            circuits = circuits,
            serving = serving,
        )
        val history = mutableListOf<PresentationRecord>()
        val prover = CountingCzkProver(innerProver ?: org.siros.sdk.keystore.FakeCircuitZkProver.optIn()).also { it.events = events; it.signs = proverSigns }
        val trackedSeeds = secretSeedSource?.let { inner -> CredentialSecretSeedSource { id -> events += "seed"; inner.secretSeed(id) } }
        val consentHandler = PresentationConsentHandler { r -> events += "consent"; consents += r; consent(r) }
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob() + kotlinx.coroutines.CoroutineExceptionHandler { _, t -> czkUncaught += t }),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to store,
            "_presentationHistory" to history,
            "config" to WalletConfig(
                backendUrl = "https://backend.example",
                readerTrustEvaluationMode = if (localOnlyTrust) MdocTrustEvaluationMode.LOCAL_ONLY else null,
                circuitZkPredicateFunctions = predicates ?: org.siros.sdk.credentials.PredicateFunctions.DEFAULT,
            ),
            "circuitZkSupport" to (if (flagOn) support else null),
            *(if (defaultProver) arrayOf("defaultCircuitZkProverHolder" to defaultCatalogProverHolder()) else arrayOf("circuitZkProver" to prover)),
            "verifierIdRegistry" to registry,
            *(if (trackedSeeds != null) arrayOf("credentialSecretSeedSource" to trackedSeeds) else emptyArray()),
            "presentationConsentHandler" to (if (noConsentHandler) null else consentHandler),
        )
        return CzkSetup(wallet, apiClient, history, prover, trustRequests, consents, events)
    }

    /** [ids] is what the picker reported; nothing is chosen for the user, so a call without one is refused. */
    private fun czkRun(s: CzkSetup, raw: String, origin: String = CzkFixtures.ORIGIN, ids: List<Long> = listOf(1L)) =
        kotlinx.coroutines.runBlocking { s.wallet.handleDCAPIRequest(raw, origin, ids) }

    private fun czkRefused(
        s: CzkSetup,
        raw: String,
        origin: String = CzkFixtures.ORIGIN,
        reason: org.siros.sdk.wallet.dcapi.DCAPIRefusalReason? = null,
        ids: List<Long> = listOf(1L),
    ) {
        val e = org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) { czkRun(s, raw, origin, ids) }
        // The message (and so anything that reaches a log or the verifier) is the same for every reason.
        assertEquals("DC API request refused (protocol=${e.protocol})", e.message)
        if (reason != null) assertEquals(reason, e.reason)
        assertTrue(s.history.isEmpty())
    }

    private val czkLogs = mutableListOf<String>()
    private val czkTree = object : timber.log.Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) { czkLogs += message + (t?.toString() ?: "") }
    }

    private fun czkExpectedPseudonym(verifierId: String) = org.siros.sdk.credentials.NymPseudonym.derive(
        "known-offender-matching-psc", CzkFixtures.seed, verifierId = verifierId,
    )

    private fun czkSetupWithIssuer(issuer: String?) = czkSetup(
        credentials = listOf(
            StoredCredential(
                id = 1L, format = "mso_mdoc", raw = CzkFixtures.mdoc(CzkFixtures.psc, "2000-06-15"),
                credentialIssuerIdentifier = issuer, metadata = CredentialMetadata(name = "Nym"), batchId = 1L, instanceId = 0,
            ),
        ),
    )

    @Test
    fun circuitZkDcApi_theDevicePscFollowsTheIssuerExactlyAsStored_atPresentationToo() = runTest(dispatcher) {
        // The fixture credential committed to the seed of "https://issuer.example/" (trailing slash), the stored string.
        val ok = czkRun(czkSetupWithIssuer(CzkFixtures.ISSUER), czkRequest())
        assertEquals(setOf("n"), czkDecoded(ok.responseJson).results.keys)
        // The same issuer without the slash is another string, another seed, another psc: refused, never normalised.
        czkRefused(czkSetupWithIssuer("https://issuer.example"), czkRequest())
        // A credential stored without its issuer cannot derive the device seed at all.
        czkRefused(czkSetupWithIssuer(null), czkRequest())
    }

    @Test
    fun circuitZkDcApi_success_presentationDecodesAndPseudonymMatchesIndependentRecompute() = runTest(dispatcher) {
        timber.log.Timber.plant(czkTree)
        try {
            val s = czkSetup()
            val result = czkRun(s, czkRequest())

            assertEquals(listOf(1L), result.credentialIds)
            val envelope = Json.parseToJsonElement(result.responseJson).jsonObject
            assertEquals("openid4vp-v1-signed", envelope["protocol"]?.jsonPrimitive?.content)
            val decoded = czkDecoded(result.responseJson)
            assertEquals(
                org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:rp.example")),
                decoded.results["n"],
            )
            assertEquals(setOf("n"), decoded.results.keys)
            // The response shape (rulebook v0.4 ZkpPresentation): exactly these members, the offered system id, the issuer key set, proof_time.
            assertEquals(setOf("system_id", "proof", "issuer_key_set", "proof_time", "results"), decoded.members)
            assertEquals("c1", decoded.cbor["system_id"].AsString())
            assertTrue(decoded.cbor["issuer_key_set"].size() > 0)
            assertTrue(decoded.cbor["proof_time"].HasMostOuterTag(0))
            assertEquals(20, decoded.cbor["proof_time"].AsString().length)
            assertEquals(1, s.prover.calls)
            // History: a ZK proof, no claim names, no pseudonym.
            val record = s.history.single()
            assertTrue(record.zkProof)
            assertTrue(record.requestedClaims.isEmpty())
            coVerify(exactly = 1) { s.apiClient.evaluateTrust(any()) }
            // No log carries request contents or the verifier id.
            for (line in czkLogs) {
                assertFalse(line, line.contains("rp.example"))
                assertFalse(line, line.contains("czk-nonce-1"))
            }
        } finally {
            timber.log.Timber.uproot(czkTree)
        }
    }

    @Test
    fun circuitZkDcApi_aResponseThatFailsTheWalletsOwnCheck_isNeverSent() = runTest(dispatcher) {
        // The legacy claim-disclosure function has no result shape in the circuit_zk response spec, so a verifier must
        // refuse its response (result_function_unknown). The presenter builds it happily (this prover "proves" it): the
        // wallet's own CircuitZkResponseValidator check is what stops it leaving the device.
        val legacy = org.siros.sdk.credentials.CircuitZkFunction(
            org.siros.sdk.credentials.CircuitZkLegacyDisclosure.FUNCTION_ID, "d",
            Json.parseToJsonElement("""{"claims":["birth_date"],"systems":[{"id":"c","system":"sys"}]}""").jsonObject,
        )
        val everythingTrue = object : org.siros.sdk.keystore.CircuitZkProver {
            override suspend fun prove(input: org.siros.sdk.keystore.CircuitZkProveInput) = org.siros.sdk.keystore.CircuitZkProveOutput(
                proof = byteArrayOf(1, 2, 3),
                results = input.plan.functions.associate { it.handle to org.siros.sdk.credentials.ResultValue.Predicate },
            )
        }
        val s = czkSetup(
            functions = listOf(legacy),
            innerProver = everythingTrue,
            extraFunctions = setOf(org.siros.sdk.credentials.CircuitZkLegacyDisclosure.FUNCTION_ID),
        )
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.PROOF_FAILED)
        // The proof was made (the request got as far as the prover) and the response was still not sent.
        assertEquals(1, s.prover.calls)
    }

    // ── zkp_req over the engine (QR / same-device redirect, direct_post.jwt) ──

    private val redirectThumbprint = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { (it + 1).toByte() })
    private val redirectClientId = "x509_san_dns:rp.example"

    private class EngineCzk(
        val s: CzkSetup,
        val engine: WalletEngineSession,
        val match: MutableSharedFlow<MatchRequestMessage>,
        val sign: MutableSharedFlow<SignRequestMessage>,
        val progress: MutableSharedFlow<FlowProgressMessage>,
        val complete: MutableSharedFlow<FlowCompleteMessage>,
        val errors: MutableSharedFlow<FlowErrorMessage>,
        val state: MutableStateFlow<WalletEngineSession.State>,
        val metadataSeen: MutableList<JsonObject?>,
        val generations: MutableStateFlow<Int> = MutableStateFlow(0),
    )

    private fun TestScope.engineCzk(
        trusted: Boolean = true,
        consent: suspend (org.siros.sdk.credentials.PresentationConsentRequest) -> Boolean = { true },
        flagOn: Boolean = true,
        offersCircuit: Boolean = true,
        credentials: List<StoredCredential>? = null,
        /** False: nothing is put into the wallet's private state; the engine's own trust progress has to do it. */
        seedTrust: Boolean = true,
        clientId: String = redirectClientId,
        flows: List<String> = listOf("f1"),
    ): EngineCzk {
        val match = MutableSharedFlow<MatchRequestMessage>()
        val sign = MutableSharedFlow<SignRequestMessage>()
        val progress = MutableSharedFlow<FlowProgressMessage>()
        val complete = MutableSharedFlow<FlowCompleteMessage>()
        val errors = MutableSharedFlow<FlowErrorMessage>()
        val generations = MutableStateFlow(0)
        val engine = mockEngineConstructor(signRequests = sign, matchRequests = match, progressFlow = progress, flowComplete = complete, flowErrors = errors, generations = generations)
        val engineState = MutableStateFlow(WalletEngineSession.State.CONNECTED)
        every { engine.state } returns engineState
        every { engine.cancelFlow(any()) } just runs
        every { engine.sendSignRefusal(any(), any(), any()) } just runs
        every { engine.sendSignResponse(any(), vpToken = any(), messageId = any()) } just runs
        every { engine.sendSignResponse(any(), responseJwe = any(), messageId = any()) } just runs
        every { engine.sendMatchResponse(any(), any(), any()) } just runs
        val seen = mutableListOf<JsonObject?>()
        val s = czkSetup(trust = czkIds("x509_san_dns" to redirectClientId.removePrefix("x509_san_dns:")), consent = consent, flagOn = flagOn, offersCircuit = offersCircuit, credentials = credentials, onPlan = { seen += it })
        invokeConnectEngine(s.wallet, "app-token")
        advanceUntilIdle()
        // What the engine's trust step left for this flow.
        if (seedTrust) {
            @Suppress("UNCHECKED_CAST")
            for (flow in flows) (getField(s.wallet, "lastTrustResults") as MutableMap<String, TrustResult>)[flow] = TrustResult(
                trusted = trusted, identifier = clientId, entityName = "Example RP",
                context = buildJsonObject { putJsonArray("verifier_ids") { add(buildJsonObject { put("verifier_id_type", "x509_san_dns"); put("verifier_id", redirectClientId.removePrefix("x509_san_dns:")) }) } },
            )
        }
        return EngineCzk(s, engine, match, sign, progress, complete, errors, engineState, seen, generations)
    }

    private val redirectQuery = Json.parseToJsonElement(
        """{"credentials":[{"id":"q","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"${CzkFixtures.DOCTYPE}"},"_req":[{"fn_id":"pseudonym","return":"n","params":{"config":"known-offender-matching-psc","ver":1,"prf":"sha-256"}}]}]}""",
    )
    private val redirectMetadata = Json.parseToJsonElement(
        """{"vp_formats_supported":{"zkp_req":{"system_id_values":["c1"],"proof_system_values":["sys"]}},"authorization_encrypted_response_alg":"ECDH-ES"}""",
    )

    /** What the legacy redirect flow really sends: a flow_progress step with the request, the verifier and its client_metadata. */
    private suspend fun EngineCzk.matchOnce(query: kotlinx.serialization.json.JsonElement = redirectQuery, flow: String = "f1") {
        progress.emit(FlowProgressMessage(
            flowId = flow, step = "credential_selection",
            payload = buildJsonObject {
                put("dcql_query", query)
                putJsonObject("verifier") { put("client_id", redirectClientId); put("name", "Example RP") }
                put("client_metadata", redirectMetadata)
            },
        ).also { it.connectionGeneration = engineGeneration.get() }) // stamped by the session on receipt, as in production
    }

    private fun redirectSign(thumbprint: String? = redirectThumbprint, audience: String = redirectClientId, responseUri: String? = "https://rp.example/response", creds: List<String> = listOf("1"), flow: String = "f1", messageId: String = "m1") =
        SignRequestMessage(
            flowId = flow, messageId = messageId, action = "sign_presentation",
            params = SignRequestParams(
                audience = audience, nonce = "n-redirect", responseUri = responseUri, verifierJwkThumbprint = thumbprint,
                credentialsToInclude = creds.map { org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "q", credentialId = it) },
            ),
        )

    @Test
    fun circuitZkRedirect_aZkpReqRequestRelayedByTheEngine_isMatchedProvedAndAnsweredWithTheCborPresentation() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        // The verifier's client_metadata reached the planner, and the credential was offered.
        assertEquals(listOf<kotlinx.serialization.json.JsonElement?>(redirectMetadata), e.metadataSeen)
        val consent = slot<JsonObject>()
        verify(exactly = 1) { e.engine.sendFlowAction("f1", "consent", capture(consent)) }
        val selected = consent.captured["selected_credentials"]!!.jsonArray.single().jsonObject
        assertEquals("q", selected["credential_query_id"]?.jsonPrimitive?.content)
        assertEquals("1", selected["credential_id"]?.jsonPrimitive?.content)
        // A zkp_req query discloses no claims: the engine's consent check would refuse any.
        assertEquals(0, selected["disclosed_claims"]!!.jsonArray.size)
        // Nothing is recorded as presented before anything is proved.
        assertTrue(e.s.history.isEmpty())

        e.sign.emit(redirectSign())
        advanceUntilIdle()

        val vp = slot<String>()
        verify(exactly = 1) { e.engine.sendSignResponse("f1", vpToken = capture(vp), messageId = "m1") }
        val token = Json.parseToJsonElement(vp.captured).jsonObject
        assertEquals(setOf("q"), token.keys)
        val decoded = CzkDecoded(token["q"]!!.jsonArray.single().jsonPrimitive.content)
        assertEquals(
            org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym(redirectClientId)),
            decoded.results["n"],
        )
        // The proof is bound to the redirect OpenID4VPHandover over [client id, nonce, thumbprint, response_uri].
        org.junit.Assert.assertArrayEquals(
            org.siros.sdk.keystore.MdocDeviceResponseBuilder.buildCircuitZkRedirectSessionTranscript(redirectClientId, "n-redirect", "https://rp.example/response", redirectThumbprint),
            e.s.prover.lastInput!!.sessionTranscript,
        )
        // One consent, naming the verifier; the history records a ZK proof; the flow is not cancelled.
        assertEquals(1, e.s.consents.size)
        assertEquals("Example RP", e.s.consents.single().verifier.label)
        assertTrue(e.s.history.single().zkProof) // written once, when answered
        verify(exactly = 0) { e.engine.cancelFlow(any()) }
        verify(exactly = 0) { e.engine.sendSignRefusal(any(), any(), any()) }
    }

    /** A verifier response-encryption key as the engine sends it in `response_encryption`: public JWK with a kid. */
    private fun verifierKey() = com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256).keyID("verifier-enc-1").generate()

    private fun redirectSignEncrypted(
        key: com.nimbusds.jose.jwk.ECKey,
        verifiedClientId: String? = "x509_san_dns:rp.example",
        state: String? = "st-1",
        alg: String = "ECDH-ES",
        enc: String = "A128GCM",
    ) = redirectSign().let { m ->
        m.copy(
            params = m.params.copy(
                responseEncryption = org.siros.sdk.transport.ResponseEncryptionRequest(
                    jwk = Json.parseToJsonElement(key.toPublicJWK().toJSONString()).jsonObject, alg = alg, enc = enc,
                ),
                // The engine's own thumbprint of the same key (they agree; a mismatch is refused, see below).
                verifierJwkThumbprint = key.computeThumbprint().toString(),
                state = state,
                verifiedRequest = org.siros.sdk.transport.VerifiedRequest(clientId = verifiedClientId, responseMode = "direct_post.jwt", signed = true, signatureVerification = "verified"),
            ),
        )
    }

    @Test
    fun circuitZkRedirect_withResponseEncryption_answersOnlyWithAResponseJweTheVerifierCanOpen() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        val key = verifierKey()
        e.sign.emit(redirectSignEncrypted(key, verifiedClientId = "x509_san_dns:rp.example"))
        advanceUntilIdle()

        val jwe = slot<String>()
        verify(exactly = 1) { e.engine.sendSignResponse("f1", responseJwe = capture(jwe), messageId = "m1") }
        // NOTHING but the JWE: no vp_token alongside, no refusal.
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        verify(exactly = 0) { e.engine.sendSignRefusal(any(), any(), any()) }
        // Five non-empty segments (direct ECDH-ES has an empty encrypted-key segment only), header as the engine validates it.
        val segments = jwe.captured.split(".")
        assertEquals(5, segments.size)
        // Only the encrypted-key segment may be empty, and only for direct ECDH-ES (this request's alg).
        segments.forEachIndexed { i, seg -> if (i != 1) assertTrue("segment $i is empty", seg.isNotEmpty()) }
        val parsed = com.nimbusds.jose.JWEObject.parse(jwe.captured)
        val protectedHeader = Json.parseToJsonElement(String(java.util.Base64.getUrlDecoder().decode(segments[0]))).jsonObject
        assertEquals("ECDH-ES", protectedHeader["alg"]!!.jsonPrimitive.content)
        assertEquals("A128GCM", protectedHeader["enc"]!!.jsonPrimitive.content)
        assertEquals("verifier-enc-1", protectedHeader["kid"]!!.jsonPrimitive.content)
        assertEquals("ECDH-ES", parsed.header.algorithm.name)
        assertEquals("A128GCM", parsed.header.encryptionMethod.name)
        assertEquals("verifier-enc-1", parsed.header.keyID)
        parsed.decrypt(com.nimbusds.jose.crypto.ECDHDecrypter(key))
        val claims = Json.parseToJsonElement(parsed.payload.toString()).jsonObject
        assertEquals("st-1", claims["state"]!!.jsonPrimitive.content)
        assertEquals("x509_san_dns:rp.example", claims["aud"]!!.jsonPrimitive.content)
        val token = claims["vp_token"]!!.jsonObject
        assertEquals(setOf("q"), token.keys)
        val decoded = CzkDecoded(token["q"]!!.jsonArray.single().jsonPrimitive.content)
        assertEquals(org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym(redirectClientId)), decoded.results["n"])
    }

    @Test
    fun circuitZkRedirect_theJarmAudienceIsTheEnginesVerifiedClientId_notTheSignRequestAudience() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        val key = verifierKey()
        e.sign.emit(redirectSignEncrypted(key, verifiedClientId = "x509_san_dns:verified.example"))
        advanceUntilIdle()
        val jwe = slot<String>()
        verify(exactly = 1) { e.engine.sendSignResponse("f1", responseJwe = capture(jwe), messageId = "m1") }
        val parsed = com.nimbusds.jose.JWEObject.parse(jwe.captured).also { it.decrypt(com.nimbusds.jose.crypto.ECDHDecrypter(key)) }
        assertEquals("x509_san_dns:verified.example", Json.parseToJsonElement(parsed.payload.toString()).jsonObject["aud"]!!.jsonPrimitive.content)
    }

    @Test
    fun circuitZkRedirect_withResponseEncryptionButNoVerifiedClientId_isRefusedAndNothingIsSent() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSignEncrypted(verifierKey(), verifiedClientId = null))
        advanceUntilIdle()
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", "jarm-audience") }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), responseJwe = any(), messageId = any()) }
    }

    @Test
    fun circuitZkRedirect_anEngineThumbprintThatIsNotTheEncryptionKeys_isRefusedAndNothingIsSent() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        // The transcript's thumbprint and the key the JWE goes to must be the same key's: one source, a mismatch is refused.
        val m = redirectSignEncrypted(verifierKey())
        e.sign.emit(m.copy(params = m.params.copy(verifierJwkThumbprint = redirectThumbprint)))
        advanceUntilIdle()
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", "handover-thumbprint") }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), responseJwe = any(), messageId = any()) }
    }

    @Test
    fun theSessionTranscriptThumbprintOfADirectPostJwtRequestComesFromTheEncryptionKey_aMismatchIsRefused() {
        val wallet = newWallet()
        val key = verifierKey()
        val own = key.computeThumbprint().toString()
        val encryption = org.siros.sdk.transport.ResponseEncryptionRequest(Json.parseToJsonElement(key.toPublicJWK().toJSONString()).jsonObject, "ECDH-ES", "A128GCM")
        // No engine value, or the same one: the key's own thumbprint.
        assertEquals(own, wallet.transcriptThumbprint(SignRequestParams(responseEncryption = encryption)))
        assertEquals(own, wallet.transcriptThumbprint(SignRequestParams(responseEncryption = encryption, verifierJwkThumbprint = own)))
        // A different engine value: refused, never preferred.
        org.junit.Assert.assertThrows(WalletException::class.java) {
            wallet.transcriptThumbprint(SignRequestParams(responseEncryption = encryption, verifierJwkThumbprint = redirectThumbprint))
        }
        // An unusable key: refused.
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            wallet.transcriptThumbprint(SignRequestParams(responseEncryption = org.siros.sdk.transport.ResponseEncryptionRequest(buildJsonObject { put("kty", JsonPrimitive("EC")) }, "ECDH-ES", "A128GCM")))
        }
        // A plain mode (no response encryption) keeps the engine's value.
        assertEquals(redirectThumbprint, wallet.transcriptThumbprint(SignRequestParams(verifierJwkThumbprint = redirectThumbprint)))
        assertEquals(null, wallet.transcriptThumbprint(SignRequestParams()))
    }

    @Test
    fun legacySignPresentation_overDirectPostJwt_anEngineThumbprintThatIsNotTheEncryptionKeys_isAnsweredWithAnErrorBeforeAnythingIsSigned() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val keystore = mockk<KeystoreManager>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to keystore,
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-t", messageId = "m-t", action = "sign_presentation",
                params = SignRequestParams(
                    audience = "admin", nonce = "n", responseEncryption = blindResponseEncryption(), verifierJwkThumbprint = redirectThumbprint,
                    verifiedRequest = org.siros.sdk.transport.VerifiedRequest(clientId = "client-id-1", responseMode = "direct_post.jwt"),
                ),
            )
        )
        repeat(5) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            advanceUntilIdle()
        }
        verify(exactly = 1) { engine.sendSignResponse(flowId = "flow-t", messageId = "m-t", error = any()) }
        coVerify(exactly = 0) { keystore.signMdocPresentation(any(), any(), any(), any(), any(), any(), any()) }
        coVerify(exactly = 0) { keystore.signVpToken(any(), any(), any(), any(), any()) }
    }

    @Test
    fun circuitZkRedirect_anUnusableVerifierKey_isRefusedAndNothingIsSent() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        // An algorithm pair the key cannot be used with: the response cannot be built, so the wallet refuses rather than send a plain vp_token.
        e.sign.emit(redirectSignEncrypted(verifierKey(), alg = "RSA-OAEP-256"))
        advanceUntilIdle()
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", "response-encryption") }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), responseJwe = any(), messageId = any()) }
    }

    @Test
    fun circuitZkRedirect_aSelectedCredentialDeletedBeforeSigning_isRefusedNotSilentlyDropped() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        // The credential the user picked disappears between the match and the sign request.
        (getField(e.s.wallet, "credentialStore") as org.siros.sdk.credentials.CredentialStore).delete(1L)
        e.sign.emit(redirectSignEncrypted(verifierKey()))
        advanceUntilIdle()
        // Correlated refusal (message_id echoed), nothing proved, nothing sent in the clear or encrypted.
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", any()) }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), responseJwe = any(), messageId = any()) }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        assertEquals(0, e.s.prover.calls)
    }

    @Test
    fun circuitZkRedirect_anOversizedResponse_isRefusedWithTheMessageIdNotLeftToTheEnginesTimeout() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        // `state` is echoed into the encrypted claims: 5 MiB of it makes the JWE exceed the engine's 4 MiB limit.
        e.sign.emit(redirectSignEncrypted(verifierKey(), state = "s".repeat(5 * 1024 * 1024)))
        advanceUntilIdle()
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", "response-encryption") }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), responseJwe = any(), messageId = any()) }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
    }

    @Test
    fun circuitZkRedirect_aSocketThatRejectsTheAnswerAndTheRefusal_letsNoExceptionEscape() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        every { e.engine.sendSignResponse(any(), responseJwe = any(), messageId = any()) } throws IllegalStateException("socket refused the frame")
        every { e.engine.sendSignRefusal(any(), any(), any()) } throws IllegalStateException("socket refused the frame")
        e.sign.emit(redirectSignEncrypted(verifierKey()))
        advanceUntilIdle() // an exception escaping the signing launch would fail the test here
        verify(exactly = 1) { e.engine.sendSignResponse("f1", responseJwe = any(), messageId = "m1") }
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", "error") }
        assertTrue("nothing escaped the launch: $czkUncaught", czkUncaught.isEmpty())
    }

    @Test
    fun circuitZkRedirect_aRefusalSurvivesARejectingSocket() = runTest(dispatcher) {
        val e = engineCzk(consent = { false })
        e.matchOnce()
        advanceUntilIdle()
        every { e.engine.sendSignRefusal(any(), any(), any()) } throws IllegalStateException("socket refused the frame")
        e.sign.emit(redirectSignEncrypted(verifierKey()))
        advanceUntilIdle()
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", "consent-declined") }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), responseJwe = any(), messageId = any()) }
        assertTrue("nothing escaped the launch: $czkUncaught", czkUncaught.isEmpty())
    }

    /** A listener whose selection callback waits for [answer]; it reports what it saw. */
    private class WaitingSelectionListener(
        val answer: kotlinx.coroutines.CompletableDeferred<List<Long>>,
        val ignoreCancellation: Boolean = false,
        val failAfterAnswer: Boolean = false,
    ) : WalletEventListener {
        var cancelled = false
        var asked = 0
        val errors = mutableListOf<Pair<String, String>>()
        override suspend fun onCredentialSelectionRequired(request: PresentationRequest): List<Long> = try {
            asked++
            val r = if (ignoreCancellation) kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { answer.await() } else answer.await()
            if (failAfterAnswer) throw IllegalStateException("the app failed after the flow was lost")
            r
        } catch (e: kotlinx.coroutines.CancellationException) {
            cancelled = true
            throw e
        }
        override fun onFlowError(flowId: String, errorMessage: String, redirectUri: String?) { errors += flowId to errorMessage }
    }

    private fun EngineCzk.currentWalletState() = getField(s.wallet, "_state").let { (it as MutableStateFlow<*>).value }

    @Test
    fun flowLost_theConnectionIsLostWhileTheConsentScreenIsUp_endsTheFlowAndDismissesTheWait() = runTest(dispatcher) {
        val e = engineCzk(seedTrust = true)
        val answer = kotlinx.coroutines.CompletableDeferred<List<Long>>()
        val listener = WaitingSelectionListener(answer)
        e.s.wallet.setEventListener(listener)
        e.matchOnce()
        runCurrent()
        // Selection is on screen and the wallet is mid-flow.
        assertTrue(e.currentWalletState() is WalletState.FlowActive)
        // The engine closed the socket: the session (and with it the flow) is gone.
        e.state.value = WalletEngineSession.State.RECONNECTING
        runCurrent()
        assertTrue("the pending selection was cancelled so the UI can dismiss it", listener.cancelled)
        assertEquals(listOf("f1" to SirosWallet.FLOW_LOST_MESSAGE), listener.errors)
        assertTrue("no spinner: back to Ready", e.currentWalletState() is WalletState.Ready)
        // Nothing was sent into the void.
        verify(exactly = 0) { e.engine.sendFlowAction("f1", "decline", any()) }
        verify(exactly = 0) { e.engine.sendFlowAction("f1", "consent", any()) }
    }

    @Test
    fun flowLost_aReplacedSocketEndsTheFlowEvenWithoutAStateChange() = runTest(dispatcher) {
        val e = engineCzk()
        val answer = kotlinx.coroutines.CompletableDeferred<List<Long>>()
        val listener = WaitingSelectionListener(answer)
        e.s.wallet.setEventListener(listener)
        e.matchOnce()
        runCurrent()
        assertTrue(e.currentWalletState() is WalletState.FlowActive)
        // The session got a new socket (generation 1) with no RECONNECTING seen (it was conflated away).
        engineGeneration.incrementAndGet()
        e.generations.value = engineGeneration.get()
        runCurrent()
        assertTrue(listener.cancelled)
        assertEquals(1, listener.errors.size)
        assertTrue(e.currentWalletState() is WalletState.Ready)
    }

    @Test
    fun flowLost_anAppThatAnswersAfterwards_causesNothingToBeSentToTheNewSession() = runTest(dispatcher) {
        val e = engineCzk()
        val answer = kotlinx.coroutines.CompletableDeferred<List<Long>>()
        // The app does not honour cancellation (like a continuation nobody cancels): the user taps Decline two minutes later.
        e.s.wallet.setEventListener(WaitingSelectionListener(answer, ignoreCancellation = true))
        e.matchOnce()
        runCurrent()
        engineGeneration.incrementAndGet()
        e.generations.value = engineGeneration.get()
        e.state.value = WalletEngineSession.State.RECONNECTING
        runCurrent()
        answer.complete(emptyList()) // Decline
        runCurrent()
        verify(exactly = 0) { e.engine.sendFlowAction(any(), "decline", any()) }
        verify(exactly = 0) { e.engine.sendFlowAction(any(), "consent", any()) }
        assertTrue(e.currentWalletState() is WalletState.Ready)
    }

    private fun unknownFlow(flow: String, gen: Int = 0) = FlowErrorMessage(
        flowId = flow, step = "",
        error = org.siros.sdk.transport.engine.FlowError(code = "UNKNOWN_FLOW", message = "Flow not found or already completed"),
    ).also { it.connectionGeneration = gen }

    @Test
    fun flowLost_anUnknownFlowFrameForALiveFlowEndsItLikeALostConnection() = runTest(dispatcher) {
        val e = engineCzk()
        val answer = kotlinx.coroutines.CompletableDeferred<List<Long>>()
        val listener = WaitingSelectionListener(answer)
        e.s.wallet.setEventListener(listener)
        e.matchOnce()
        runCurrent()
        assertTrue(e.currentWalletState() is WalletState.FlowActive)
        // The user's action reached a session that does not know the flow; the engine says so.
        e.errors.emit(unknownFlow("f1"))
        runCurrent()
        assertTrue("the pending selection was cancelled", listener.cancelled)
        assertEquals(listOf("f1" to SirosWallet.FLOW_LOST_MESSAGE), listener.errors)
        assertTrue(e.currentWalletState() is WalletState.Ready)
    }

    @Test
    fun flowLost_anUnknownFlowFrameForAnEndedOrUnknownFlowIsIgnored() = runTest(dispatcher) {
        val e = engineCzk(flows = listOf("f1", "f2"))
        val listener = WaitingSelectionListener(kotlinx.coroutines.CompletableDeferred())
        e.s.wallet.setEventListener(listener)
        // A different, newer flow is active; a late UNKNOWN_FLOW for a dead one must not touch it or tell the app.
        e.matchOnce(flow = "f2")
        runCurrent()
        e.errors.emit(unknownFlow("f1-dead"))
        runCurrent()
        assertEquals("f2", (e.currentWalletState() as WalletState.FlowActive).flowId)
        assertTrue(listener.errors.isEmpty())
        // After the live flow ended once, a second frame for it is ignored too (the app is told once).
        e.errors.emit(unknownFlow("f2"))
        runCurrent()
        e.errors.emit(unknownFlow("f2"))
        runCurrent()
        assertEquals(1, listener.errors.size)
    }

    @Test
    fun flowLost_aFlowErrorWithAnUnrecognisedCodeStillDecodesAndEndsTheFlow() = runTest(dispatcher) {
        val wire = """{"type":"flow_error","flow_id":"f1","step":"","error":{"code":"SOME_FUTURE_CODE","message":"m","details":{"x":1}},"extra":true}"""
        val msg = Json { ignoreUnknownKeys = true }.decodeFromString(FlowErrorMessage.serializer(), wire)
        assertEquals("SOME_FUTURE_CODE", msg.error.code)
        val e = engineCzk()
        val listener = WaitingSelectionListener(kotlinx.coroutines.CompletableDeferred())
        e.s.wallet.setEventListener(listener)
        e.matchOnce()
        runCurrent()
        e.errors.emit(msg)
        runCurrent()
        assertTrue("the pending selection was cancelled", listener.cancelled)
        assertEquals(1, listener.errors.size)
        assertTrue(e.currentWalletState() is WalletState.Ready)
    }

    @Test
    fun flowLost_aFlowStartedOnTheNewConnectionIsNotEnded() = runTest(dispatcher) {
        val e = engineCzk(flows = listOf("f1", "f2"))
        e.s.wallet.setEventListener(WaitingSelectionListener(kotlinx.coroutines.CompletableDeferred()))
        engineGeneration.incrementAndGet()
        e.generations.value = engineGeneration.get()
        runCurrent()
        // A flow that begins after the socket was replaced lives on the new connection.
        e.matchOnce(flow = "f2")
        runCurrent()
        assertTrue(e.currentWalletState() is WalletState.FlowActive)
        assertEquals("f2", (e.currentWalletState() as WalletState.FlowActive).flowId)
    }

    @Test
    fun flowLost_aMatchRequestQueuedOnTheOldConnectionIsNeitherAskedNorAnswered() = runTest(dispatcher) {
        val (e, listener) = lostFlowSetup()
        e.replaceSocket()
        runCurrent()
        // Stamped by the session with the connection that delivered it (0), consumed after the replacement (1).
        e.match.emit(MatchRequestMessage(flowId = "f1", dcqlQuery = redirectQuery, clientMetadata = redirectMetadata))
        runCurrent()
        assertFalse(listener.cancelled)
        assertTrue(listener.errors.isEmpty())
        verify(exactly = 0) { e.engine.sendMatchResponse(any(), any(), any()) }
        assertTrue(e.currentWalletState() is WalletState.Ready)
    }

    private fun TestScope.lostFlowSetup(ignoreCancellation: Boolean = false): Pair<EngineCzk, WaitingSelectionListener> {
        val e = engineCzk(flows = listOf("f1", "f9"))
        val listener = WaitingSelectionListener(kotlinx.coroutines.CompletableDeferred(), ignoreCancellation)
        e.s.wallet.setEventListener(listener)
        return e to listener
    }

    private fun EngineCzk.replaceSocket() {
        engineGeneration.incrementAndGet()
        generations.value = engineGeneration.get()
    }

    private fun staleProgress(flow: String, step: String = "credential_selection") =
        FlowProgressMessage(flowId = flow, step = step, payload = buildJsonObject {
            put("dcql_query", redirectQuery)
            putJsonObject("verifier") { put("client_id", redirectClientId); put("name", "Example RP") }
            put("client_metadata", redirectMetadata)
        }).also { it.connectionGeneration = 0 }

    @Test
    fun flowLost_progressBufferedOnTheOldSocketAfterTheLossNeverReopensConsent() = runTest(dispatcher) {
        val (e, listener) = lostFlowSetup()
        e.matchOnce()
        runCurrent()
        e.replaceSocket()
        runCurrent()
        assertEquals(1, listener.errors.size)
        // A second selection frame of the dead flow, and the very first frame of another flow, both stamped with the old connection.
        listener.cancelled = false
        e.progress.emit(staleProgress("f1"))
        e.progress.emit(staleProgress("f9"))
        runCurrent()
        assertFalse("no consent wait was opened for either", listener.cancelled)
        assertTrue(e.currentWalletState() is WalletState.Ready)
        assertEquals("the app was told once", 1, listener.errors.size)
        verify(exactly = 0) { e.engine.sendFlowAction(any(), "consent", any()) }
    }

    @Test
    fun flowLost_anOrdinaryErrorBufferedBeforeTheLossIsNotReportedASecondTime() = runTest(dispatcher) {
        val (e, listener) = lostFlowSetup()
        e.matchOnce()
        runCurrent()
        e.replaceSocket()
        runCurrent()
        e.errors.emit(FlowErrorMessage(flowId = "f1", error = org.siros.sdk.transport.engine.FlowError(code = "x", message = "boom")))
        runCurrent()
        assertEquals(1, listener.errors.size)
    }

    @Test
    fun flowLost_aLateAnswerAfterAnOrdinaryEngineErrorSendsNothing() = runTest(dispatcher) {
        val (e, listener) = lostFlowSetup(ignoreCancellation = true)
        val answer = kotlinx.coroutines.CompletableDeferred<List<Long>>()
        e.s.wallet.setEventListener(WaitingSelectionListener(answer, ignoreCancellation = true))
        e.matchOnce()
        runCurrent()
        e.errors.emit(FlowErrorMessage(flowId = "f1", error = org.siros.sdk.transport.engine.FlowError(code = "x", message = "boom")))
        runCurrent()
        answer.complete(listOf(1L))
        runCurrent()
        verify(exactly = 0) { e.engine.sendFlowAction("f1", "consent", any()) }
        verify(exactly = 0) { e.engine.sendFlowAction("f1", "decline", any()) }
        assertNotNull(listener)
    }

    @Test
    fun flowLost_theMatchRequestRouteIsStoppedByTheLossToo_andAnswersNothing() = runTest(dispatcher) {
        val (e, listener) = lostFlowSetup()
        e.match.emit(MatchRequestMessage(flowId = "f1", dcqlQuery = redirectQuery, clientMetadata = redirectMetadata))
        runCurrent()
        e.replaceSocket()
        runCurrent()
        assertTrue("the wait of the match route was cancelled", listener.cancelled)
        assertEquals(1, listener.errors.size)
        verify(exactly = 0) { e.engine.sendMatchResponse(any(), any(), any()) }
        // The shared collector is alive: a new flow on the new connection is served.
        listener.cancelled = false
        val askedBefore = listener.asked
        // Stamped with the current connection, as the session stamps a frame it receives on the new socket.
        e.match.emit(MatchRequestMessage(flowId = "f9", dcqlQuery = redirectQuery, clientMetadata = redirectMetadata).also { it.connectionGeneration = engineGeneration.get() })
        runCurrent()
        assertEquals("the new flow's selection wait was registered and the app was asked", askedBefore + 1, listener.asked)
        assertFalse("and it is still waiting, not cancelled", listener.cancelled)
        assertEquals(1, listener.errors.size)
    }

    @Test
    fun flowLost_aBufferedSignPresentationOfALostZkpReqFlowIsNeverSignedOrAnswered() = runTest(dispatcher) {
        val (e, listener) = lostFlowSetup()
        e.matchOnce()
        runCurrent()
        e.replaceSocket()
        runCurrent()
        assertEquals(1, listener.errors.size)
        // Buffered on the old connection (stamped 0), consumed after the loss swept the flow's match state.
        var dispatched = 0
        e.s.wallet.signDispatchHook = { dispatched++ } // reached only by a request that passed the admission guards
        e.sign.emit(redirectSign())
        advanceUntilIdle()
        assertEquals("the request was rejected before dispatch", 0, dispatched)
        // Every answer shape, whatever its arguments: nothing was signed and nothing was sent for the dead flow.
        verify(exactly = 0) { e.engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) }
        verify(exactly = 0) { e.engine.sendSignRefusal(any(), any(), any()) }
    }

    @Test
    fun flowLost_aSelectionCallbackThatFailsAfterTheLossSendsNoDecline() = runTest(dispatcher) {
        val e = engineCzk()
        val answer = kotlinx.coroutines.CompletableDeferred<List<Long>>()
        e.s.wallet.setEventListener(WaitingSelectionListener(answer, ignoreCancellation = true, failAfterAnswer = true))
        e.matchOnce()
        runCurrent()
        e.replaceSocket()
        runCurrent()
        answer.complete(emptyList()) // the app answers (and then fails) well after the flow was lost
        runCurrent()
        verify(exactly = 0) { e.engine.sendFlowAction(any(), "decline", any()) }
        verify(exactly = 0) { e.engine.sendFlowAction(any(), "consent", any()) }
    }

    @Test
    fun flowLost_anAbandonedFlowAndABrowserAuthorizationInProgressAreNotEndedAsLost() = runTest(dispatcher) {
        val (e, listener) = lostFlowSetup()
        e.matchOnce()
        runCurrent()
        @Suppress("UNCHECKED_CAST")
        (getField(e.s.wallet, "abandonedFlowIds") as MutableSet<String>).add("f1")
        e.replaceSocket()
        runCurrent()
        assertTrue("an abandoned flow's cancellation is not reported again", listener.errors.isEmpty())
        @Suppress("UNCHECKED_CAST")
        (getField(e.s.wallet, "flowConnectionGeneration") as MutableMap<String, Int>)["auth"] = 0
        @Suppress("UNCHECKED_CAST")
        (getField(e.s.wallet, "pendingAuthorizations") as MutableMap<String, Any>)["auth"] = Any()
        e.replaceSocket()
        runCurrent()
        assertTrue("a browser authorization in progress is resumable, not lost", listener.errors.isEmpty())
    }

    @Test
    fun flowLost_aLostPresentationDoesNotEraseTheStateAnIssuanceJustClaimed() = runTest(dispatcher) {
        val (e, listener) = lostFlowSetup()
        e.matchOnce()
        runCurrent()
        // A new issuance claimed the shared guards before reconnecting.
        setField(e.s.wallet, "issuanceInFlight", true)
        e.replaceSocket()
        runCurrent()
        assertEquals(1, listener.errors.size)
        assertEquals("the presentation does not own the issuance guards", true, getField(e.s.wallet, "issuanceInFlight"))
    }

    private fun czkTwoCredentials() = listOf(
        StoredCredential(id = 1L, format = "mso_mdoc", raw = CzkFixtures.mdoc(CzkFixtures.psc, "2000-06-15"), credentialIssuerIdentifier = CzkFixtures.ISSUER,
            metadata = CredentialMetadata(name = "Nym A"), batchId = 1L, instanceId = 0),
        StoredCredential(id = 2L, format = "mso_mdoc", raw = CzkFixtures.mdoc(CzkFixtures.psc, "1990-01-01"), credentialIssuerIdentifier = CzkFixtures.ISSUER,
            metadata = CredentialMetadata(name = "Nym B"), batchId = 2L, instanceId = 0),
    )

    private fun TestScope.engineCzkWith(credentials: List<StoredCredential>?, policy: CredentialConsumptionPolicy? = null): EngineCzk {
        val e = engineCzk(credentials = credentials)
        policy?.let { e.s.wallet.credentialConsumptionPolicy = it }
        return e
    }

    @Test
    fun circuitZkRedirect_eachQueryIsAnsweredWithTheCredentialItsReferenceNames_whateverTheOrder() = runTest(dispatcher) {
        val e = engineCzkWith(czkTwoCredentials())
        val query = Json.parseToJsonElement(
            """{"credentials":[
              {"id":"q1","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"${CzkFixtures.DOCTYPE}"},"_req":[{"fn_id":"pseudonym","return":"n1","params":{"config":"known-offender-matching-psc","ver":1,"prf":"sha-256"}}]},
              {"id":"q2","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"${CzkFixtures.DOCTYPE}"},"_req":[{"fn_id":"pseudonym","return":"n2","params":{"config":"known-offender-matching-psc","ver":1,"prf":"sha-256"}}]}]}""",
        )
        e.matchOnce(query)
        advanceUntilIdle()
        // The references come in the reverse order of the queries: q2 is answered by credential 1, q1 by credential 2.
        e.sign.emit(redirectSign().let { r ->
            r.copy(params = r.params.copy(credentialsToInclude = listOf(
                org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "q2", credentialId = "1"),
                org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "q1", credentialId = "2"),
            )))
        })
        advanceUntilIdle()
        val vp = slot<String>()
        verify(exactly = 1) { e.engine.sendSignResponse("f1", vpToken = capture(vp), messageId = "m1") }
        assertEquals(setOf("q1", "q2"), Json.parseToJsonElement(vp.captured).jsonObject.keys)
        // The prover got credential 2 for q1 and credential 1 for q2: tell them apart by the birth dates they hold.
        fun holds(input: org.siros.sdk.keystore.CircuitZkProveInput, birth: String) = String(input.credentialBytes, Charsets.ISO_8859_1).contains(birth)
        assertEquals(2, e.s.prover.inputs.size)
        // Proved in query order: q1 with credential 2, q2 with credential 1.
        assertTrue(holds(e.s.prover.inputs[0], "1990-01-01") && !holds(e.s.prover.inputs[0], "2000-06-15"))
        assertTrue(holds(e.s.prover.inputs[1], "2000-06-15") && !holds(e.s.prover.inputs[1], "1990-01-01"))
    }

    private fun redirectQueries(n: Int) = Json.parseToJsonElement(
        """{"credentials":[""" + (1..n).joinToString(",") { i ->
            """{"id":"q$i","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"${CzkFixtures.DOCTYPE}"},"_req":[{"fn_id":"pseudonym","return":"n$i","params":{"config":"known-offender-matching-psc","ver":1,"prf":"sha-256"}}]}"""
        } + "]}",
    )

    private fun refs(vararg pairs: Pair<String, String>) = pairs.map { (q, id) -> org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = q, credentialId = id) }

    private fun SignRequestMessage.withRefs(r: List<org.siros.sdk.transport.engine.CredentialRef>) = copy(params = params.copy(credentialsToInclude = r))

    private fun holds(input: org.siros.sdk.keystore.CircuitZkProveInput, birth: String) = String(input.credentialBytes, Charsets.ISO_8859_1).contains(birth)

    @Test
    fun circuitZkRedirect_aCredentialReusedAcrossQueries_keepsEveryQueriesOwnChoice() = runTest(dispatcher) {
        val e = engineCzkWith(czkTwoCredentials())
        e.matchOnce(redirectQueries(3))
        advanceUntilIdle()
        // q1 and q2 are answered by credential 1, q3 by credential 2: three queries, two distinct credentials.
        e.sign.emit(redirectSign().withRefs(refs("q1" to "1", "q2" to "1", "q3" to "2")))
        advanceUntilIdle()
        verify(exactly = 1) { e.engine.sendSignResponse("f1", vpToken = any(), messageId = "m1") }
        assertEquals(3, e.s.prover.inputs.size)
        assertTrue(holds(e.s.prover.inputs[0], "2000-06-15"))
        assertTrue(holds(e.s.prover.inputs[1], "2000-06-15"))
        assertTrue(holds(e.s.prover.inputs[2], "1990-01-01") && !holds(e.s.prover.inputs[2], "2000-06-15"))
    }

    @Test
    fun circuitZkRedirect_aQueryWithoutItsOwnReference_isRefused_evenIfAnotherQueryChoseTheSameCredential() = runTest(dispatcher) {
        val e = engineCzkWith(czkTwoCredentials())
        e.matchOnce(redirectQueries(2))
        advanceUntilIdle()
        e.sign.emit(redirectSign().withRefs(refs("q1" to "1")))
        advanceUntilIdle()
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        assertEquals(0, e.s.prover.calls)
        // Exactly one SIGN_REFUSED answering the sign_request (message_id echoed); no decline action, no vp_token.
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", any()) }
        verify(exactly = 0) { e.engine.cancelFlow(any()) }
    }

    @Test
    fun circuitZkRedirect_theConsentSelectsOneCredentialPerQuery_andItsOwnReferencesAreAnswered() = runTest(dispatcher) {
        for ((name, creds, expected) in listOf(
            Triple("two credentials, both match both queries", czkTwoCredentials(), listOf("q1" to "1", "q2" to "2")),
            Triple("one credential answers both queries", null, listOf("q1" to "1", "q2" to "1")),
        )) {
            val e = engineCzkWith(creds)
            e.matchOnce(redirectQueries(2))
            advanceUntilIdle()
            val consent = slot<JsonObject>()
            verify(exactly = 1) { e.engine.sendFlowAction("f1", "consent", capture(consent)) }
            val entries = consent.captured["selected_credentials"]!!.jsonArray.map { it.jsonObject }
            assertEquals(name, expected, entries.map { it["credential_query_id"]!!.jsonPrimitive.content to it["credential_id"]!!.jsonPrimitive.content })
            assertTrue(name, entries.all { it["disclosed_claims"]!!.jsonArray.isEmpty() })
            // The sign references are the ones the consent emitted, not fabricated ones.
            e.sign.emit(redirectSign().withRefs(refs(*expected.toTypedArray())))
            advanceUntilIdle()
            verify(exactly = 1) { e.engine.sendSignResponse("f1", vpToken = any(), messageId = "m1") }
            assertEquals(name, 2, e.s.prover.calls)
        }
    }

    @Test
    fun circuitZkRedirect_theMatchRequestAnswerHasOneEntryPerQuery() = runTest(dispatcher) {
        val e = engineCzkWith(czkTwoCredentials())
        e.match.emit(MatchRequestMessage(flowId = "f1", dcqlQuery = redirectQueries(2), clientMetadata = redirectMetadata))
        advanceUntilIdle()
        val matches = slot<List<CredentialMatch>>()
        verify(exactly = 1) { e.engine.sendMatchResponse("f1", capture(matches), any()) }
        assertEquals(listOf("q1" to "1", "q2" to "2"), matches.captured.map { it.credentialQueryId to it.credentialId })
    }

    private fun serverTrust(trusted: Boolean, withContext: Boolean = true) = FlowProgressMessage(
        flowId = "f1", step = "trust_evaluated",
        payload = buildJsonObject {
            put("verifier_trust_evaluated", true)
            put("verifier", redirectClientId)
            put("trusted", trusted)
            put("framework", "etsi-tl")
            if (withContext) putJsonObject("context") {
                putJsonArray("verifier_ids") { add(buildJsonObject { put("verifier_id_type", "x509_san_dns"); put("verifier_id", redirectClientId.removePrefix("x509_san_dns:")) }) }
            }
        },
    )

    @Test
    fun circuitZkRedirect_aTrustDecisionTheEngineMadeItself_isIngestedAndAnswered_withoutSeedingPrivateState() = runTest(dispatcher) {
        val e = engineCzk(seedTrust = false)
        e.progress.emit(serverTrust(trusted = true))
        advanceUntilIdle()
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign())
        advanceUntilIdle()
        verify(exactly = 1) { e.engine.sendSignResponse("f1", vpToken = any(), messageId = "m1") }
        assertEquals(1, e.s.prover.calls)
    }

    @Test
    fun circuitZkRedirect_theSameVerifierIdEntryGivesTheSamePseudonym_onTheEnginePathAndTheDcApiPath() = runTest(dispatcher) {
        // One mapping for every trust path (the PDP's bare A-label becomes x509_san_dns:<dns>), whichever path delivered it.
        val e = engineCzk(seedTrust = false)
        e.progress.emit(serverTrust(trusted = true))
        advanceUntilIdle()
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign())
        advanceUntilIdle()
        val vp = slot<String>()
        verify(exactly = 1) { e.engine.sendSignResponse("f1", vpToken = capture(vp), messageId = "m1") }
        val viaEngine = CzkDecoded(Json.parseToJsonElement(vp.captured).jsonObject["q"]!!.jsonArray.single().jsonPrimitive.content).results["n"]
        val viaDcApi = czkDecoded(czkRun(czkSetup(trust = czkIds("x509_san_dns" to "rp.example")), czkRequest()).responseJson).results["n"]
        assertEquals(org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:rp.example")), viaDcApi)
        assertEquals(viaDcApi, viaEngine)
    }

    @Test
    fun circuitZkRedirect_aReconnectWhileConsentIsPending_provesAndSendsNothing() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Boolean>()
        val e = engineCzk(consent = { gate.await() })
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign())
        runCurrent()
        assertEquals(1, e.s.consents.size)
        engineGeneration.incrementAndGet() // the socket was replaced
        gate.complete(true)
        runCurrent()
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        assertEquals(0, e.s.prover.calls)
        assertTrue(e.s.history.isEmpty())
    }

    @Test
    fun circuitZkRedirect_aConsentApprovedWhileTheEngineIsReconnecting_provesNothing_evenWithoutANewGeneration() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Boolean>()
        val e = engineCzk(consent = { gate.await() })
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign())
        runCurrent()
        assertEquals(1, e.s.consents.size)
        e.state.value = WalletEngineSession.State.RECONNECTING // the backoff: the generation has not changed yet
        gate.complete(true)
        runCurrent()
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        assertEquals(0, e.s.prover.calls)
        assertTrue(e.s.history.isEmpty())
    }

    @Test
    fun circuitZkRedirect_aConnectionLostWhileTheHistoryIsBeingRecorded_sendsNothing() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        // Recording the presentation reads the store (the renew check) AFTER the proof: the socket drops exactly there.
        val inner = getField(e.s.wallet, "credentialStore") as CredentialStore
        setField(e.s.wallet, "credentialStore", object : CredentialStore by inner {
            override suspend fun getAll(): List<StoredCredential> {
                if (e.s.prover.calls > 0) e.state.value = WalletEngineSession.State.RECONNECTING
                return inner.getAll()
            }
        })
        e.sign.emit(redirectSign())
        advanceUntilIdle()
        assertEquals(1, e.s.prover.calls)
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
    }

    @Test
    fun circuitZkRedirect_aConnectionThatEndsDuringConsent_doesNotHoldUpAnUnrelatedDcApiRequest() = runTest(dispatcher) {
        var asked = 0
        val gate = kotlinx.coroutines.CompletableDeferred<Boolean>() // the old dialog is never answered
        val e = engineCzk(consent = { if (asked++ == 0) gate.await() else true })
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign())
        runCurrent()
        assertEquals(1, e.s.consents.size)
        e.state.value = WalletEngineSession.State.RECONNECTING
        runCurrent()
        val dcApi = async(dispatcher) { e.s.wallet.handleDCAPIRequest(czkRequest(), CzkFixtures.ORIGIN, listOf(1L)) }
        runCurrent()
        assertTrue("the DC API request must not wait for the stale dialog", dcApi.isCompleted)
        assertEquals(1, e.s.prover.calls)
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
    }

    @Test
    fun circuitZkRedirect_anOverlappingDcApiRequestNeverPresentsTheSameSingleCopyCredentialTwice_underConsumeAll() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Boolean>()
        val e = engineCzk(consent = { gate.await() })
        e.s.wallet.credentialConsumptionPolicy = CredentialConsumptionPolicy.CONSUME_ALL
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign())
        runCurrent() // the redirect holds the credential and waits on the user
        val dcApi = async(dispatcher) {
            runCatching { e.s.wallet.handleDCAPIRequest(czkRequest(), CzkFixtures.ORIGIN, listOf(1L)) }
        }
        runCurrent()
        gate.complete(true)
        runCurrent()
        verify(exactly = 1) { e.engine.sendSignResponse("f1", vpToken = any(), messageId = "m1") }
        // The DC API request found the single copy spent.
        assertTrue(dcApi.await().exceptionOrNull() is org.siros.sdk.wallet.dcapi.DCAPIRequestRefused)
        assertEquals(1, e.s.prover.calls)
    }

    @Test
    fun circuitZkRedirect_twoOverlappingRequestsNeverPresentTheSameSingleCopyCredentialTwice_underConsumeAll() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Boolean>()
        val e = engineCzk(consent = { gate.await() }, flows = listOf("f1", "f2"))
        e.s.wallet.credentialConsumptionPolicy = CredentialConsumptionPolicy.CONSUME_ALL
        e.matchOnce(flow = "f1")
        e.matchOnce(flow = "f2")
        advanceUntilIdle()
        e.sign.emit(redirectSign(flow = "f1", messageId = "m1"))
        e.sign.emit(redirectSign(flow = "f2", messageId = "m2"))
        runCurrent()
        gate.complete(true)
        runCurrent()
        // Exactly one of them presented the credential; the other found it spent.
        assertEquals(1, e.s.prover.calls)
        verify(exactly = 1) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        verify(exactly = 1) { e.engine.sendSignRefusal(any(), any(), any()) }
        assertEquals(1, e.s.history.size)
    }

    @Test
    fun circuitZkRedirect_anEngineDecisionThatDistrustsTheVerifier_orCarriesNoVerifierIds_isNeverProved() = runTest(dispatcher) {
        for ((name, msg) in listOf("untrusted" to serverTrust(trusted = false), "no verifier ids" to serverTrust(trusted = true, withContext = false))) {
            val e = engineCzk(seedTrust = false)
            e.progress.emit(msg)
            advanceUntilIdle()
            e.matchOnce()
            advanceUntilIdle()
            e.sign.emit(redirectSign())
            advanceUntilIdle()
            verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
            verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", any()) }
            assertEquals(name, 0, e.s.prover.calls)
        }
    }

    @Test
    fun circuitZkRedirect_aTrustedIdentityOfAnUnsignedScheme_isRefused() = runTest(dispatcher) {
        val client = "redirect_uri:https://rp.example/"
        val e = engineCzk(clientId = client)
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign(audience = client))
        advanceUntilIdle()
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", any()) }
        assertEquals(0, e.s.prover.calls)
        assertTrue(e.s.consents.isEmpty())
    }

    @Test
    fun circuitZkRedirect_aCredentialDeletedBetweenMatchAndSign_isNeverProved() = runTest(dispatcher) {
        val e = engineCzkWith(czkTwoCredentials())
        e.matchOnce()
        advanceUntilIdle()
        val store = getField(e.s.wallet, "credentialStore") as CredentialStore
        store.delete(1L)
        store.delete(2L)
        e.sign.emit(redirectSign())
        advanceUntilIdle()
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", any()) }
        assertEquals(0, e.s.prover.calls)
    }

    @Test
    fun circuitZkRedirect_aFlowThatEndsWhileConsentIsPending_provesNothingAndSendsNothing() = runTest(dispatcher) {
        for (ending in listOf("error", "complete")) {
            val gate = kotlinx.coroutines.CompletableDeferred<Boolean>()
            val e = engineCzk(consent = { gate.await() })
            e.matchOnce()
            advanceUntilIdle()
            e.sign.emit(redirectSign())
            runCurrent() // not advanceUntilIdle: virtual time would run out the consent time limit
            assertEquals(1, e.s.consents.size)   // the user is being asked
            if (ending == "error") e.errors.emit(FlowErrorMessage(flowId = "f1", error = FlowError(code = "FLOW_TIMEOUT", message = "timeout")))
            else e.complete.emit(FlowCompleteMessage(flowId = "f1"))
            runCurrent() // not advanceUntilIdle: virtual time would run out the consent time limit
            gate.complete(true)   // a late approval
            runCurrent() // not advanceUntilIdle: virtual time would run out the consent time limit
            verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
            assertEquals(ending, 0, e.s.prover.calls)
            assertTrue(ending, e.s.history.isEmpty())
        }
    }

    @Test
    fun circuitZkRedirect_cancellingTheFlowWhileConsentIsPending_refusesTheSignRequestOnceAndProvesNothing() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Boolean>()
        val e = engineCzk(consent = { gate.await() })
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign())
        runCurrent() // not advanceUntilIdle: virtual time would run out the consent time limit
        @Suppress("UNCHECKED_CAST")
        (getField(e.s.wallet, "_state") as MutableStateFlow<WalletState>).value = WalletState.FlowActive(
            userId = "u", displayName = null, flowId = "f1", flowType = "presentation", status = "sign", credentials = emptyList(),
        )
        e.s.wallet.cancelCurrentFlow()
        runCurrent() // not advanceUntilIdle: virtual time would run out the consent time limit
        gate.complete(true)
        runCurrent() // not advanceUntilIdle: virtual time would run out the consent time limit
        // The pending sign request is refused (not left to the engine's timeout), and the late approval does nothing.
        verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", any()) }
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        assertEquals(0, e.s.prover.calls)
    }

    @Test
    fun circuitZkRedirect_aSessionThatEndsWhileConsentIsPending_orIsReplaced_provesAndSendsNothing() = runTest(dispatcher) {
        for (how in listOf("teardown", "replaced")) {
            val gate = kotlinx.coroutines.CompletableDeferred<Boolean>()
            val e = engineCzk(consent = { gate.await() })
            e.matchOnce()
            advanceUntilIdle()
            e.sign.emit(redirectSign())
            runCurrent() // not advanceUntilIdle: virtual time would run out the consent time limit
            assertEquals(1, e.s.consents.size)
            val m = e.s.wallet::class.java.declaredMethods.first { it.name == if (how == "teardown") "stopAllZkSigning" else "bumpSessionGeneration" }
            m.isAccessible = true
            m.invoke(e.s.wallet)
            runCurrent()
            gate.complete(true)
            runCurrent()
            verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
            verify(exactly = 0) { e.engine.sendSignRefusal(any(), any(), any()) }
            assertEquals(how, 0, e.s.prover.calls)
            assertTrue(how, e.s.history.isEmpty())
        }
    }

    @Test
    fun circuitZkRedirect_aForcedReconnectWhileConsentIsPending_releasesThePresentationLockAndSendsNothing() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Boolean>()
        val e = engineCzk(consent = { gate.await() })
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign())
        runCurrent() // not advanceUntilIdle: virtual time would run out the consent time limit
        assertEquals(1, e.s.consents.size)
        val mutex = getField(e.s.wallet, "zkSigningMutex") as kotlinx.coroutines.sync.Mutex
        assertTrue("the pending signing holds the presentation lock", mutex.isLocked)
        // forceReconnect(): the old socket is dropped and the state goes to CONNECTING (not RECONNECTING).
        e.state.value = WalletEngineSession.State.CONNECTING
        runCurrent()
        assertFalse("an unrelated (DC API) presentation is not held up by the stale dialog", mutex.isLocked)
        gate.complete(true)
        runCurrent()
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        assertEquals(0, e.s.prover.calls)
    }

    @Test
    fun circuitZkRedirect_aProximityPresentationCannotUseTheSingleCopyAPendingRedirectWillConsume() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Boolean>()
        val e = engineCzk(consent = { gate.await() })
        e.s.wallet.credentialConsumptionPolicy = CredentialConsumptionPolicy.CONSUME_ALL
        var proximitySigned = 0
        coEvery { (getField(e.s.wallet, "keystore") as KeystoreManager).signMdocPresentationForProximity(any(), any(), any(), any()) } coAnswers {
            proximitySigned++
            ByteArray(1)
        }
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign())
        runCurrent() // the redirect now waits on its consent dialog, holding the presentation lock
        assertEquals(1, e.s.consents.size)
        val proximity = backgroundScope.async { runCatching { e.s.wallet.signMdocPresentationForProximity(1L, null, ByteArray(1)) } }
        runCurrent()
        assertTrue("the proximity presentation waits for the redirect's lock", proximity.isActive)
        assertEquals(0, proximitySigned)
        gate.complete(true)
        advanceUntilIdle()
        // The redirect consumed the only copy; the proximity presentation then finds nothing eligible and signs nothing.
        val result = proximity.await()
        assertTrue("proximity refused: $result", result.isFailure && result.exceptionOrNull() is WalletException)
        assertEquals(0, proximitySigned)
        assertEquals(1, e.s.history.size)
    }

    private fun queryForDoctype(doctype: String) = Json.parseToJsonElement(
        """{"credentials":[{"id":"q","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"$doctype"},"_req":[{"fn_id":"pseudonym","return":"n","params":{"config":"known-offender-matching-psc","ver":1,"prf":"sha-256"}}]}]}""",
    )

    @Test
    fun circuitZkRedirect_eachWayARequestCannotBeAnswered_hasItsOwnCodeAndUserMeaningfulReason() = runTest(dispatcher) {
        timber.log.Timber.plant(czkTree)
        try {
            val cases = listOf<Triple<String, String, suspend () -> Pair<EngineCzk, kotlinx.serialization.json.JsonElement>>>(
                Triple("disabled", "not enabled") { engineCzk(flagOn = false) to redirectQuery },
                Triple("no-circuit", "no proof circuit") { engineCzk() to queryForDoctype("org.example.other") },
                Triple("no-credential", "holds no credential") { engineCzk(credentials = emptyList()) to redirectQuery },
                Triple("no-verifier-id", "did not identify itself") { engineCzk(seedTrust = false).also { it.progress.emit(serverTrust(trusted = true, withContext = false)) } to redirectQuery },
            )
            for ((code, text, make) in cases) {
                czkLogs.clear()
                val (e, query) = make()
                advanceUntilIdle()
                e.matchOnce(query)
                advanceUntilIdle()
                val reason = slot<String>()
                verify(exactly = 1) { e.engine.sendCredentialsMatched("f1", emptyList(), capture(reason)) }
                assertTrue("$code: ${reason.captured}", reason.captured.contains(text))
                // The code is logged (and only the code: nothing of the request).
                assertTrue(code, czkLogs.any { it.contains("code=$code") })
                verify(exactly = 0) { e.engine.sendFlowAction("f1", "consent", any()) }
            }
        } finally {
            timber.log.Timber.uproot(czkTree)
        }
    }

    @Test
    fun circuitZkRedirect_aReferenceToAnUnknownQuery_isRefused() = runTest(dispatcher) {
        val e = engineCzk()
        e.matchOnce()
        advanceUntilIdle()
        e.sign.emit(redirectSign().let { r ->
            r.copy(params = r.params.copy(credentialsToInclude = listOf(org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "other", credentialId = "1"))))
        })
        advanceUntilIdle()
        verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        assertEquals(0, e.s.prover.calls)
    }

    @Test
    fun circuitZkRedirect_aFreshSingleCopyCredential_isNotCountedConsumedBeforeItIsProved_underConsumeAll() = runTest(dispatcher) {
        val e = engineCzkWith(null, CredentialConsumptionPolicy.CONSUME_ALL)
        e.matchOnce()
        advanceUntilIdle()
        verify(exactly = 1) { e.engine.sendFlowAction("f1", "consent", any()) }
        e.sign.emit(redirectSign())
        advanceUntilIdle()
        verify(exactly = 1) { e.engine.sendSignResponse("f1", vpToken = any(), messageId = "m1") }
        assertEquals(1, e.s.prover.calls)
        // Recorded once, from what was really used.
        assertEquals(listOf(listOf(1L)), e.s.history.map { it.credentialIds })
    }

    @Test
    fun circuitZkRedirect_theVerifierMetadataDoesNotOutliveTheFlow() = runTest(dispatcher) {
        fun cached(e: EngineCzk) = (getField(e.s.wallet, "circuitZkClientMetadataByFlow") as Map<*, *>).size
        // A request that is refused at match time caches nothing.
        val refused = engineCzk(flagOn = false)
        refused.matchOnce()
        advanceUntilIdle()
        assertEquals(0, cached(refused))
        // An accepted one holds it for the sign step only, whether the sign step answers or refuses.
        val answered = engineCzk()
        answered.matchOnce()
        advanceUntilIdle()
        assertEquals(1, cached(answered))
        answered.sign.emit(redirectSign())
        advanceUntilIdle()
        assertEquals(0, cached(answered))
        val failed = engineCzk()
        failed.matchOnce()
        advanceUntilIdle()
        failed.sign.emit(redirectSign(thumbprint = null))
        advanceUntilIdle()
        assertEquals(0, cached(failed))
        // And one that never reaches the sign step is dropped when the flow ends.
        val completed = engineCzk()
        completed.matchOnce()
        advanceUntilIdle()
        assertEquals(1, cached(completed))
        completed.complete.emit(FlowCompleteMessage(flowId = "f1"))
        advanceUntilIdle()
        assertEquals(0, cached(completed))
    }

    @Test
    fun circuitZkRedirect_theMatchRequestMessageIsAnsweredToo() = runTest(dispatcher) {
        val e = engineCzk()
        e.match.emit(MatchRequestMessage(flowId = "f1", dcqlQuery = redirectQuery, clientMetadata = redirectMetadata))
        advanceUntilIdle()
        val matches = slot<List<CredentialMatch>>()
        verify(exactly = 1) { e.engine.sendMatchResponse("f1", capture(matches), any()) }
        assertEquals(listOf("1"), matches.captured.map { it.credentialId })
        assertEquals(listOf<List<String>?>(null), matches.captured.map { it.availableClaims })
        assertTrue(e.s.history.isEmpty())
    }

    @Test
    fun circuitZkRedirect_aMissingOrMalformedThumbprintAndOtherHandoverInputs_areRefused_nothingIsAskedOrProved() = runTest(dispatcher) {
        for ((name, req) in listOf(
            "no thumbprint" to redirectSign(thumbprint = null),
            "empty thumbprint" to redirectSign(thumbprint = ""),
            "short thumbprint" to redirectSign(thumbprint = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(31))),
            "no response_uri" to redirectSign(responseUri = null),
        )) {
            val e = engineCzk()
            e.matchOnce()
            advanceUntilIdle()
            e.sign.emit(req)
            advanceUntilIdle()
            verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
            // Exactly one SIGN_REFUSED answering the sign_request (message_id echoed); no decline action, no vp_token.
            verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", any()) }
            verify(exactly = 0) { e.engine.cancelFlow(any()) }
            assertEquals(name, 0, e.s.prover.calls)
            assertTrue(name, e.s.consents.isEmpty())
        }
    }

    @Test
    fun circuitZkRedirect_anUntrustedVerifier_aWrongAudience_aDeclinedConsent_andARequestThatOfferedNoSystem_areNeverProved() = runTest(dispatcher) {
        for ((name, make) in listOf<Pair<String, () -> Pair<EngineCzk, SignRequestMessage>>>(
            "untrusted" to { engineCzk(trusted = false) to redirectSign() },
            "audience" to { engineCzk() to redirectSign(audience = "x509_san_dns:evil.example") },
            "declined" to { engineCzk(consent = { false }) to redirectSign() },
            "no system offered" to { engineCzk(offersCircuit = false) to redirectSign() },
            "a pick that is not a candidate" to { engineCzk() to redirectSign(creds = listOf("999")) },
        )) {
            val (e, req) = make()
            e.matchOnce()
            advanceUntilIdle()
            e.sign.emit(req)
            advanceUntilIdle()
            verify(exactly = 0) { e.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
            // Exactly one SIGN_REFUSED answering the sign_request (message_id echoed); no decline action, no vp_token.
            verify(exactly = 1) { e.engine.sendSignRefusal("f1", "m1", any()) }
            verify(exactly = 0) { e.engine.cancelFlow(any()) }
            if (name != "declined") assertEquals(name, 0, e.s.prover.calls)
        }
    }

    @Test
    fun circuitZkRedirect_withTheFeatureOff_orAMixedRequest_orATransactionData_nothingIsOffered() = runTest(dispatcher) {
        val off = engineCzk(flagOn = false)
        off.matchOnce()
        advanceUntilIdle()
        verify(exactly = 1) { off.engine.sendCredentialsMatched("f1", emptyList(), any()) }

        val mixed = engineCzk()
        mixed.matchOnce(Json.parseToJsonElement("""{"credentials":[{"id":"q","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"${CzkFixtures.DOCTYPE}"}},{"id":"p","format":"mso_mdoc","meta":{"doctype_value":"x"},"claims":[{"path":["x","y"]}]}]}"""))
        advanceUntilIdle()
        verify(exactly = 1) { mixed.engine.sendCredentialsMatched("f1", emptyList(), any()) }

        val tx = engineCzk()
        tx.matchOnce()
        advanceUntilIdle()
        tx.sign.emit(redirectSign().let { it.copy(params = it.params.copy(transactionData = listOf(org.siros.sdk.transport.wmp.openid4x.TransactionData(type = "t", credentialIds = listOf("c"), payload = JsonObject(emptyMap()))))) })
        advanceUntilIdle()
        verify(exactly = 0) { tx.engine.sendSignResponse(any(), vpToken = any(), messageId = any()) }
        assertEquals(0, tx.s.prover.calls)
    }

    @Test
    fun circuitZkDcApi_aRequestThatOfferedNoCircuit_isRefusedAndNothingIsProved() = runTest(dispatcher) {
        val s = czkSetup(offersCircuit = false)
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.PROOF_FAILED)
        assertEquals(0, s.prover.calls)
    }

    @Test
    fun circuitZkDcApi_withNoConfiguredProver_usesTheRealCatalogProverAndRefusesWithoutANativeOne() = runTest(dispatcher) {
        timber.log.Timber.plant(czkTree)
        try {
            val s = czkSetup(defaultProver = true)
            czkRefused(s, czkRequest())
            // The refusal came from the catalog prover's registry (every earlier step passed, as in the success case):
            // no adapter claims the test circuit's system, so it is not offered. The fake is never substituted.
            assertTrue(czkLogs.any { it.contains("step=CIRCUIT") })
            assertEquals(0, s.prover.calls)
        } finally {
            timber.log.Timber.uproot(czkTree)
        }
    }

    @Test
    fun circuitZkDcApi_transactionData_isRefusedBeforeTrustAndProof() = runTest(dispatcher) {
        // Fail closed: the circuit path has no transaction pipeline, so a transaction-bearing request
        // (with or without a wallet consent handler) is refused, never proved.
        for (txData in listOf("""["e30"]""", "[]")) {
            val s = czkSetup()
            czkRefused(s, czkRequest(transactionData = txData), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.UNSUPPORTED_REQUEST)
            assertEquals(0, s.prover.calls)
            coVerify(exactly = 0) { s.apiClient.evaluateTrust(any()) }
        }
    }

    @Test
    fun circuitZkDcApi_aQueryWithoutAnId_isNeverDroppedFromAProvedRequest() = runTest(dispatcher) {
        // The matcher drops a credential query with no string id; the request is still not answered without it.
        val s = czkSetup()
        czkRefused(
            s,
            czkRequest(extraQueries = """,{"format":"mso_mdoc","meta":{"source_format":"mso_mdoc","doctype_value":"x"}}"""),
            reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.UNSUPPORTED_REQUEST,
        )
        assertEquals(0, s.prover.calls)
    }

    @Test
    fun circuitZkDcApi_consumeNonZkp_aCopyUsedForACircuitProofIsNotConsumed() = runTest(dispatcher) {
        val s = czkSetup()
        s.wallet.credentialConsumptionPolicy = CredentialConsumptionPolicy.CONSUME_NON_ZKP
        assertEquals(listOf(1L), czkRun(s, czkRequest()).credentialIds)
        // The first proof is in the history; the same single copy still answers a second request.
        assertEquals(listOf(1L), czkRun(s, czkRequest(nonce = "czk-nonce-2")).credentialIds)
        assertEquals(2, s.prover.calls)
    }

    @Test
    fun circuitZkDcApi_requestHardeningFailures_areRefusedBeforeTrust() = runTest(dispatcher) {
        for (raw in listOf(
            czkRequest(signed = false),
            czkRequest(origins = """["https://evil.example"]"""),
            czkRequest(origins = null),
            czkRequest(protocol = "openid4vp-v1-multisigned"),
        )) {
            val s = czkSetup()
            czkRefused(s, raw, reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.REQUEST_NOT_VERIFIED)
            coVerify(exactly = 0) { s.apiClient.evaluateTrust(any()) }
        }
    }

    @Test
    fun circuitZkDcApi_circuitWithCapabilities_isSelectedOnlyWhenTheMatcherServesIt() = runTest(dispatcher) {
        val caps = """{"schema":1,"presentation":"zkp_req","credential":{"format":"mso_mdoc","type":"${CzkFixtures.DOCTYPE}"},"functions":[]}"""
        // No matcher answer: a circuit that declares capabilities is not unrestricted, so nothing is selected.
        val noMatcher = czkSetup(capabilities = caps, serving = null)
        czkRefused(noMatcher, czkRequest())
        assertEquals(0, noMatcher.prover.calls)
        val declined = czkSetup(capabilities = caps, serving = org.siros.sdk.credentials.CircuitZkServing { _, _, _ -> false })
        czkRefused(declined, czkRequest())
        assertEquals(0, declined.prover.calls)
        // The matcher serves it: presented, and the matcher was asked about this circuit.
        val asked = mutableListOf<String>()
        val served = czkSetup(capabilities = caps, serving = org.siros.sdk.credentials.CircuitZkServing { c, _, _ -> asked += c.circuitId; true })
        czkRun(served, czkRequest())
        assertEquals(1, served.prover.calls)
        assertTrue(asked.isNotEmpty() && asked.all { it == "c1" })
    }

    @Test
    fun circuitZkDcApi_wrongCallingOrigin_isRefused() = runTest(dispatcher) {
        val s = czkSetup()
        czkRefused(s, czkRequest(), origin = "https://evil.example")
        coVerify(exactly = 0) { s.apiClient.evaluateTrust(any()) }
    }

    private fun czkSscFunction(config: String = "known-offender-matching-ssc", extra: String = "") =
        listOf(org.siros.sdk.credentials.CircuitZkFunction(
            "pseudonym", "n", Json.parseToJsonElement("""{"config":"$config","ver":1,"prf":"sha-256"$extra}""").jsonObject,
        ))

    private fun czkSscSetup(
        source: CredentialSecretSeedSource?,
        config: String = "known-offender-matching-ssc",
        extra: String = "",
        ssc: ByteArray = NymTestCredentials.goodSsc,
        consent: suspend (org.siros.sdk.credentials.PresentationConsentRequest) -> Boolean = { true },
        noConsentHandler: Boolean = false,
        proverSigns: Boolean = false,
    ) =
        czkSetup(
            consent = consent, noConsentHandler = noConsentHandler, proverSigns = proverSigns,
            functions = czkSscFunction(config, extra),
            credentials = listOf(StoredCredential(
                id = 1L, format = "mso_mdoc", raw = CzkFixtures.mdoc(ssc = ssc), credentialIssuerIdentifier = CzkFixtures.ISSUER,
                metadata = CredentialMetadata(name = "Nym"), batchId = 1L, instanceId = 0,
            )),
            secretSeedSource = source,
        )

    @Test
    fun circuitZkDcApi_sscConfig_isProvenWithTheDeliveredSeed_andTheSeedIsZeroedAndNeverPresented() = runTest(dispatcher) {
        val handedOut = mutableListOf<ByteArray>()
        val source = CredentialSecretSeedSource { id ->
            if (id == 1L) NymTestCredentials.seed.copyOf().also { handedOut += it } else null
        }
        val s = czkSscSetup(source)
        val result = czkRun(s, czkRequest())
        assertEquals(
            org.siros.sdk.credentials.ResultValue.Pseudonym(
                org.siros.sdk.credentials.NymPseudonym.derive("known-offender-matching-ssc", NymTestCredentials.seed, verifierId = "x509_san_dns:rp.example"),
            ),
            czkPseudonymOf(result),
        )
        assertEquals(1, handedOut.size)
        assertTrue("the wallet must zero the seed it fetched", handedOut.single().all { it == 0.toByte() })
        assertNoSecretIn(result.responseJson)
        assertNoSecretIn(s.history.toString())
    }

    @Test
    fun circuitZkDcApi_accountRecoverySsc_isNotModelledByTheConsent_soItIsRefusedBeforeTheSeedIsFetched() = runTest(dispatcher) {
        // Only per-verifier configs have consent wording; the others are refused for now, before anything is asked or fetched.
        val s = czkSscSetup({ NymTestCredentials.seed.copyOf() }, "account-recovery-ssc", ""","verifier_context":"ctx-1"""")
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.UNSUPPORTED_REQUEST)
        assertTrue(s.events.isEmpty())
    }

    @Test
    fun circuitZkDcApi_sscConfig_isRefusedWithoutAFittingSeed() = runTest(dispatcher) {
        // No seed held, a seed of another credential, and an ssc the seed does not open.
        czkRefused(czkSscSetup(CredentialSecretSeedSource.NONE), czkRequest())
        czkRefused(czkSscSetup({ ByteArray(16) { 3 } }), czkRequest())
        czkRefused(czkSscSetup({ NymTestCredentials.seed.copyOf() }, ssc = NymTestCredentials.wrongSsc), czkRequest())
        czkRefused(czkSscSetup({ NymTestCredentials.seed.copyOf(15) }), czkRequest())
    }

    @Test
    fun circuitZkDcApi_pdpAnswerOnly_resolves_andTheRequestsClientIdIsNotAnInput() = runTest(dispatcher) {
        // The only id comes from the PDP list; the client id (an x509_hash one here) is not parsed for it.
        val s = czkSetup(trust = czkIds("x509_san_dns" to "pdp.example"))
        assertEquals(
            org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:pdp.example")),
            czkPseudonymOf(czkRun(s, czkRequest(clientId = "x509_hash:abcdef"))),
        )
    }

    @Test
    fun circuitZkDcApi_theBareDnsFromThePdpIsPrefixed_andNotOtherwiseNormalisedByTheWallet() = runTest(dispatcher) {
        // The PDP returns the bare A-label; the wallet adds the rulebook prefix and nothing else (lower case, no trailing dot: the PDP's job).
        val mixed = "Rp.Example.COM"
        val s = czkSetup(trust = czkIds("x509_san_dns" to mixed))
        val got = czkPseudonymOf(czkRun(s, czkRequest()))
        assertEquals(org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:$mixed")), got)
        assertTrue(got != org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:" + mixed.lowercase())))
    }

    @Test
    fun circuitZkDcApi_aPseudonymFunctionWithoutVerifierIdType_stillNeedsAndGetsAVerifierId() = runTest(dispatcher) {
        // The request no longer carries verifier_id_type: the config alone says a verifier id is needed.
        val bare = listOf(org.siros.sdk.credentials.CircuitZkFunction(
            "pseudonym", "n", Json.parseToJsonElement("""{"config":"known-offender-matching-psc","ver":1,"prf":"sha-256"}""").jsonObject,
        ))
        val s = czkSetup(functions = bare, trust = czkIds("x509_san_dns" to "pdp.example"))
        assertEquals(
            org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:pdp.example")),
            czkPseudonymOf(czkRun(s, czkRequest())),
        )
        czkRefused(
            czkSetup(functions = bare, trust = { buildJsonObject { put("decision", true) } }),
            czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.VERIFIER_ID_UNAVAILABLE,
        )
    }

    @Test
    fun circuitZkDcApi_noPdpEntryForAnyListedType_isRefused_nothingIsDerivedLocally() = runTest(dispatcher) {
        // The request carries a client id and an x5c chain whose SAN matches it, but nothing is derived from them.
        val none = czkSetup(trust = { buildJsonObject { put("decision", true) } })
        czkRefused(none, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.VERIFIER_ID_UNAVAILABLE)
        assertEquals(0, none.prover.calls)
        // The PDP lists only types outside the wallet's list.
        val other = czkSetup(trust = czkIds("dns" to "rp.example", "uri" to "https://rp.example"))
        czkRefused(other, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.VERIFIER_ID_UNAVAILABLE)
        assertEquals(0, other.prover.calls)
    }

    /** What the wallet answered for query `q`: the one presentation OBJECT of the `circuit_zk` response shape. */
    /** One presentation of the answer: the base64url CBOR `ZkpPresentation` string of the query `q`, decoded. */
    private class CzkDecoded(val encoded: String) {
        val cbor: com.upokecenter.cbor.CBORObject = com.upokecenter.cbor.CBORObject.DecodeFromBytes(java.util.Base64.getUrlDecoder().decode(encoded))
        val members: Set<String> = cbor.keys.map { it.AsString() }.toSet()
        val results: Map<String, org.siros.sdk.credentials.ResultValue> = cbor["results"].keys.associate { k ->
            val v = cbor["results"][k]
            k.AsString() to if (v.type == com.upokecenter.cbor.CBORType.ByteString) {
                org.siros.sdk.credentials.ResultValue.Pseudonym(v.GetByteString())
            } else {
                assertTrue(v.isTrue)
                org.siros.sdk.credentials.ResultValue.Predicate
            }
        }
    }

    private fun czkDecoded(responseJson: String): CzkDecoded {
        val entry = Json.parseToJsonElement(responseJson).jsonObject["data"]!!.jsonObject["vp_token"]!!.jsonObject["q"]!!.jsonArray
        return CzkDecoded(entry.single().jsonPrimitive.content)
    }

    private fun czkPseudonymOf(result: SirosWallet.DCAPIPresentationResult): org.siros.sdk.credentials.ResultValue? {
        return czkDecoded(result.responseJson).results["n"]
    }

    private fun czkFnOfType(type: String) = org.siros.sdk.credentials.CircuitZkFunction(
        "pseudonym", "n",
        Json.parseToJsonElement("""{"config":"known-offender-matching-psc","ver":1,"prf":"sha-256"}""").jsonObject,
    )

    private fun czkIds(vararg entries: Pair<String, String>): suspend () -> JsonObject = {
        buildJsonObject {
            put("decision", true)
            putJsonObject("context") {
                putJsonArray("verifier_ids") { entries.forEach { (t, v) -> add(buildJsonObject { put("verifier_id_type", t); put("verifier_id", v) }) } }
            }
        }
    }

    @Test
    fun circuitZkDcApi_theTypeTheRequestNames_isIgnoredForSelection_andNotRefusedOnMismatch() = runTest(dispatcher) {
        // The request names x509_hash, which no source of the wallet produces; the wallet's own order governs.
        val s = czkSetup(functions = listOf(czkFnOfType("x509_hash")), trust = czkIds("semantic" to "semantic_id:A"))
        assertEquals(
            org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("semantic_id:A")),
            czkPseudonymOf(czkRun(s, czkRequest())),
        )
        // The request naming "semantic" does not make the wallet use semantic when its list says otherwise.
        val other = czkSetup(
            functions = listOf(czkFnOfType("semantic")), types = listOf("x509_san_dns"),
            trust = czkIds("semantic" to "semantic_id:A", "x509_san_dns" to "b.example"),
        )
        assertEquals(
            org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:b.example")),
            czkPseudonymOf(czkRun(other, czkRequest())),
        )
    }

    @Test
    fun theDefaultValidator_acceptsAPseudonymFunctionNamingAnyVerifierIdType() {
        val circuits = org.siros.sdk.credentials.CircuitZkCircuitSource {
            listOf(org.siros.sdk.credentials.CircuitZkCircuit("sys", "c1", setOf(CzkFixtures.DOCTYPE)))
        }
        for (type in listOf("x509_hash", "semantic", "x509_san_dns", "anything-else")) {
            val plan = org.siros.sdk.credentials.CircuitZkPlan(listOf(czkFnOfType(type)), raw = Json.parseToJsonElement("""{"meta":{"source_format":"mso_mdoc","doctype_value":"d"}}""").jsonObject)
            assertEquals(type, org.siros.sdk.credentials.CircuitZkVerdict.Ok, defaultCircuitZkValidator(circuits).validate(plan))
        }
    }

    @Test
    fun circuitZkDcApi_theWalletsOrderIsRespected_firstTypeWinsWhenBothArePresent_theSecondWhenTheFirstIsAbsent() = runTest(dispatcher) {
        val both = czkSetup(trust = czkIds("x509_san_dns" to "second.example", "semantic" to "semantic_id:first"))
        assertEquals(org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("semantic_id:first")), czkPseudonymOf(czkRun(both, czkRequest())))
        val onlySecond = czkSetup(trust = czkIds("x509_san_dns" to "second.example"))
        assertEquals(org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:second.example")), czkPseudonymOf(czkRun(onlySecond, czkRequest())))
        // Reordering the wallet's list flips the winner for the same PDP answer.
        val reordered = czkSetup(
            types = listOf("x509_san_dns", "semantic"),
            trust = czkIds("x509_san_dns" to "second.example", "semantic" to "semantic_id:first"),
        )
        assertEquals(org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:second.example")), czkPseudonymOf(czkRun(reordered, czkRequest())))
    }

    @Test
    fun circuitZkDcApi_aTypeWithConflictingDistinctValuesIsDeclined_andTheNextTypeIsTried() = runTest(dispatcher) {
        val s = czkSetup(
            trust = czkIds("semantic" to "semantic_id:1", "semantic" to "semantic_id:2", "x509_san_dns" to "ok.example"),
        )
        assertEquals(org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:ok.example")), czkPseudonymOf(czkRun(s, czkRequest())))
        // Conflict on the only available type: nothing resolves, refused.
        czkRefused(
            czkSetup(trust = czkIds("semantic" to "semantic_id:1", "semantic" to "semantic_id:2")),
            czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.VERIFIER_ID_UNAVAILABLE,
        )
    }

    @Test
    fun circuitZkDcApi_onlyTheRulebookVerifierIdFormsAreTakenFromThePdp() = runTest(dispatcher) {
        // A semantic value without its prefix, and the types that are no v0.4 verifier id form, are never used.
        for ((name, ids) in listOf(
            "semantic without prefix" to arrayOf("semantic" to "A"),
            "x509_san_uri" to arrayOf("x509_san_uri" to "https://rp.example/x"),
            "decentralized_identifier" to arrayOf("decentralized_identifier" to "did:web:rp.example"),
            "openid_federation" to arrayOf("openid_federation" to "https://rp.example"),
        )) {
            czkRefused(
                czkSetup(types = listOf("semantic", "x509_san_dns", "x509_san_uri", "decentralized_identifier", "openid_federation"), trust = czkIds(*ids)),
                czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.VERIFIER_ID_UNAVAILABLE,
            )
        }
    }

    @Test
    fun authZenSource_aGoTrustShapedBareDns_resolvesToThePrefixedVerifierId_withTheArchiveHash() = runTest(dispatcher) {
        val trust = TrustResult(trusted = true, context = buildJsonObject {
            putJsonArray("verifier_ids") { add(buildJsonObject { put("verifier_id_type", "x509_san_dns"); put("verifier_id", "verifier.example"); put("basis", "client-id-binding") }) }
        })
        val ctx = VerifierIdContext(
            org.siros.sdk.wallet.dcapi.DCAPIRequest(clientId = "x509_san_dns:verifier.example", responseMode = "direct_post.jwt", nonce = "n", dcqlQuery = null, clientMetadata = null, protocol = "openid4vp-redirect", state = null),
            trust, "https://verifier.example",
        )
        val id = AuthZENSource("x509_san_dns").resolve(ctx)
        assertEquals("x509_san_dns:verifier.example", id)
        assertTrue(sha256HexOf(id!!.toByteArray()).startsWith("6eae85a0"))
    }

    @Test
    fun circuitZkDcApi_anEmptyTypeList_refusesAPseudonymRequest_evenWhenThePdpHasIds() = runTest(dispatcher) {
        val s = czkSetup(types = emptyList(), trust = czkIds("semantic" to "semantic_id:A"))
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.VERIFIER_ID_UNAVAILABLE)
        assertEquals(0, s.prover.calls)
    }

    @Test
    fun circuitZkDcApi_aHostRegisteredSourceIsUsable_forASupportedType_butNotForAnUnsupportedOne() = runTest(dispatcher) {
        val none: suspend () -> JsonObject = { buildJsonObject { put("decision", true) } }
        val calls = mutableListOf<String>()
        // The PDP says nothing: the registered source answers for x509_san_dns.
        val s = czkSetup(trust = none, sources = listOf(FixedSource("x509_san_dns", "host-id", calls)))
        assertEquals(
            org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("host-id")),
            czkPseudonymOf(czkRun(s, czkRequest())),
        )
        // The type is not in the wallet's list: the source is never consulted.
        calls.clear()
        czkRefused(
            czkSetup(trust = none, types = listOf("semantic"), sources = listOf(FixedSource("x509_san_dns", "host-id", calls))),
            czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.VERIFIER_ID_UNAVAILABLE,
        )
        assertTrue(calls.isEmpty())
        // The PDP wins over a registered source for the same type, which is then not consulted.
        calls.clear()
        val both = czkSetup(trust = czkIds("x509_san_dns" to "from-pdp"), sources = listOf(FixedSource("x509_san_dns", "host-id", calls)))
        assertEquals(org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:from-pdp")), czkPseudonymOf(czkRun(both, czkRequest())))
        assertTrue(calls.isEmpty())
    }

    @Test
    fun circuitZkDcApi_trustFailureAndPdpOutage_areRefused_withNoLocalOrCachedFallback() = runTest(dispatcher) {
        val untrusted = czkSetup(trust = { buildJsonObject { put("decision", false) } })
        czkRefused(untrusted, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.NOT_TRUSTED)

        // An outage: the request is refused and nothing stale or local stands in for it.
        val outage = czkSetup(trust = { throw java.io.IOException("PDP unreachable") })
        czkRefused(outage, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.TRUST_UNAVAILABLE)
        coVerify(exactly = 1) { outage.apiClient.evaluateTrust(any()) }

        val rejected = czkSetup(trust = { throw IllegalStateException("403") })
        czkRefused(rejected, czkRequest())

        // A wallet configured for local-only reader trust still asks the PDP for circuit_zk, and an outage is a refusal.
        val localOnly = czkSetup(trust = { throw java.io.IOException("PDP unreachable") }, localOnlyTrust = true)
        czkRefused(localOnly, czkRequest())
        coVerify(exactly = 1) { localOnly.apiClient.evaluateTrust(any()) }
    }

    @Test
    fun circuitZkDcApi_localOnlyTrustMode_stillUsesThePdp() = runTest(dispatcher) {
        val s = czkSetup(localOnlyTrust = true)
        assertEquals(listOf(1L), czkRun(s, czkRequest()).credentialIds)
        coVerify(exactly = 1) { s.apiClient.evaluateTrust(any()) }
    }

    @Test
    fun circuitZkDcApi_falseAgePredicate_isRefusedWithNoDescription() = runTest(dispatcher) {
        val age = org.siros.sdk.credentials.CircuitZkFunction(
            "age_check", "a", Json.parseToJsonElement("""{"ge":"2010-01-01"}""").jsonObject,
        )
        val s = czkSetup(functions = listOf(age))
        czkRefused(s, czkRequest())
        assertEquals(0, s.prover.calls)
    }

    @Test
    fun circuitZkDcApi_pscMismatch_isRefused() = runTest(dispatcher) {
        val s = czkSetup(psc = ByteArray(32))
        czkRefused(s, czkRequest())
        assertEquals(0, s.prover.calls)
    }

    @Test
    fun circuitZkDcApi_noCredentialInTheWallet_isRefusedWithTheNoMatchReason() = runTest(dispatcher) {
        val s = czkSetup(credentials = emptyList())
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.NO_MATCHING_CREDENTIAL)
        assertEquals(0, s.prover.calls)
    }

    private fun czkCred(id: Long, batch: Long, instance: Int = 0) = StoredCredential(
        id = id, format = "mso_mdoc", raw = CzkFixtures.mdoc(CzkFixtures.psc, "2000-06-15"), credentialIssuerIdentifier = CzkFixtures.ISSUER,
        metadata = CredentialMetadata(name = "Nym $id"), batchId = batch, instanceId = instance,
    )

    private fun czkSelectionSetup() = czkSetup(credentials = listOf(czkCred(1, 1), czkCred(2, 2), czkCred(3, 1, 1)))

    private fun czkRunSelected(s: CzkSetup, vararg ids: Long, raw: String = czkRequest()) =
        kotlinx.coroutines.runBlocking { s.wallet.handleDCAPIRequest(raw, CzkFixtures.ORIGIN, ids.toList()) }

    @Test
    fun circuitZkDcApi_presentsExactlyTheCredentialTheUserPicked() = runTest(dispatcher) {
        // No pick is refused: nothing is chosen for the user (no silent first-eligible), and nothing is asked or proved.
        val none = czkSelectionSetup()
        czkRefused(none, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.SELECTED_CREDENTIAL_UNAVAILABLE, ids = emptyList())
        assertTrue(none.consents.isEmpty())
        assertEquals(0, none.prover.calls)
        // A pick of the second credential is what is presented.
        assertEquals(listOf(2L), czkRunSelected(czkSelectionSetup(), 2L).credentialIds)
        // The prover ran once, for the picked credential only.
        val s = czkSelectionSetup()
        czkRunSelected(s, 2L)
        assertEquals(1, s.prover.calls)
    }

    @Test
    fun circuitZkDcApi_aPickIsServedByAnotherCopyOfTheSameCredential() = runTest(dispatcher) {
        // Credential 3 is the second copy (batch 1) of credential 1: picking 3 presents 3, not the other credential.
        assertEquals(listOf(3L), czkRunSelected(czkSelectionSetup(), 3L).credentialIds)
    }

    @Test
    fun circuitZkDcApi_aPickThatIsNotACandidateIsRefused_neverReplacedByAnotherCredential() = runTest(dispatcher) {
        val plain = StoredCredential(id = 9L, format = "dc+sd-jwt", raw = "x", metadata = CredentialMetadata(name = "Plain"), batchId = 9L, instanceId = 0)
        for (pick in listOf(longArrayOf(99L), longArrayOf(9L), longArrayOf(-1L))) {
            val s = czkSetup(credentials = listOf(czkCred(1, 1), czkCred(2, 2), plain))
            val e = org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
                czkRunSelected(s, *pick)
            }
            assertEquals(org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.SELECTED_CREDENTIAL_UNAVAILABLE, e.reason)
            assertEquals(0, s.prover.calls)
            assertTrue(s.history.isEmpty())
        }
    }

    @Test
    fun circuitZkDcApi_multiQuery_eachQueryTakesAPickThatIsItsCandidate() = runTest(dispatcher) {
        val raw = czkRequest(queryIds = listOf("q", "q2"))
        // One credential picked for both (it satisfies both queries).
        assertEquals(listOf(2L, 2L), czkRunSelected(czkSelectionSetup(), 2L, raw = raw).credentialIds)
        // One credential per query, in query order.
        assertEquals(listOf(2L, 1L), czkRunSelected(czkSelectionSetup(), 2L, 1L, raw = raw).credentialIds)
        assertEquals(listOf(1L, 2L), czkRunSelected(czkSelectionSetup(), 1L, 2L, raw = raw).credentialIds)
        // No pick at all is refused, not read as "the first eligible for each".
        val none = czkSelectionSetup()
        czkRefused(none, raw, reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.SELECTED_CREDENTIAL_UNAVAILABLE, ids = emptyList())
        assertEquals(0, none.prover.calls)
    }

    @Test
    fun circuitZkDcApi_multiQuery_aPartlyUnreadableOrForeignSelectionIsRefused_theReadableSubsetNeverAuthorises() = runTest(dispatcher) {
        val raw = czkRequest(queryIds = listOf("q", "q2"))
        // Both queries accept credential 2; the second pick is the unreadable sentinel or an unknown id.
        for (pick in listOf(longArrayOf(2L, -1L), longArrayOf(-1L, 2L), longArrayOf(2L, 99L))) {
            val s = czkSelectionSetup()
            val e = org.junit.Assert.assertThrows(pick.toList().toString(), org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
                czkRunSelected(s, *pick, raw = raw)
            }
            assertEquals(org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.SELECTED_CREDENTIAL_UNAVAILABLE, e.reason)
            assertEquals(0, s.prover.calls)
            assertTrue(s.history.isEmpty())
        }
    }

    @Test
    fun circuitZkDcApi_multiQuery_aDuplicatedPickIsRefused() = runTest(dispatcher) {
        val s = czkSelectionSetup()
        val e = org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
            czkRunSelected(s, 2L, 2L, raw = czkRequest(queryIds = listOf("q", "q2")))
        }
        assertEquals(org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.SELECTED_CREDENTIAL_UNAVAILABLE, e.reason)
        assertEquals(0, s.prover.calls)
    }

    @Test
    fun circuitZkDcApi_multiQuery_aPickMatchingNoQueryIsStillRefused() = runTest(dispatcher) {
        val s = czkSelectionSetup()
        org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
            czkRunSelected(s, 77L, raw = czkRequest(queryIds = listOf("q", "q2")))
        }
        assertEquals(0, s.prover.calls)
    }

    @Test
    fun circuitZkDcApi_multiQuery_aQueryTheUsersPickIsNotACandidateOf_isRefused_notAnsweredWithAnotherCredential() = runTest(dispatcher) {
        // Query "qo" wants the other doctype (only credential 5 is its candidate); the user picked credential 1.
        val other = StoredCredential(
            id = 5L, format = "mso_mdoc", raw = CzkFixtures.mdoc(psc = CzkFixtures.pscFor(CzkFixtures.OTHER_DOCTYPE), docType = CzkFixtures.OTHER_DOCTYPE), credentialIssuerIdentifier = CzkFixtures.ISSUER,
            metadata = CredentialMetadata(name = "Other"), batchId = 5L, instanceId = 0,
        )
        val raw = czkRequest(queryIds = listOf("qo", "q"), queryDoctypes = listOf(CzkFixtures.OTHER_DOCTYPE, CzkFixtures.DOCTYPE))
        val s = czkSetup(credentials = listOf(czkCred(1, 1), other), extraDocTypes = setOf(CzkFixtures.OTHER_DOCTYPE))
        val e = org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) { czkRunSelected(s, 1L, raw = raw) }
        assertEquals(org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.SELECTED_CREDENTIAL_UNAVAILABLE, e.reason)
        assertEquals(0, s.prover.calls)
        assertTrue(s.history.isEmpty())
        // One pick per query is served, each from its own query's candidates.
        assertEquals(listOf(5L, 1L), czkRunSelected(czkSetup(credentials = listOf(czkCred(1, 1), other), extraDocTypes = setOf(CzkFixtures.OTHER_DOCTYPE)), 5L, 1L, raw = raw).credentialIds)
    }

    @Test
    fun circuitZkDcApi_flagOff_isRefusedAsBefore() = runTest(dispatcher) {
        val s = czkSetup(flagOn = false)
        czkRefused(s, czkRequest())
        // The existing path: trust is evaluated, then nothing matches. The prover is never reached.
        assertEquals(0, s.prover.calls)
    }

    // ── circuit_zk presentation consent ──

    private fun czkAgeFunction(json: String) = org.siros.sdk.credentials.CircuitZkFunction("age_check", "a", Json.parseToJsonElement(json).jsonObject)

    private fun czkSeedSource() = CredentialSecretSeedSource { NymTestCredentials.seed.copyOf() }

    @Test
    fun circuitZkConsent_isAskedBeforeAnySeedSignerOrProverCall() = runTest(dispatcher) {
        val s = czkSscSetup(czkSeedSource(), proverSigns = true)
        czkRun(s, czkRequest())
        // Consent first; only then the seed, then the prover, which asks the signer.
        assertEquals(listOf("consent", "seed", "prove", "sign"), s.events)
    }

    @Test
    fun circuitZkConsent_declineThrowTimeoutAndCancelAreAllDeclines_withZeroSeedSignerProverCalls() = runTest(dispatcher) {
        val variants = mapOf<String, suspend (org.siros.sdk.credentials.PresentationConsentRequest) -> Boolean>(
            "decline" to { false },
            "throws" to { throw IllegalStateException("boom") },
            "handler cancelled (the dialog went away)" to { throw kotlinx.coroutines.CancellationException("dialog dismissed") },
            "never answers" to { kotlinx.coroutines.awaitCancellation() },
        )
        for ((name, answer) in variants) {
            val s = czkSscSetup(czkSeedSource(), consent = answer, proverSigns = true)
            s.wallet.presentationConsentTimeoutMillis = 100L
            czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.USER_DECLINED)
            assertEquals(name, listOf("consent"), s.events)
            assertEquals(name, 0, s.prover.calls)
        }
    }

    @Test
    fun circuitZkConsent_withNoHandlerAtAll_isRefusedAsUnavailable_neverProceeds() = runTest(dispatcher) {
        val s = czkSscSetup(czkSeedSource(), noConsentHandler = true, proverSigns = true)
        // The TS12 handler is a different consent: it neither enables nor stands in for this one.
        s.wallet.transactionConsentHandler = TransactionConsentHandler { true }
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.CONSENT_UNAVAILABLE)
        assertTrue(s.events.isEmpty())
        coVerify(exactly = 0) { s.apiClient.evaluateTrust(any()) }
    }

    @Test
    fun circuitZkConsent_aPerRequestHandlerIsUsedInsteadOfTheWalletOne_andAloneIsEnough() = runTest(dispatcher) {
        val own = mutableListOf<org.siros.sdk.credentials.PresentationConsentRequest>()
        val s = czkSscSetup(czkSeedSource())
        kotlinx.coroutines.runBlocking {
            s.wallet.handleDCAPIRequestWithPresentationConsent(czkRequest(), CzkFixtures.ORIGIN, PresentationConsentHandler { own += it; true }, listOf(1L))
        }
        assertEquals(1, own.size)
        assertTrue("the wallet-level handler was not asked", s.consents.isEmpty())
        // With no wallet-level handler, the per-request one is all that is needed.
        val bare = czkSscSetup(czkSeedSource(), noConsentHandler = true)
        kotlinx.coroutines.runBlocking {
            bare.wallet.handleDCAPIRequestWithPresentationConsent(czkRequest(), CzkFixtures.ORIGIN, PresentationConsentHandler { true }, listOf(1L))
        }
        assertEquals(1, bare.prover.calls)
        // A per-request handler that declines is a decline, whatever the wallet-level one would say.
        val declined = czkSscSetup(czkSeedSource())
        org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIRequestRefused::class.java) {
            kotlinx.coroutines.runBlocking {
                declined.wallet.handleDCAPIRequestWithPresentationConsent(czkRequest(), CzkFixtures.ORIGIN, PresentationConsentHandler { false }, listOf(1L))
            }
        }
        assertEquals(0, declined.prover.calls)
        assertTrue(declined.events.isEmpty())
    }

    @Test
    fun circuitZkConsent_carriesTheItemsTheVerifierWillReceive_andNoSecret() = runTest(dispatcher) {
        val s = czkSscSetup(czkSeedSource())
        czkRun(s, czkRequest())
        val request = s.consents.single()
        assertEquals("rp.example", request.verifier.label)
        assertEquals("x509_san_dns:rp.example", request.verifier.verifierId)
        assertEquals("x509_san_dns", request.verifier.verifierIdType)
        assertTrue(request.requestSigned)
        val entry = request.entries.single()
        assertEquals(org.siros.sdk.credentials.CredentialRef("Nym", null), entry.credential)
        assertEquals(
            listOf<org.siros.sdk.credentials.ConsentItem>(
                org.siros.sdk.credentials.ConsentItem.Pseudonym(
                    config = "known-offender-matching-ssc",
                    scope = org.siros.sdk.credentials.PseudonymScope.PER_VERIFIER,
                    remappableByIssuer = true,
                    crossSite = false,
                    verifierId = "x509_san_dns:rp.example",
                    verifierContext = null,
                ),
            ),
            entry.items,
        )
        // Nothing the user is shown carries a seed, a pseudonym value or a birth date.
        val shown = request.toString()
        assertFalse(shown.contains(java.util.HexFormat.of().formatHex(NymTestCredentials.seed)))
        assertFalse(shown.contains("2000-06-15"))
    }

    @Test
    fun circuitZkConsent_aTwoQueryRequest_isOneConsentCallCoveringBothQueries() = runTest(dispatcher) {
        val s = czkSetup(
            functions = listOf(
                czkSscFunction("known-offender-matching-psc").single(),
                czkAgeFunction("""{"ge":"1999-01-01","le":"2005-01-01"}"""),
            ),
            credentials = listOf(czkCred(1, 1), czkCred(2, 2)),
        )
        val raw = czkRequest(queryIds = listOf("q", "q2"))
        val result = kotlinx.coroutines.runBlocking { s.wallet.handleDCAPIRequest(raw, CzkFixtures.ORIGIN, listOf(1L, 2L)) }
        assertEquals(listOf(1L, 2L), result.credentialIds)
        val request = s.consents.single()
        assertEquals(listOf("Nym 1", "Nym 2"), request.entries.map { it.credential.name })
        for (entry in request.entries) assertEquals(listOf("pseudonym", "age_range"), entry.items.map { if (it is org.siros.sdk.credentials.ConsentItem.Pseudonym) "pseudonym" else "age_range" })
        // One consent, then everything else.
        assertEquals("consent", s.events.first())
        assertEquals(1, s.events.count { it == "consent" })
    }

    @Test
    fun circuitZkConsent_anUnsatisfiablePredicate_isRefusedLocally_withoutAskingTheUser() = runTest(dispatcher) {
        // The credential's birth_date is 2000-06-15; the request wants someone born in 1980 or earlier.
        val s = czkSetup(functions = listOf(czkAgeFunction("""{"le":"1980-01-01"}""")), secretSeedSource = czkSeedSource())
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.SELECTED_CREDENTIAL_UNAVAILABLE)
        assertTrue("the user was not asked", s.consents.isEmpty())
        assertTrue(s.events.isEmpty())
        // A satisfiable one is asked, with the age item in its human form.
        val ok = czkSetup(functions = listOf(czkAgeFunction("""{"ge":"1999-01-01","le":"2005-01-01"}""")))
        czkRun(ok, czkRequest())
        val age = ok.consents.single().entries.single().items.single() as org.siros.sdk.credentials.ConsentItem.Predicate
        assertTrue(age.age is org.siros.sdk.credentials.AgeForm.Between)
        assertEquals(listOf("birth_date"), age.claim.path)
    }

    @Test
    fun circuitZkConsent_twoQueriesWhoseAgeBoundsTogetherPinTheBirthDate_areRefusedBeforeConsent() = runTest(dispatcher) {
        // Each plan alone is one-sided and passes the rulebook; ge=D and le=D together would reveal the exact date.
        val plans = listOf("""{"ge":"2000-06-15"}""", """{"le":"2000-06-15"}""")
        val s = czkSetup(functionsPerQuery = { listOf(czkAgeFunction(plans[it])) })
        czkRefused(s, czkRequest(queryIds = listOf("q", "q2")), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.UNSUPPORTED_REQUEST, ids = listOf(1L))
        assertTrue(s.consents.isEmpty())
        assertTrue(s.events.isEmpty())
    }

    @Test
    fun circuitZkConsent_aRefusalBeforeThePhaseOneEnds_neverAsks() = runTest(dispatcher) {
        // Untrusted verifier, and no resolvable verifier id: both refused before the user is asked.
        val untrusted = czkSscSetup(czkSeedSource())
        coEvery { untrusted.apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", false) }
        czkRefused(untrusted, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.NOT_TRUSTED)
        assertTrue(untrusted.consents.isEmpty())
        val noId = czkSetup(functions = czkSscFunction(), trust = czkIds(), secretSeedSource = czkSeedSource())
        czkRefused(noId, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.VERIFIER_ID_UNAVAILABLE)
        assertTrue(noId.consents.isEmpty())
        assertTrue(noId.events.isEmpty())
    }

    // ── predicates over any claim ──

    private val numberRange = org.siros.sdk.credentials.PredicateFunction(
        id = "number_range", claim = org.siros.sdk.credentials.ClaimSource.FromParam, valueType = org.siros.sdk.credentials.ValueType.NUMBER,
        comparisons = linkedMapOf("ge" to org.siros.sdk.credentials.ComparisonOp.GE, "le" to org.siros.sdk.credentials.ComparisonOp.LE), minSpan = 10,
    )

    private fun czkScoreSetup(
        score: Long,
        params: String = """{"claim":"score","ge":10,"le":20}""",
        scoreValue: com.upokecenter.cbor.CBORObject = com.upokecenter.cbor.CBORObject.FromObject(score),
        declared: Boolean = true,
        consent: suspend (org.siros.sdk.credentials.PresentationConsentRequest) -> Boolean = { false },
        innerProver: org.siros.sdk.keystore.CircuitZkProver? = null,
    ) = czkSetup(
        functions = listOf(org.siros.sdk.credentials.CircuitZkFunction("number_range", "p", Json.parseToJsonElement(params).jsonObject)),
        credentials = listOf(StoredCredential(
            id = 1L, format = "mso_mdoc",
            raw = CzkFixtures.mdoc(extra = listOf("score" to scoreValue)),
            metadata = CredentialMetadata(name = "Nym", claims = listOf(org.siros.sdk.credentials.ClaimMeta(listOf(CzkFixtures.DOCTYPE, "score"), "Credit score"))), batchId = 1L, instanceId = 0,
        )),
        predicates = if (declared) org.siros.sdk.credentials.PredicateFunctions(listOf(org.siros.sdk.credentials.PredicateFunctions.AGE_CHECK, numberRange)) else null,
        extraFunctions = setOf("number_range"),
        consent = consent,
        innerProver = innerProver,
    )

    @Test
    fun circuitZkConsent_aPredicateOnAnotherClaim_isDescribedWithTheCredentialsOwnLabel_andNeverTheValue() = runTest(dispatcher) {
        val s = czkScoreSetup(15)
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.USER_DECLINED)
        val item = s.consents.single().entries.single().items.single() as org.siros.sdk.credentials.ConsentItem.Predicate
        assertEquals("number_range", item.functionId)
        assertEquals(org.siros.sdk.credentials.ClaimRef(listOf("score"), "Credit score"), item.claim)
        assertNull(item.age)
        assertFalse(s.consents.single().toString().contains("15,") || s.consents.single().toString().contains("value=15"))
        assertEquals(listOf("consent"), s.events)
    }

    @Test
    fun circuitZkDefaultValidator_takesItsPredicateRulesFromTheSameDeclarations() {
        val plan = org.siros.sdk.credentials.CircuitZkPlan(listOf(
            org.siros.sdk.credentials.CircuitZkFunction("number_range", "p", Json.parseToJsonElement("""{"claim":"score","ge":10,"le":20}""").jsonObject),
        ), raw = Json.parseToJsonElement("""{"meta":{"source_format":"mso_mdoc","doctype_value":"d"}}""").jsonObject)
        val declared = org.siros.sdk.credentials.PredicateFunctions(listOf(org.siros.sdk.credentials.PredicateFunctions.AGE_CHECK, numberRange))
        assertEquals(org.siros.sdk.credentials.CircuitZkVerdict.Ok, defaultCircuitZkValidator(null, declared).validate(plan))
        val narrow = org.siros.sdk.credentials.CircuitZkPlan(listOf(
            org.siros.sdk.credentials.CircuitZkFunction("number_range", "p", Json.parseToJsonElement("""{"claim":"score","ge":10,"le":15}""").jsonObject),
        ), raw = Json.parseToJsonElement("""{"meta":{"source_format":"mso_mdoc","doctype_value":"d"}}""").jsonObject)
        assertEquals("number_range_span_too_short", (defaultCircuitZkValidator(null, declared).validate(narrow) as org.siros.sdk.credentials.CircuitZkVerdict.AccessDenied).ruleId)
        // Undeclared: the validator does not know it.
        assertEquals("function_unknown", (defaultCircuitZkValidator(null).validate(plan) as org.siros.sdk.credentials.CircuitZkVerdict.AccessDenied).ruleId)
    }

    @Test
    fun circuitZkConsent_aDecoyNamespacesSameNamedClaimIsNeverTheLabel() = runTest(dispatcher) {
        val s = czkSetup(
            functions = listOf(org.siros.sdk.credentials.CircuitZkFunction("number_range", "p", Json.parseToJsonElement("""{"claim":"score","ge":10,"le":20}""").jsonObject)),
            credentials = listOf(StoredCredential(
                id = 1L, format = "mso_mdoc",
                raw = CzkFixtures.mdoc(extra = listOf("score" to com.upokecenter.cbor.CBORObject.FromObject(15L))),
                metadata = CredentialMetadata(name = "Nym", claims = listOf(org.siros.sdk.credentials.ClaimMeta(listOf("org.example.other", "score"), "Other score"))),
                batchId = 1L, instanceId = 0,
            )),
            predicates = org.siros.sdk.credentials.PredicateFunctions(listOf(org.siros.sdk.credentials.PredicateFunctions.AGE_CHECK, numberRange)),
            extraFunctions = setOf("number_range"),
            consent = { false },
        )
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.USER_DECLINED)
        val item = s.consents.single().entries.single().items.single() as org.siros.sdk.credentials.ConsentItem.Predicate
        assertNull(item.claim.label)
        assertEquals("score", item.claim.display)
    }

    @Test
    fun circuitZkConsent_theRulebookExamplesSourceParamIsAcceptedForAgeCheck_andAnotherSourceIsRefused() = runTest(dispatcher) {
        fun age(source: String) = czkSetup(
            functions = listOf(czkAgeFunction("""{"ge":"1999-01-01","le":"2005-01-01","source":$source}""")),
            consent = { false },
        )
        val ok = age("""{"path":["birth_date"]}""")
        czkRefused(ok, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.USER_DECLINED)
        assertEquals(1, ok.consents.size)
        val other = age("""{"path":["family_name"]}""")
        czkRefused(other, czkRequest())
        assertTrue(other.consents.isEmpty())
    }

    @Test
    fun circuitZkConsent_aTaggedCborNumberIsANumber_notAMismatchingType() = runTest(dispatcher) {
        // Tag 4 (decimal fraction) [-1, 150] is 15: within 10..20, so the user is asked.
        val fifteen = com.upokecenter.cbor.CBORObject.FromObject(com.upokecenter.numbers.EDecimal.FromString("15.0"))
        assertTrue(fifteen.isTagged)
        val s = czkScoreSetup(0, scoreValue = fifteen)
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.USER_DECLINED)
        assertEquals(1, s.consents.size)
        // 25 is outside the range, tagged or not: refused locally, never asked.
        val out = czkScoreSetup(0, scoreValue = com.upokecenter.cbor.CBORObject.FromObject(com.upokecenter.numbers.EDecimal.FromString("25.0")))
        czkRefused(out, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.SELECTED_CREDENTIAL_UNAVAILABLE)
        assertTrue(out.consents.isEmpty())
    }

    /** A prover for a custom predicate: every planned function proves as a predicate. */
    private val predicateOnlyProver = object : org.siros.sdk.keystore.CircuitZkProver {
        override suspend fun prove(input: org.siros.sdk.keystore.CircuitZkProveInput) = org.siros.sdk.keystore.CircuitZkProveOutput(
            proof = byteArrayOf(1), results = input.plan.functions.associate { it.handle to org.siros.sdk.credentials.ResultValue.Predicate },
        )
    }

    @Test
    fun circuitZkConsent_aDeclaredCustomPredicate_isPresentedAfterConsent_withTheStockKeystore() = runTest(dispatcher) {
        // The presenter must know every function the wallet described to the user, not only the rulebook's.
        val s = czkScoreSetup(15, consent = { true }, innerProver = predicateOnlyProver)
        val result = czkRun(s, czkRequest())
        assertEquals(listOf(1L), result.credentialIds)
        assertEquals(1, s.prover.calls)
        assertEquals(1, s.consents.size)
    }

    @Test
    fun circuitZkConsent_theLocalPrecheck_isNotAboutBirthDate_andRefusesWithoutAsking() = runTest(dispatcher) {
        val s = czkScoreSetup(5)
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.SELECTED_CREDENTIAL_UNAVAILABLE)
        assertTrue(s.consents.isEmpty())
    }

    @Test
    fun circuitZkConsent_aFunctionTheWalletCannotDescribe_isRefusedBeforeConsent() = runTest(dispatcher) {
        // The validator and circuit accept number_range, but the wallet has no declaration for it: it cannot say what is disclosed.
        val s = czkScoreSetup(15, declared = false)
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.UNSUPPORTED_REQUEST)
        assertTrue(s.consents.isEmpty())
        assertTrue(s.events.isEmpty())
    }

    @Test
    fun circuitZkConsent_aPredicateThatPinsTheClaim_isRefusedByTheDeclaredMinimumSelectivity() = runTest(dispatcher) {
        val s = czkScoreSetup(15, params = """{"claim":"score","ge":15,"le":15}""")
        czkRefused(s, czkRequest(), reason = org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.UNSUPPORTED_REQUEST)
        assertTrue(s.consents.isEmpty())
    }

    private class FixedSource(override val type: String, val id: String?, val calls: MutableList<String>) : VerifierIdSource {
        override suspend fun resolve(context: VerifierIdContext): String? { calls += id ?: "declined-$type"; return id }
    }

    @Test
    fun circuitZkDcApi_theVerifierIdentityIsResolvedOncePerRequest_andEveryQueryAndTheConsentUseIt() = runTest(dispatcher) {
        // A source that answers differently (here: then declines) on later calls must not split the request's identity.
        var calls = 0
        val flaky = object : VerifierIdSource {
            override val type = "x509_san_dns"
            override suspend fun resolve(context: VerifierIdContext): String? = if (++calls == 1) "x509_san_dns:first.example" else null
        }
        val s = czkSetup(trust = { buildJsonObject { put("decision", true) } }, sources = listOf(flaky))
        val result = czkRun(s, czkRequest(queryIds = listOf("q", "q2")))
        assertEquals(1, calls)
        val tokens = Json.parseToJsonElement(result.responseJson).jsonObject["data"]!!.jsonObject["vp_token"]!!.jsonObject
        val expected = org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("x509_san_dns:first.example"))
        for (q in listOf("q", "q2")) assertEquals(q, expected, CzkDecoded(tokens[q]!!.jsonArray.single().jsonPrimitive.content).results["n"])
        assertEquals("x509_san_dns:first.example", s.consents.single().verifier.verifierId)
    }

    @Test
    fun circuitZkDcApi_sourcesForOneTypeAreTriedInOrder_andADecliningSourceFallsThrough() = runTest(dispatcher) {
        val calls = mutableListOf<String>()
        val s = czkSetup(trust = { buildJsonObject { put("decision", true) } }, sources = listOf(
            FixedSource("x509_san_dns", null, calls),
            FixedSource("x509_san_dns", "second-id", calls),
            FixedSource("x509_san_dns", "third-id", calls),
        ))
        val result = czkRun(s, czkRequest())
        val decoded = czkDecoded(result.responseJson)
        assertEquals(org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("second-id")), decoded.results["n"])
        assertEquals(listOf("declined-x509_san_dns", "second-id"), calls)
    }

    @Test
    fun circuitZkDcApi_authZenSourceReadsTheVerifierIdFromTheTrustContext() = runTest(dispatcher) {
        val semantic = org.siros.sdk.credentials.CircuitZkFunction(
            "pseudonym", "n",
            Json.parseToJsonElement("""{"config":"known-offender-matching-psc","ver":1,"prf":"sha-256"}""").jsonObject,
        )
        val withContext = czkSetup(functions = listOf(semantic), trust = {
            buildJsonObject {
                put("decision", true)
                // go-trust #203: a LIST of {verifier_id_type, verifier_id, basis}. Entries of other types
                // come first, and the requested type is listed twice with the same value (one identifier).
                putJsonObject("context") {
                    putJsonArray("verifier_ids") {
                        add(buildJsonObject { put("verifier_id_type", "dns"); put("verifier_id", "rp.example.com"); put("basis", "client-id-binding") })
                        add(buildJsonObject { put("verifier_id_type", "semantic"); put("verifier_id", "semantic_id:LEIXG-5299"); put("basis", "x5c-chain") })
                        add(buildJsonObject { put("verifier_id_type", "semantic"); put("verifier_id", "semantic_id:LEIXG-5299"); put("basis", "other-basis") })
                    }
                }
            }
        })
        val result = czkRun(withContext, czkRequest())
        assertEquals(
            org.siros.sdk.credentials.ResultValue.Pseudonym(czkExpectedPseudonym("semantic_id:LEIXG-5299")),
            czkDecoded(result.responseJson).results["n"],
        )

        // No context, no verifier_ids, or a different type: the source declines and the request is refused.
        for (trust in listOf<suspend () -> JsonObject>(
            { buildJsonObject { put("decision", true) } },
            { buildJsonObject { put("decision", true); putJsonObject("context") { put("framework", "x") } } },
            { buildJsonObject { put("decision", true); putJsonObject("context") { putJsonArray("verifier_ids") { add(buildJsonObject { put("verifier_id_type", "other"); put("verifier_id", "v") }) } } } },
            // Malformed or empty entries of the requested type are skipped, never guessed from.
            { buildJsonObject { put("decision", true); putJsonObject("context") { putJsonArray("verifier_ids") { add(buildJsonObject { put("verifier_id_type", "semantic"); put("verifier_id", "") }); add(kotlinx.serialization.json.JsonPrimitive("semantic")) } } } },
            // Two DISTINCT values of the requested type: the wallet does not choose, it declines.
            { buildJsonObject { put("decision", true); putJsonObject("context") { putJsonArray("verifier_ids") {
                add(buildJsonObject { put("verifier_id_type", "semantic"); put("verifier_id", "semantic_id:LEIXG-5299") })
                add(buildJsonObject { put("verifier_id_type", "semantic"); put("verifier_id", "semantic_id:LEIXG-OTHER") })
            } } } },
            // The pre-contract map form is not the contract.
            { buildJsonObject { put("decision", true); putJsonObject("context") { putJsonObject("verifier_ids") { put("semantic", "semantic_id:LEIXG-5299") } } } },
        )) {
            czkRefused(czkSetup(functions = listOf(semantic), trust = trust), czkRequest())
        }
    }

    @Test
    fun authZenSource_usesTheOneDistinctValueOfTheRequestedType_andDeclinesWhenAmbiguous() = runTest(dispatcher) {
        fun ctx(ids: kotlinx.serialization.json.JsonElement) = VerifierIdContext(
            org.siros.sdk.wallet.dcapi.DCAPIRequest(
                clientId = "c", responseMode = "dc_api", nonce = "n", dcqlQuery = null, clientMetadata = null,
                keyMaterial = null, protocol = "openid4vp-v1-signed", state = null,
            ),
            TrustResult(trusted = true, context = buildJsonObject { put("verifier_ids", ids) }), "https://rp.example",
        )
        val ids = Json.parseToJsonElement(
            """[{"verifier_id_type":"semantic","verifier_id":""},{"verifier_id_type":"x509_san_dns","verifier_id":"d1"},
               {"verifier_id_type":"x509_san_dns","verifier_id":"d2"},{"verifier_id_type":"uri","verifier_id":"u"},
               {"verifier_id_type":"semantic","verifier_id":"semantic_id:one","basis":"x5c-chain"},{"verifier_id_type":"semantic","verifier_id":"semantic_id:one"}]""",
        )
        assertEquals("semantic_id:one", AuthZENSource("semantic").resolve(ctx(ids)))
        // Distinct values of one type: declined, not guessed.
        assertNull(AuthZENSource("x509_san_dns").resolve(ctx(ids)))
        // A type that is no rulebook verifier id form is never taken.
        assertNull(AuthZENSource("uri").resolve(ctx(ids)))
    }

    private class CancellingSource(override val type: String) : VerifierIdSource {
        override suspend fun resolve(context: VerifierIdContext): String? = throw kotlinx.coroutines.CancellationException("cancelled")
    }

    @Test
    fun verifierIdRegistry_doesNotSwallowCancellation_butStillSkipsAFailingSource() = runTest(dispatcher) {
        val ctx = VerifierIdContext(
            org.siros.sdk.wallet.dcapi.DCAPIRequest(
                clientId = "c", responseMode = "dc_api", nonce = "n", dcqlQuery = null, clientMetadata = null,
                keyMaterial = null, protocol = "openid4vp-v1-signed", state = null,
            ),
            TrustResult(trusted = true), "https://rp.example",
        )
        org.junit.Assert.assertThrows(kotlinx.coroutines.CancellationException::class.java) {
            kotlinx.coroutines.runBlocking { VerifierIdRegistry(listOf("t"), listOf(CancellingSource("t"), FixedSource("t", "later", mutableListOf()))).resolve(ctx) }
        }
        val failing = object : VerifierIdSource {
            override val type = "t"
            override suspend fun resolve(context: VerifierIdContext): String? = error("boom")
        }
        assertEquals(ResolvedVerifierId("t", "later"), VerifierIdRegistry(listOf("t"), listOf(failing, FixedSource("t", "later", mutableListOf()))).resolve(ctx))
    }

    @Test
    fun circuitZkDcApi_theTrustRequestNeverNarrowsTheVerifierIdType() = runTest(dispatcher) {
        // Exactly one type is asked for: the PDP is still not narrowed, so the wallet can pick by its own order.
        val s = czkSetup()
        czkRun(s, czkRequest())
        assertNull(s.trustRequests.single()["context"])
        val noPseudonym = czkSetup(functions = listOf(org.siros.sdk.credentials.CircuitZkFunction(
            "age_check", "a", Json.parseToJsonElement("""{"ge":"2000-01-01"}""").jsonObject,
        )))
        czkRun(noPseudonym, czkRequest())
        assertNull(noPseudonym.trustRequests.single()["context"])
    }

    @Test
    fun verifierIdRegistry_triesSourcesOfATypeInOrder_afterThePdp_andRejectsAnInvalidTypeList() = runTest(dispatcher) {
        val ctx = VerifierIdContext(
            org.siros.sdk.wallet.dcapi.DCAPIRequest(
                clientId = "c", responseMode = "dc_api", nonce = "n", dcqlQuery = null, clientMetadata = null,
                keyMaterial = null, protocol = "openid4vp-v1-signed", state = null,
            ),
            TrustResult(trusted = true), "https://rp.example",
        )
        val calls = mutableListOf<String>()
        val r = VerifierIdRegistry(listOf("a", "b"), listOf(FixedSource("b", "b-id", calls), FixedSource("a", null, calls), FixedSource("a", "a-id", calls)))
        assertEquals(ResolvedVerifierId("a", "a-id"), r.resolve(ctx))
        assertEquals(listOf("declined-a", "a-id"), calls)
        assertNull(VerifierIdRegistry(emptyList(), listOf(FixedSource("a", "x", mutableListOf()))).resolve(ctx))
        for (bad in listOf(listOf("a", "a"), listOf(" "), listOf(""), listOf(" a"), listOf("a,b"))) {
            org.junit.Assert.assertThrows(bad.toString(), IllegalArgumentException::class.java) { VerifierIdRegistry(bad) }
            org.junit.Assert.assertThrows(bad.toString(), IllegalArgumentException::class.java) { WalletConfig(backendUrl = "https://b.example", circuitZkVerifierIdTypes = bad) }
        }
    }

    @Test
    fun verifierIdRegistry_earlyCheck_neverAsksAHostSourceWithTheEmptyMatchTimeContext() = runTest(dispatcher) {
        val ctx = VerifierIdContext(
            org.siros.sdk.wallet.dcapi.DCAPIRequest(
                clientId = "c", responseMode = "direct_post.jwt", nonce = "", dcqlQuery = null, clientMetadata = null,
                keyMaterial = null, protocol = "openid4vp-redirect", state = null,
            ),
            TrustResult(trusted = true), "",
        )
        val calls = mutableListOf<String>()
        val custom = VerifierIdRegistry(listOf("a"), listOf(FixedSource("a", "a-id", calls)))
        assertEquals(VerifierIdRegistry.EarlyCheck.Skipped, custom.earlyCheck(ctx))
        assertEquals("a host source is not called at match time", emptyList<String>(), calls)
        // Without a host source the PDP answer alone decides, now.
        assertEquals(VerifierIdRegistry.EarlyCheck.Unresolvable, VerifierIdRegistry(listOf("a")).earlyCheck(ctx))
    }

    @Test
    fun circuitZkDcApi_cancelledTrustEvaluation_propagatesCancellation_notARefusal() = runTest(dispatcher) {
        val s = czkSetup(trust = { throw kotlinx.coroutines.CancellationException("cancelled") })
        org.junit.Assert.assertThrows(kotlinx.coroutines.CancellationException::class.java) { czkRun(s, czkRequest()) }
        assertEquals(0, s.prover.calls)
    }

    @Test
    fun trustResult_contextIsAbsentByDefault() {
        assertNull(TrustResult(trusted = true).context)
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
        // The user is told (coarsely) and the verifier's message is the same WalletException message as before.
        assertEquals(org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.NOT_TRUSTED, (thrown as org.siros.sdk.wallet.dcapi.DCAPIPresentationDeclined).reason)
        assertTrue(thrown!!.message!!.startsWith("Verifier 'https://untrusted-relying-party.example' is not trusted"))
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
        assertEquals(org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.NO_MATCHING_CREDENTIAL, (thrown as org.siros.sdk.wallet.dcapi.DCAPIPresentationDeclined).reason)
        assertEquals("No credential in the wallet matches the request", thrown.message)
    }

    private fun plainDcApiWallet(credential: StoredCredential?): SirosWallet {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        val keystore = mockk<KeystoreManager>()
        every { keystore.isUnlocked } returns false
        every { keystore.listKeys() } returns listOf(KeyInfo("test-kid", "ES256", 0L))
        coEvery { keystore.signVpToken(any(), any(), any(), any()) } returns "signed-vp-token"
        return newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "apiClient" to apiClient,
            "keystore" to keystore,
            "credentialStore" to FakeCredentialStore(listOfNotNull(credential).toMutableList()),
            "_presentationHistory" to mutableListOf<PresentationRecord>(),
        )
    }

    private fun declinedReason(block: suspend () -> Unit): org.siros.sdk.wallet.dcapi.DCAPIPresentationDeclined {
        val e = org.junit.Assert.assertThrows(org.siros.sdk.wallet.dcapi.DCAPIPresentationDeclined::class.java) { kotlinx.coroutines.runBlocking { block() } }
        // Still a WalletException: existing handlers (and the verifier's error_description) are unchanged.
        assertTrue(e is WalletException)
        return e
    }

    @Test
    fun handleDCAPIRequest_missingEncryptionKey_isDeclinedWithAUserReason() = runTest(dispatcher) {
        val wallet = plainDcApiWallet(StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw", metadata = CredentialMetadata(name = "X"), batchId = 1L, instanceId = 0))
        val e = declinedReason {
            wallet.handleDCAPIRequest(
                wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject { put("nonce", "n"); put("response_mode", "dc_api.jwt") }),
                origin = "https://relying-party.example",
            )
        }
        assertEquals(org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.UNSUPPORTED_REQUEST, e.reason)
        assertEquals("dc_api.jwt response_mode requires client_metadata.jwks with an encryption key", e.message)
    }

    @Test
    fun handleDCAPIRequest_noEligibleCopyLeft_isDeclinedWithAUserReason() = runTest(dispatcher) {
        // The credential's key is not in the keystore, so no copy is eligible.
        val wallet = plainDcApiWallet(StoredCredential(id = 1L, format = "dc+sd-jwt", raw = "raw", kid = "gone-kid", metadata = CredentialMetadata(name = "X"), batchId = 1L, instanceId = 0))
        val e = declinedReason {
            wallet.handleDCAPIRequest(
                wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject { put("nonce", "n") }),
                origin = "https://relying-party.example",
            )
        }
        assertEquals(org.siros.sdk.wallet.dcapi.DCAPIRefusalReason.SELECTED_CREDENTIAL_UNAVAILABLE, e.reason)
        assertEquals("No eligible copies of the requested credential remain - renew it to get more", e.message)
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

    // -- go-trust requires resource.id == subject.id on every full evaluation;
    // a mismatch is a 400 there and a 502 from the backend's authzen proxy.

    private fun issuerNamingFixtureCert(): java.security.cert.X509Certificate {
        val pem = checkNotNull(javaClass.getResourceAsStream("/mdoc-issuer-identity/uri_and_dns.pem"))
        return java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(pem)
            as java.security.cert.X509Certificate
    }

    private fun sha256HexOf(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    @Test
    fun evaluateIssuerTrust_issuerNamedSubject_resourceIdEqualsSubjectId() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val request = slot<JsonObject>()
        coEvery { apiClient.evaluateTrust(capture(request)) } returns buildJsonObject {
            put("decision", JsonPrimitive(true))
        }
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )
        val cert = issuerNamingFixtureCert()

        wallet.evaluateIssuerTrust(listOf(cert.encoded), docType = "org.iso.18013.5.1.mDL")

        val subject = request.captured["subject"]!!.jsonObject
        val resource = request.captured["resource"]!!.jsonObject
        assertEquals("https://issuer.example/tenant", subject["id"]?.jsonPrimitive?.content)
        assertEquals(subject["id"]?.jsonPrimitive?.content, resource["id"]?.jsonPrimitive?.content)
        // The key material still travels in resource.key.
        assertEquals("x5c", resource["type"]?.jsonPrimitive?.content)
        assertEquals(
            java.util.Base64.getEncoder().encodeToString(cert.encoded),
            resource["key"]?.jsonArray?.single()?.jsonPrimitive?.content,
        )
    }

    @Test
    fun evaluateIssuerTrust_certificateNamingNoUrl_usesCertificateHashForBoth() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val request = slot<JsonObject>()
        coEvery { apiClient.evaluateTrust(capture(request)) } returns buildJsonObject {
            put("decision", JsonPrimitive(false))
        }
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )
        val der = ByteArray(4) { it.toByte() } // not a certificate: names no URL

        wallet.evaluateIssuerTrust(listOf(der), docType = null)

        val expected = sha256HexOf(der)
        assertEquals(expected, request.captured["subject"]!!.jsonObject["id"]?.jsonPrimitive?.content)
        assertEquals(expected, request.captured["resource"]!!.jsonObject["id"]?.jsonPrimitive?.content)
    }

    @Test
    fun evaluateReaderTrust_defaultCertificateSubject_resourceIdEqualsSubjectId() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        val request = slot<JsonObject>()
        coEvery { apiClient.evaluateTrust(capture(request)) } returns buildJsonObject {
            put("decision", JsonPrimitive(true))
        }
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )
        val der = ByteArray(6) { (it + 1).toByte() }

        wallet.evaluateReaderTrust(listOf(der))

        val subjectId = request.captured["subject"]!!.jsonObject["id"]?.jsonPrimitive?.content
        assertEquals(sha256HexOf(der), subjectId)
        assertEquals(subjectId, request.captured["resource"]!!.jsonObject["id"]?.jsonPrimitive?.content)
        assertEquals("mdoc-reader-auth", request.captured["action"]!!.jsonObject["name"]?.jsonPrimitive?.content)
    }

    // -- Trust decision cache wiring: one cache across every evaluate call site.

    @Test
    fun trustDecisionCache_sameIssuerEvaluatedTwice_callsBackendOnce_andLogoutStyleClearReasks() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", JsonPrimitive(false)) }
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "trustDecisionCache" to TrustDecisionCache(java.time.Duration.ofMinutes(5), nowMillis = { System.nanoTime() / 1_000_000L }),
        )
        val cert = issuerNamingFixtureCert()

        assertTrue(!wallet.evaluateIssuerTrust(listOf(cert.encoded), "org.iso.18013.5.1.mDL").trusted)
        assertTrue(!wallet.evaluateIssuerTrust(listOf(cert.encoded), "org.iso.18013.5.1.mDL").trusted)
        coVerify(exactly = 1) { apiClient.evaluateTrust(any()) }

        // A different doc type is a different question; the reader action too.
        wallet.evaluateIssuerTrust(listOf(cert.encoded), "eu.europa.ec.eudi.pid.1")
        wallet.evaluateReaderTrust(listOf(cert.encoded))
        coVerify(exactly = 3) { apiClient.evaluateTrust(any()) }

        (getField(wallet, "trustDecisionCache") as TrustDecisionCache).clear()
        wallet.evaluateIssuerTrust(listOf(cert.encoded), "org.iso.18013.5.1.mDL")
        coVerify(exactly = 4) { apiClient.evaluateTrust(any()) }
    }

    @Test
    fun trustDecisionCache_decisionOfAnOldClientNeverAnswersTheNewClient() = runTest(dispatcher) {
        val oldClient = mockk<BackendApiClient>()
        val newClient = mockk<BackendApiClient>()
        coEvery { oldClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", JsonPrimitive(true)) }
        coEvery { newClient.evaluateTrust(any()) } returns buildJsonObject { put("decision", JsonPrimitive(false)) }
        val wallet = newWallet(
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "trustDecisionCache" to TrustDecisionCache(java.time.Duration.ofMinutes(5), nowMillis = { System.nanoTime() / 1_000_000L }),
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "evaluateTrustCached" }
        method.isAccessible = true
        val body = buildJsonObject { put("subject", buildJsonObject { put("id", JsonPrimitive("s")) }) }

        // Old client's call completes after a re-login (the cache was cleared in between).
        (getField(wallet, "trustDecisionCache") as TrustDecisionCache).clear()
        method.callSuspend(wallet, oldClient, body)
        val answer = method.callSuspend(wallet, newClient, body) as JsonObject

        assertEquals(JsonPrimitive(false), answer["decision"])
        coVerify(exactly = 1) { newClient.evaluateTrust(any()) }
    }

    @Test
    fun trustDecisionCache_errorsAreNotCachedByTheWallet() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws NetworkException("offline")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "trustDecisionCache" to TrustDecisionCache(java.time.Duration.ofMinutes(5), nowMillis = { System.nanoTime() / 1_000_000L }),
        )
        wallet.evaluateReaderTrust(listOf(ByteArray(4)))
        wallet.evaluateReaderTrust(listOf(ByteArray(4)))
        coVerify(exactly = 2) { apiClient.evaluateTrust(any()) }
    }

    // -- Fallback to local validation: genuine unreachability only.

    /** A wallet whose local VICAL root accepts [cert], so a fallback would say trusted=true. */
    private fun issuerWalletWithLocalRoot(apiClient: BackendApiClient, cert: java.security.cert.X509Certificate) =
        newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                issuerTrustRootCertificatesPem = listOf("unused"),
            ),
            "issuerTrustRootCertificates\$delegate" to lazy { listOf(cert) },
        )

    @Test
    fun evaluateIssuerTrust_fallbackOnlyForGenuineUnreachability() = runTest(dispatcher) {
        val cert = issuerNamingFixtureCert()
        // (exception, expect local fallback)
        val cases = listOf(
            NetworkException("timeout") to true,
            BackendApiException(502, "API request failed: 502", "") to true,
            BackendApiException(502, "API request failed: 502", "{}") to true,
            BackendApiException(503, "API request failed: 503", "<html>Service Unavailable</html>") to true,
            BackendApiException(504, "API request failed: 504", "upstream timed out") to true,
            BackendApiException(400, "API request failed: 400", """{"error":"bad request"}""") to false,
            BackendApiException(401, "API request failed: 401", "") to false,
            BackendApiException(403, "API request failed: 403", "") to false,
            BackendApiException(404, "API request failed: 404", "") to false,
            BackendApiException(500, "API request failed: 500", "") to false,
            BackendApiException(502, "API request failed: 502", """{"error":"resource.id must match subject.id"}""") to false,
            BackendApiException(503, "API request failed: 503", """{"error":"pdp refused"}""") to false,
            BackendApiException(0, "Missing field in response", "") to false,
        )
        for ((exception, expectFallback) in cases) {
            val apiClient = mockk<BackendApiClient>()
            coEvery { apiClient.evaluateTrust(any()) } throws exception
            val wallet = issuerWalletWithLocalRoot(apiClient, cert)

            val result = wallet.evaluateIssuerTrust(listOf(cert.encoded), docType = null)

            val label = "$exception (${(exception as? BackendApiException)?.code}) body=${(exception as? BackendApiException)?.body}"
            if (expectFallback) {
                assertEquals(label, "local-vical-root", result.framework)
                assertTrue(label, result.trusted)
            } else {
                assertEquals(label, "vical", result.framework)
                assertTrue(label, !result.trusted)
            }
        }
    }

    @Test
    fun evaluateIssuerTrust_remoteOnly_502WithoutBody_isNotTrusted() = runTest(dispatcher) {
        val cert = issuerNamingFixtureCert()
        val apiClient = mockk<BackendApiClient>()
        coEvery { apiClient.evaluateTrust(any()) } throws BackendApiException(502, "API request failed: 502", "")
        val wallet = newWallet(
            "apiClient" to apiClient,
            "config" to WalletConfig(
                backendUrl = "https://wallet.example.com",
                issuerTrustEvaluationMode = MdocTrustEvaluationMode.REMOTE_ONLY,
                issuerTrustRootCertificatesPem = listOf("unused"),
            ),
            "issuerTrustRootCertificates\$delegate" to lazy { listOf(cert) },
        )

        val result = wallet.evaluateIssuerTrust(listOf(cert.encoded), docType = null)

        assertTrue(!result.trusted)
        assertEquals("vical", result.framework)
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
        every { keystore.listKeys() } returns listOf(KeyInfo("instance-key-1", "ES256", 0L))
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

    // ---- Issuance start: visible state before any network work ----------

    private val engineGeneration = java.util.concurrent.atomic.AtomicInteger(0)

    private val startOffer = org.siros.sdk.credentials.CredentialOffer(
        credentialConfigurationId = "pid",
        credentialIssuerIdentifier = "https://issuer.invalid",
        credentialName = "Personal ID",
        issuerName = "Issuer",
    )

    private fun startingWallet(engine: WalletEngineSession, stateFlow: MutableStateFlow<WalletState>) = newWallet(
        "_state" to stateFlow,
        "engineSession" to engine,
        "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
    )

    /** Records every state the wallet publishes, in order, interleaved with [log] entries. */
    private fun CoroutineScope.recordStates(stateFlow: MutableStateFlow<WalletState>, log: MutableList<String>) =
        launch(Dispatchers.Unconfined) {
            stateFlow.collect { s ->
                log += when {
                    s is WalletState.FlowActive && s.isPending -> "state:${s.status}"
                    s is WalletState.FlowActive -> "state:flow:${s.flowId}:${s.flowType}:${s.status}"
                    else -> "state:${s::class.simpleName}"
                }
            }
        }

    @Test
    fun startIssuanceByOffer_emitsInitializing_beforeAnyNetworkWork_andStepsThroughTheStart() = runTest(dispatcher) {
        val log = mutableListOf<String>()
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val engine = mockk<WalletEngineSession>(relaxed = true)
        coEvery { engine.forceReconnect() } coAnswers { log += "net:forceReconnect" }
        coEvery { engine.awaitConnected(any()) } coAnswers { log += "net:awaitConnected" }
        every { engine.startIssuance(any(), any(), any(), any(), any(), any()) } answers { log += "net:startIssuance" }
        val wallet = startingWallet(engine, stateFlow)
        val recorder = recordStates(stateFlow, log)

        wallet.startIssuanceByOffer(startOffer)
        recorder.cancel()

        val steps = log.filter { it.startsWith("state:") || it.startsWith("net:") }
        assertEquals(
            listOf(
                "state:Ready",
                "state:initializing",
                "state:connecting_engine",
                "net:forceReconnect",
                "state:establishing_session",
                "net:awaitConnected",
                "state:checking_entitlement",
                "state:preparing_issuance",
                "state:starting_flow",
                "net:startIssuance",
            ),
            steps,
        )
        // Still the flow screen, not Ready, until the engine reports its first
        // progress step; a host must not drop back to the list in this window.
        val now = stateFlow.value as WalletState.FlowActive
        assertTrue(now.isPending)
        assertEquals("issuance", now.flowType)
    }

    @Test
    fun startIssuance_withOfferUri_emitsInitializing_beforeAnyNetworkWork() = runTest(dispatcher) {
        val log = mutableListOf<String>()
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val engine = mockk<WalletEngineSession>(relaxed = true)
        coEvery { engine.forceReconnect() } coAnswers { log += "net:forceReconnect" }
        val wallet = startingWallet(engine, stateFlow)
        val recorder = recordStates(stateFlow, log)

        wallet.startIssuance("""{"credential_issuer":"https://issuer.invalid","credential_configuration_ids":["pid"]}""")
        recorder.cancel()

        val steps = log.filter { it.startsWith("state:") || it.startsWith("net:") }
        assertEquals(listOf("state:Ready", "state:initializing", "state:connecting_engine", "net:forceReconnect"), steps.take(4))
        assertTrue(steps.contains("state:starting_flow"))
        assertFalse("no entitlement check on the offer-URI path", steps.contains("state:checking_entitlement"))
    }

    @Test
    fun startIssuanceByOffer_engineUnreachable_clearsPendingState_andThrows() = runTest(dispatcher) {
        val log = mutableListOf<String>()
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val engine = mockk<WalletEngineSession>(relaxed = true)
        coEvery { engine.awaitConnected(any()) } throws IllegalStateException("Engine WebSocket connection failed")
        val wallet = startingWallet(engine, stateFlow)
        val recorder = recordStates(stateFlow, log)

        val e = runCatching { wallet.startIssuanceByOffer(startOffer) }.exceptionOrNull()
        recorder.cancel()

        assertTrue("the failure must reach the caller, was $e", e is IllegalStateException)
        assertTrue("pending state was shown first: $log", "state:establishing_session" in log)
        // Never left on a spinner nothing will clear, and never a silent return
        // to a state the caller cannot tell from "nothing happened".
        assertTrue(stateFlow.value is WalletState.Ready)
        assertFalse(getField(wallet, "issuanceInFlight") as Boolean)
        verify(exactly = 0) { engine.startIssuance(any(), any(), any(), any(), any(), any()) }

        // And a retry is allowed.
        coEvery { engine.awaitConnected(any()) } returns Unit
        wallet.startIssuanceByOffer(startOffer)
        verify(exactly = 1) { engine.startIssuance(any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun startIssuanceByOffer_engineStartThrows_clearsPendingState() = runTest(dispatcher) {
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val engine = mockk<WalletEngineSession>(relaxed = true)
        every { engine.startIssuance(any(), any(), any(), any(), any(), any()) } throws IllegalStateException("not connected")
        val wallet = startingWallet(engine, stateFlow)

        val e = runCatching { wallet.startIssuanceByOffer(startOffer) }.exceptionOrNull()

        assertTrue(e is IllegalStateException)
        assertTrue(stateFlow.value is WalletState.Ready)
        assertFalse(getField(wallet, "issuanceInFlight") as Boolean)
    }

    @Test
    fun cancelDuringStart_resetsAtOnce_andTheSuspendedStartNeverReachesTheEngine() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val engine = mockk<WalletEngineSession>(relaxed = true)
        coEvery { engine.forceReconnect() } coAnswers { gate.await() }
        val wallet = startingWallet(engine, stateFlow)

        val job = launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
            runCatching { wallet.startIssuanceByOffer(startOffer) }
        }
        assertTrue("pending state is up while the engine connects", (stateFlow.value as WalletState.FlowActive).isPending)

        wallet.cancelCurrentFlow()

        assertTrue(stateFlow.value is WalletState.Ready)
        assertFalse(getField(wallet, "issuanceInFlight") as Boolean)
        // There is no engine flow to cancel yet - sending one would name a
        // flow id that does not exist.
        verify(exactly = 0) { engine.cancelFlow(any()) }

        gate.complete(Unit)
        job.join()

        verify(exactly = 0) { engine.startIssuance(any(), any(), any(), any(), any(), any()) }
        assertTrue("the cancelled start must not resurrect the flow", stateFlow.value is WalletState.Ready)
        assertFalse(getField(wallet, "issuanceInFlight") as Boolean)
    }

    @Test
    fun cancelledStart_doesNotClobberANewerStart() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val engine = mockk<WalletEngineSession>(relaxed = true)
        var first = true
        coEvery { engine.forceReconnect() } coAnswers { if (first) { first = false; gate.await() } }
        val wallet = startingWallet(engine, stateFlow)

        val job = launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
            runCatching { wallet.startIssuanceByOffer(startOffer) }
        }
        wallet.cancelCurrentFlow()
        wallet.startIssuanceByOffer(startOffer) // second attempt completes
        gate.complete(Unit)
        job.join() // first attempt unwinds as cancelled

        verify(exactly = 1) { engine.startIssuance(any(), any(), any(), any(), any(), any()) }
        assertTrue("the newer start's pending state survives", (stateFlow.value as WalletState.FlowActive).isPending)
        assertTrue("and so does its in-flight guard", getField(wallet, "issuanceInFlight") as Boolean)
    }

    @Test
    fun firstEngineProgress_replacesPendingState_andKeepsTheIssuanceFlowType() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        every { engine.startIssuance(any(), any(), any(), any(), any(), any()) } just runs
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val wallet = newWallet(
            "_state" to stateFlow,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", tenantId = "tenant-1"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to mockk<WalletEventListener>(relaxed = true),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()

        wallet.startIssuanceByOffer(startOffer)
        assertTrue((stateFlow.value as WalletState.FlowActive).isPending)
        progressFlow.emit(FlowProgressMessage(flowId = "flow-1", step = "parsing_offer").also { it.connectionGeneration = engineGeneration.get() })
        advanceUntilIdle()
        progressFlow.emit(FlowProgressMessage(flowId = "flow-1", step = "offer_parsed").also { it.connectionGeneration = engineGeneration.get() })
        advanceUntilIdle()

        val s = stateFlow.value as WalletState.FlowActive
        assertEquals("flow-1", s.flowId)
        assertFalse(s.isPending)
        assertEquals("issuance", s.flowType)
        assertEquals("offer_parsed", s.status)
    }

    @Test
    fun flowLost_aSentIssuanceStartWhoseConnectionIsReplacedBeforeItsFirstProgressIsRetired() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val generations = MutableStateFlow(0)
        val engine = mockEngineConstructor(progressFlow = progressFlow, generations = generations)
        every { engine.startIssuance(any(), any(), any(), any(), any(), any()) } just runs
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val listener = mockk<WalletEventListener>(relaxed = true)
        val wallet = newWallet(
            "_state" to stateFlow,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", tenantId = "tenant-1"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        wallet.startIssuanceByOffer(startOffer)
        assertTrue((stateFlow.value as WalletState.FlowActive).isPending)
        // The socket is replaced before any progress arrived.
        engineGeneration.incrementAndGet()
        generations.value = engineGeneration.get()
        advanceUntilIdle()
        assertTrue("no stranded spinner", stateFlow.value is WalletState.Ready)
        verify(exactly = 1) { listener.onFlowError(any(), SirosWallet.FLOW_LOST_MESSAGE, any()) }
        assertEquals("a new issuance can start", false, getField(wallet, "issuanceInFlight"))
    }

    @Test
    fun failureOfACancelledStart_unwindsAsCancellation_notAsTheNetworkError() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val engine = mockk<WalletEngineSession>(relaxed = true)
        // Fails only after the cancel, past every epoch check, so it is the
        // network error itself that has to be suppressed.
        coEvery { engine.awaitConnected(any()) } coAnswers {
            gate.await()
            throw IllegalStateException("Engine WebSocket connection failed")
        }
        coEvery { engine.forceReconnect() } just runs
        val wallet = startingWallet(engine, stateFlow)
        var result: Throwable? = null
        val job = launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
            result = runCatching { wallet.startIssuanceByOffer(startOffer) }.exceptionOrNull()
        }
        wallet.cancelCurrentFlow()
        gate.complete(Unit)
        job.join()

        assertTrue("a late failure after cancel must not surface as an error, was $result",
            result is kotlinx.coroutines.CancellationException)
        assertTrue(stateFlow.value is WalletState.Ready)
    }

    @Test
    fun cancelDuringMetadataFetch_doesNotPublishIntoSharedFields() = runTest(dispatcher) {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val vctmFetcher = mockk<org.siros.sdk.credentials.VctmFetcher>(relaxed = true)
        val reached = kotlinx.coroutines.CompletableDeferred<Unit>()
        coEvery { vctmFetcher.fetchDocument(any(), any(), any(), any(), any()) } coAnswers {
            reached.complete(Unit)
            gate.await()
            null
        }
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val wallet = newWallet(
            "_state" to stateFlow,
            "engineSession" to engine,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "vctmFetcher" to vctmFetcher,
        )
        val job = launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
            runCatching { wallet.startIssuanceByOffer(startOffer) }
        }
        // Wait until the start is parked inside the metadata fetch (after the
        // entitlement check, which runs on the IO dispatcher), then cancel.
        reached.await()
        wallet.cancelCurrentFlow()
        setField(wallet, "activeOffer", null)
        gate.complete(Unit)
        job.join()

        assertNull("cancelled start published its offer", getField(wallet, "activeOffer"))
        verify(exactly = 0) { engine.startIssuance(any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun cancelAfterFlowStartSent_cancelsTheFlowOnItsFirstEvent_andIgnoresIt() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val engine = mockEngineConstructor(progressFlow = progressFlow)
        every { engine.startIssuance(any(), any(), any(), any(), any(), any()) } just runs
        every { engine.cancelFlow(any()) } just runs
        val listener = mockk<WalletEventListener>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val wallet = newWallet(
            "_state" to stateFlow,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", tenantId = "tenant-1"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()

        wallet.startIssuanceByOffer(startOffer) // flow_start is out, no flow id yet
        wallet.cancelCurrentFlow()
        assertTrue(stateFlow.value is WalletState.Ready)

        progressFlow.emit(FlowProgressMessage(flowId = "flow-late", step = "parsing_offer").also { it.connectionGeneration = engineGeneration.get() })
        advanceUntilIdle()

        verify(exactly = 1) { engine.cancelFlow("flow-late") }
        assertTrue("the cancelled flow must not reopen: ${stateFlow.value}", stateFlow.value is WalletState.Ready)
    }

    private fun abandonedStartWallet(
        progressFlow: MutableSharedFlow<FlowProgressMessage>,
        flowErrors: MutableSharedFlow<FlowErrorMessage> = MutableSharedFlow(),
        listener: WalletEventListener,
        stateFlow: MutableStateFlow<WalletState>,
    ): Pair<SirosWallet, WalletEngineSession> {
        val engine = mockEngineConstructor(progressFlow = progressFlow, flowErrors = flowErrors)
        every { engine.startIssuance(any(), any(), any(), any(), any(), any()) } just runs
        every { engine.cancelFlow(any()) } just runs
        val wallet = newWallet(
            "_state" to stateFlow,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", tenantId = "tenant-1"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
        )
        invokeConnectEngine(wallet, "app-token")
        return wallet to engine
    }

    @Test
    fun cancelledStart_whoseFirstReplyIsAnError_doesNotResetState_orReachTheHost() = runTest(dispatcher) {
        val flowErrors = MutableSharedFlow<FlowErrorMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val (wallet, engine) = abandonedStartWallet(MutableSharedFlow(), flowErrors, listener, stateFlow)
        advanceUntilIdle()
        wallet.startIssuanceByOffer(startOffer)
        wallet.cancelCurrentFlow()

        flowErrors.emit(
            FlowErrorMessage(flowId = "flow-late", error = org.siros.sdk.transport.engine.FlowError(code = "x", message = "boom")).also { it.connectionGeneration = engineGeneration.get() }
        )
        advanceUntilIdle()

        verify(exactly = 1) { engine.cancelFlow("flow-late") }
        verify(exactly = 0) { listener.onFlowError(any(), any(), any()) }
    }

    @Test
    fun retryAfterACancelledStart_isNotMistakenForTheCancelledFlow() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val (wallet, engine) = abandonedStartWallet(progressFlow, listener = listener, stateFlow = stateFlow)
        advanceUntilIdle()
        wallet.startIssuanceByOffer(startOffer)
        wallet.cancelCurrentFlow()
        // The retry replaces the socket; the cancelled flow's reply can no longer arrive.
        wallet.startIssuanceByOffer(startOffer)

        progressFlow.emit(FlowProgressMessage(flowId = "flow-retry", step = "parsing_offer").also { it.connectionGeneration = engineGeneration.get() })
        advanceUntilIdle()

        verify(exactly = 0) { engine.cancelFlow(any()) }
        assertEquals("flow-retry", (stateFlow.value as WalletState.FlowActive).flowId)
    }

    @Test
    fun supersededStartResumingAfterReconnect_doesNotEraseALaterCancelledStartsMarker() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val (wallet, engine) = abandonedStartWallet(progressFlow, listener = listener, stateFlow = stateFlow)
        advanceUntilIdle()
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        var calls = 0
        coEvery { engine.forceReconnect() } coAnswers { if (calls++ == 0) gate.await() }

        val a = launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
            runCatching { wallet.startIssuanceByOffer(startOffer) }
        }
        wallet.cancelCurrentFlow()                      // A parked in forceReconnect, cancelled
        wallet.startIssuanceByOffer(startOffer)         // B sends its start...
        wallet.cancelCurrentFlow()                      // ...and is cancelled after send
        gate.complete(Unit)                             // A resumes: must not touch B's marker
        a.join()

        progressFlow.emit(FlowProgressMessage(flowId = "flow-b", step = "parsing_offer"))
        advanceUntilIdle()

        verify(exactly = 1) { engine.cancelFlow("flow-b") }
        assertTrue(stateFlow.value is WalletState.Ready)
    }

    @Test
    fun cancelledIssuanceMarker_isRetiredByAnyConnectionReplacement_notJustAnIssuanceRetry() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val (wallet, engine) = abandonedStartWallet(progressFlow, listener = listener, stateFlow = stateFlow)
        advanceUntilIdle()
        wallet.startIssuanceByOffer(startOffer)
        wallet.cancelCurrentFlow()

        // A presentation/renewal path reconnects through ensureEngineConnected.
        val method = wallet::class.declaredMemberFunctions.first { it.name == "ensureEngineConnected" }
        method.isAccessible = true
        method.callSuspend(wallet, engine)

        progressFlow.emit(FlowProgressMessage(flowId = "flow-presentation", step = "parsing_request").also { it.connectionGeneration = engineGeneration.get() })
        advanceUntilIdle()

        verify(exactly = 0) { engine.cancelFlow(any()) }
        assertEquals("flow-presentation", (stateFlow.value as WalletState.FlowActive).flowId)
    }

    @Test
    fun staleBufferedCompletion_afterARetry_isRecognisedAsTheCancelledStarts_andNotTheRetrys() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val completes = MutableSharedFlow<FlowCompleteMessage>()
        val engine = mockEngineConstructor(progressFlow = progressFlow, flowComplete = completes)
        every { engine.startIssuance(any(), any(), any(), any(), any(), any()) } just runs
        every { engine.cancelFlow(any()) } just runs
        val listener = mockk<WalletEventListener>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val wallet = newWallet(
            "_state" to stateFlow,
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", tenantId = "tenant-1"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        wallet.startIssuanceByOffer(startOffer)
        val oldGeneration = engineGeneration.get() // the connection the start was sent on
        wallet.cancelCurrentFlow()                 // cancelled after send, on that connection
        wallet.startIssuanceByOffer(startOffer)    // retry: new connection

        // The retry's own first event arrives first and must not be taken for the cancelled flow...
        progressFlow.emit(FlowProgressMessage(flowId = "flow-new", step = "parsing_offer").also { it.connectionGeneration = engineGeneration.get() })
        advanceUntilIdle()
        assertEquals("flow-new", (stateFlow.value as WalletState.FlowActive).flowId)
        verify(exactly = 0) { engine.cancelFlow("flow-new") }

        // ...and the buffered completion of the cancelled start, still tagged with
        // the old connection, is dropped instead of acting on the retry's state.
        completes.emit(FlowCompleteMessage(flowId = "flow-old").also { it.connectionGeneration = oldGeneration })
        advanceUntilIdle()
        verify(exactly = 1) { engine.cancelFlow("flow-old") }
        assertEquals("flow-new", (stateFlow.value as WalletState.FlowActive).flowId)
    }

    @Test
    fun reconnectBetweenSendAndCancel_stillMatchesTheConnectionTheStartWasSentOn() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val (wallet, engine) = abandonedStartWallet(progressFlow, listener = listener, stateFlow = stateFlow)
        advanceUntilIdle()
        wallet.startIssuanceByOffer(startOffer)
        val sentOn = engineGeneration.get()
        engineGeneration.incrementAndGet() // automatic reconnect before the user cancels
        wallet.cancelCurrentFlow()

        progressFlow.emit(FlowProgressMessage(flowId = "flow-late", step = "parsing_offer").also { it.connectionGeneration = sentOn })
        advanceUntilIdle()

        verify(exactly = 1) { engine.cancelFlow("flow-late") }
        assertTrue(stateFlow.value is WalletState.Ready)
    }

    @Test
    fun sessionReplacement_doesNotReuseAnAbandonedMarkerFromTheOldSession() = runTest(dispatcher) {
        val progress1 = MutableSharedFlow<FlowProgressMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val (wallet, engine1) = abandonedStartWallet(progress1, listener = listener, stateFlow = stateFlow)
        advanceUntilIdle()
        wallet.startIssuanceByOffer(startOffer)
        val generation = engineGeneration.get()
        wallet.cancelCurrentFlow()               // marker: session 1, generation g
        every { engine1.disconnect() } just runs

        // Logout/login: a brand new session whose generations restart at the same number.
        val progress2 = MutableSharedFlow<FlowProgressMessage>()
        val engine2 = mockEngineConstructor(progressFlow = progress2)
        every { engine2.startIssuance(any(), any(), any(), any(), any(), any()) } just runs
        every { engine2.cancelFlow(any()) } just runs
        engineGeneration.set(generation - 1) // so the new session's first connection is generation g again
        invokeConnectEngine(wallet, "app-token-2")
        advanceUntilIdle()
        wallet.startIssuanceByOffer(startOffer)
        assertEquals(generation, engineGeneration.get())

        progress2.emit(FlowProgressMessage(flowId = "flow-legit", step = "parsing_offer").also { it.connectionGeneration = generation })
        advanceUntilIdle()

        verify(exactly = 0) { engine2.cancelFlow(any()) }
        assertEquals("flow-legit", (stateFlow.value as WalletState.FlowActive).flowId)
    }

    @Test
    fun cancelFromASynchronousStateCollector_onStartingFlow_stopsTheStartBeforeItIsSent() = runTest(dispatcher) {
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val engine = mockk<WalletEngineSession>(relaxed = true)
        val wallet = startingWallet(engine, stateFlow)
        val collector = CoroutineScope(Dispatchers.Unconfined).launch {
            stateFlow.collect { s ->
                if (s is WalletState.FlowActive && s.status == WalletState.FlowActive.STEP_STARTING_FLOW) {
                    wallet.cancelCurrentFlow()
                }
            }
        }

        val e = runCatching { wallet.startIssuanceByOffer(startOffer) }.exceptionOrNull()
        collector.cancel()

        assertTrue("start must unwind as a cancellation, was $e", e is kotlinx.coroutines.CancellationException)
        verify(exactly = 0) { engine.startIssuance(any(), any(), any(), any(), any(), any()) }
        assertTrue(stateFlow.value is WalletState.Ready)
    }

    @Test
    fun cancellationErrorOfAnActiveFlow_doesNotClearAnImmediateRetry() = runTest(dispatcher) {
        val progressFlow = MutableSharedFlow<FlowProgressMessage>()
        val flowErrors = MutableSharedFlow<FlowErrorMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val (wallet, engine) = abandonedStartWallet(progressFlow, flowErrors, listener, stateFlow)
        advanceUntilIdle()
        wallet.startIssuanceByOffer(startOffer)
        progressFlow.emit(FlowProgressMessage(flowId = "flow-old", step = "parsing_offer").also { it.connectionGeneration = engineGeneration.get() })
        advanceUntilIdle()
        assertEquals("flow-old", (stateFlow.value as WalletState.FlowActive).flowId)

        wallet.cancelCurrentFlow()
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        coEvery { engine.forceReconnect() } coAnswers { gate.await() }
        val retry = launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
            runCatching { wallet.startIssuanceByOffer(startOffer) }
        }
        // The old flow's cancellation error arrives while the retry refreshes its token.
        flowErrors.emit(FlowErrorMessage(flowId = "flow-old", error = org.siros.sdk.transport.engine.FlowError(code = "cancelled", message = "cancelled")))
        advanceUntilIdle()

        verify(exactly = 0) { listener.onFlowError(any(), any(), any()) }
        assertTrue("retry keeps its pending state", (stateFlow.value as WalletState.FlowActive).isPending)
        assertTrue("and its in-flight guard", getField(wallet, "issuanceInFlight") as Boolean)
        gate.complete(Unit)
        retry.join()
    }

    @Test
    fun cancelledStart_whoseFirstReplyIsAnErrorWithoutAFlowId_isIgnored() = runTest(dispatcher) {
        val flowErrors = MutableSharedFlow<FlowErrorMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val stateFlow = MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice"))
        val (wallet, engine) = abandonedStartWallet(MutableSharedFlow(), flowErrors, listener, stateFlow)
        advanceUntilIdle()
        wallet.startIssuanceByOffer(startOffer)
        wallet.cancelCurrentFlow()
        wallet.startIssuanceByOffer(startOffer) // immediate retry; its reconnect has not replaced the socket yet in the old reply's view
        val sentOn = engineGeneration.get() - 1  // the cancelled start's connection

        flowErrors.emit(
            FlowErrorMessage(flowId = null, error = org.siros.sdk.transport.engine.FlowError(code = "x", message = "boom"))
                .also { it.connectionGeneration = sentOn }
        )
        advanceUntilIdle()

        verify(exactly = 0) { listener.onFlowError(any(), any(), any()) }
        verify(exactly = 0) { engine.cancelFlow(any()) }
        assertTrue("retry keeps its pending state", (stateFlow.value as WalletState.FlowActive).isPending)
        assertTrue(getField(wallet, "issuanceInFlight") as Boolean)
    }

    private fun newWallet(vararg fields: Pair<String, Any?>): SirosWallet {
        val wallet = allocateInstance(SirosWallet::class.java) as SirosWallet
        val values = fields.toMap(mutableMapOf())
        val stateFlow = values["_state"] as? MutableStateFlow<WalletState>
        if (stateFlow != null && "state" !in values) {
            values["state"] = stateFlow.asStateFlow()
        }
        if ("holderCommitmentsByFlow" !in values) {
            values["holderCommitmentsByFlow"] = java.util.concurrent.ConcurrentHashMap<String, List<org.siros.sdk.credentials.HolderCommitment>>()
        }
        // allocateInstance skips this initializer too; the lost-flow sweeps ask whether a browser authorization is parked.
        if ("pendingAuthorizations" !in values) {
            values["pendingAuthorizations"] = mutableMapOf<String, Any>()
        }
        if ("pscIssuerByFlow" !in values) {
            values["pscIssuerByFlow"] = java.util.concurrent.ConcurrentHashMap<String, String>()
        }
        if ("terminatedFlowIds" !in values) {
            values["terminatedFlowIds"] = mutableSetOf<String>()
        }
        // allocateInstance skips the initializer of the response-key holder too; flow ends and cancels clear it.
        if ("blindIssuance" !in values) {
            values["blindIssuance"] = BlindIssuance()
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
        // Disabled by default so cache behaviour never leaks into other tests.
        if ("zkSigningMutex" !in values) {
            values["zkSigningMutex"] = kotlinx.coroutines.sync.Mutex()
        }
        if ("zkSignJobsByFlow" !in values) {
            values["zkSignJobsByFlow"] = java.util.concurrent.ConcurrentHashMap<String, Any>()
        }
        if ("flowConnectionGeneration" !in values) {
            values["flowConnectionGeneration"] = java.util.concurrent.ConcurrentHashMap<String, Int>()
        }
        if ("lostFlowIds" !in values) {
            values["lostFlowIds"] = java.util.Collections.newSetFromMap(java.util.concurrent.ConcurrentHashMap<String, Boolean>())
        }
        if ("selectionJobsByFlow" !in values) {
            values["selectionJobsByFlow"] = java.util.concurrent.ConcurrentHashMap<String, kotlinx.coroutines.Job>()
        }
        if ("lastTrustResults" !in values) {
            values["lastTrustResults"] = mutableMapOf<String, TrustResult>()
        }
        if ("circuitZkClientMetadataByFlow" !in values) {
            values["circuitZkClientMetadataByFlow"] = mutableMapOf<String, JsonObject>()
        }
        if ("trustDecisionCache" !in values) {
            values["trustDecisionCache"] = TrustDecisionCache(java.time.Duration.ZERO)
        }
        if ("zkPreparationsByFlow" !in values) {
            values["zkPreparationsByFlow"] =
                java.util.concurrent.ConcurrentHashMap<String, org.siros.sdk.credentials.ZkIssuancePreparation>()
        }
        // Same allocateInstance reason: the start-attempt counter's initializer
        // never runs, and every issuance start and cancel touches it.
        // readyState() (cancel/failure of a pending issuance start) reads the account list.
        if ("accountRegistry" !in values) {
            val registry = mockk<AccountRegistry>(relaxed = true)
            every { registry.listAccounts() } returns emptyList()
            values["accountRegistry"] = registry
        }
        if ("abandonedStarts" !in values) {
            values["abandonedStarts"] = java.util.concurrent.CopyOnWriteArrayList<Any>()
        }
        if ("abandonedFlowIds" !in values) {
            values["abandonedFlowIds"] = java.util.Collections.newSetFromMap(
                java.util.concurrent.ConcurrentHashMap<String, Boolean>()
            )
        }
        if ("issuanceStartEpoch" !in values) {
            values["issuanceStartEpoch"] = java.util.concurrent.atomic.AtomicInteger(0)
        }
        if ("credentialConsumptionPolicy" !in values) {
            values["credentialConsumptionPolicy"] = CredentialConsumptionPolicy.NEVER_CONSUME
        }
        // allocateInstance bypasses property initializers entirely, so
        // zkPresentation's default (ZkMdocPresentation.standard(...)) never
        // runs unless set here explicitly - without this, any call site that
        // reads zkSystemIds (matchDcql/match, since this fix threads the
        // wallet's registered ZK systems into the shared DCQL matcher) NPEs
        // on the null backing field. An empty registry matches every
        // existing test's expectation of "no ZK systems registered" unless a
        // test explicitly overrides it.
        if ("zkPresentation" !in values) {
            values["zkPresentation"] = org.siros.sdk.keystore.ZkMdocPresentation(
                org.siros.sdk.credentials.ZkProofSystemRegistry(emptyList())
            )
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

    /** What the wallet's advertisement record holds: the legacy adapter for the one configuration, or nothing. */
    private fun advertisedSelections(advertised: Boolean): java.util.concurrent.ConcurrentHashMap<Pair<String, String>, org.siros.sdk.credentials.AuxiliarySelection.Selected> =
        java.util.concurrent.ConcurrentHashMap<Pair<String, String>, org.siros.sdk.credentials.AuxiliarySelection.Selected>().also {
            if (advertised) it["https://issuer.example" to "nym"] = org.siros.sdk.credentials.AuxiliarySelection.Selected(
                org.siros.sdk.credentials.LegacyOrgSirosShape,
                org.siros.sdk.credentials.AuxiliaryAdvertisement(
                    listOf(org.siros.sdk.credentials.AuxiliaryAdvertisement.Slot(listOf("org.siros.nym_auth"), "sha-256")), emptyList(),
                ),
            )
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

    private fun invokeHandleWmpTrustEvaluation(
        wallet: SirosWallet,
        flowId: String,
        payload: JsonObject?,
    ): org.siros.sdk.transport.wmp.openid4x.TrustResult {
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpTrustEvaluation" }
        method.isAccessible = true
        return kotlinx.coroutines.runBlocking {
            method.callSuspend(wallet, flowId, payload) as org.siros.sdk.transport.wmp.openid4x.TrustResult
        }
    }

    private fun invokeCurrentWalletInstanceId(wallet: SirosWallet): String? {
        val method = wallet::class.declaredMemberFunctions.first { it.name == "currentWalletInstanceId" }
        method.isAccessible = true
        return method.call(wallet) as String?
    }

    // ── transaction_data (EC TS12) refusal and declaration ──────────

    private val tdEntry = org.siros.sdk.transport.wmp.openid4x.TransactionData(
        type = "urn:eudi:sca:payment:1",
        raw = "eyJ0eXBlIjoidXJuOmV1ZGk6c2NhOnBheW1lbnQ6MSJ9",
        credentialIds = listOf("pay"),
    )

    private fun unwrapped(t: Throwable): Throwable =
        if (t is java.lang.reflect.InvocationTargetException && t.cause != null) t.cause!! else t

    /**
     * A legacy-transport sign_presentation carrying transaction_data must be
     * refused before anything is signed: answering without the hashes would
     * authorise a payment the user never saw.
     */
    @Test
    fun legacySignPresentation_withTransactionData_isRefusedAndNothingIsSigned() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every {
            engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } just runs
        val keystore = mockk<KeystoreManager>(relaxed = true)
        val listener = mockk<WalletEventListener>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to keystore,
            "eventListener" to listener,
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "customTransactionLogStore" to InMemoryTransactionLog(),
            "transactionMetadataSourceOverride" to org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource(),
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
            "apiClient" to mockk<BackendApiClient>(relaxed = true),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()

        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-td",
                messageId = "msg-td",
                action = "sign_presentation",
                params = SignRequestParams(audience = "https://verifier.example.com", nonce = "n", transactionData = listOf(tdEntry)),
            )
        )
        repeat(5) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            advanceUntilIdle()
        }

        coVerify(exactly = 0) { keystore.signPresentation(any(), any(), any()) }
        coVerify(exactly = 0) { keystore.signVpToken(any(), any(), any(), any(), any()) }
        verify(exactly = 0) {
            engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        }
        verify(exactly = 1) {
            listener.onFlowError("flow-td", match { it.contains("refused: disabled") }, any())
        }
    }

    /** The same request without transaction_data is answered exactly as before. */
    @Test
    fun legacySignPresentation_withoutTransactionData_isUnchanged() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every {
            engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } just runs
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signPresentation(any(), any(), any()) } returns "vp-token"
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to keystore,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
            "apiClient" to mockk<BackendApiClient>(relaxed = true),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()

        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-plain",
                messageId = "msg-plain",
                action = "sign_presentation",
                params = SignRequestParams(audience = "https://verifier.example.com", nonce = "n"),
            )
        )
        repeat(5) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            advanceUntilIdle()
        }

        coVerify(exactly = 1) { keystore.signPresentation("n", "https://verifier.example.com", emptyList()) }
        verify(exactly = 1) {
            engine.sendSignResponse(
                flowId = "flow-plain", vpToken = "vp-token", messageId = "msg-plain",
            )
        }
    }

    /** WMP sign sub-flow: refused with the typed error, before anything is signed. */
    @Test
    fun wmpSignPresentation_withTransactionData_isRefusedAndNothingIsSigned() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to keystore,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "customTransactionLogStore" to InMemoryTransactionLog(),
            "transactionMetadataSourceOverride" to org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource(),
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        val params = org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
            action = "sign_presentation", nonce = "n", audience = "https://verifier.example.com",
            transactionData = listOf(tdEntry), responseMode = "direct_post",
        )

        val thrown = runCatching { runBlocking { method.callSuspend(wallet, "flow-w", params) } }.exceptionOrNull()

        val error = unwrapped(thrown ?: throw AssertionError("expected a refusal")) as org.siros.sdk.credentials.TransactionDataError
        assertEquals(org.siros.sdk.credentials.TransactionDataReason.DISABLED, error.reason)
        coVerify(exactly = 0) { keystore.signPresentation(any(), any(), any()) }
    }

    /** WMP sign sub-flow without transaction_data is signed as before. */
    @Test
    fun wmpSignPresentation_withoutTransactionData_isUnchanged() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signPresentation(any(), any(), any()) } returns "vp-token"
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to keystore,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        val params = org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
            action = "sign_presentation", nonce = "n", audience = "https://verifier.example.com",
        )

        val result = runBlocking { method.callSuspend(wallet, "flow-w", params) }
            as org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult

        assertEquals("vp-token", result.vpToken)
    }

    /** The DC API has no negotiation, so it must refuse transaction_data itself, before trust evaluation. */
    @Test
    fun dcApiRequest_withTransactionData_isRefusedBeforeAnyTrustEvaluation() = runTest(dispatcher) {
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "apiClient" to apiClient,
            "customTransactionLogStore" to InMemoryTransactionLog(),
            "transactionMetadataSourceOverride" to org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource(),
        )
        val raw = """{"requests":[{"protocol":"openid4vp-v1-unsigned","data":{
            "nonce":"n","dcql_query":{"credentials":[]},"transaction_data":["eyJ0eXBlIjoieCJ9"]}}]}"""

        val error = runCatching { runBlocking { wallet.handleDCAPIRequest(raw, "https://verifier.example.com") } }
            .exceptionOrNull()

        val refusal = error as? org.siros.sdk.credentials.TransactionDataError
            ?: throw AssertionError("expected TransactionDataError, got $error")
        assertEquals(org.siros.sdk.credentials.TransactionDataReason.DISABLED, refusal.reason)
        assertEquals("invalid_transaction_data", refusal.verifierError)
        coVerify(exactly = 0) { apiClient.evaluateTrust(any()) }
    }

    /** Effective enablement is flag AND handler; initial flag from the config. */
    @Test
    fun transactionData_effectiveEnablement_needsFlagAndHandler() {
        val wallet = newWallet(
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", transactionDataEnabled = true),
        )
        val handler = TransactionConsentHandler { true }

        assertFalse(wallet.isTransactionDataEffectivelyEnabled)
        wallet.transactionDataEnabled = true
        assertFalse("flag without a handler", wallet.isTransactionDataEffectivelyEnabled)
        wallet.transactionConsentHandler = handler
        assertTrue(wallet.isTransactionDataEffectivelyEnabled)
        wallet.transactionDataEnabled = false
        assertFalse("handler without the flag", wallet.isTransactionDataEffectivelyEnabled)
    }

    @Test
    fun transactionDataConfigDefaultIsOff() {
        assertFalse(WalletConfig(backendUrl = "https://wallet.example.com").transactionDataEnabled)
    }

    /** startPresentation declares the feature only when effectively enabled, read at each start. */
    @Test
    fun startPresentation_declaresFeatureOnlyWhenEffectivelyEnabled() = runTest(dispatcher) {
        val engine = mockk<WalletEngineSession>(relaxed = true)
        every { engine.state } returns MutableStateFlow(WalletEngineSession.State.CONNECTED)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "engineSession" to engine,
        )
        wallet.startPresentation("https://verifier.example.com/r1")
        wallet.transactionDataEnabled = true
        wallet.transactionConsentHandler = TransactionConsentHandler { true }
        wallet.startPresentation("https://verifier.example.com/r2")
        wallet.transactionDataEnabled = false
        wallet.startPresentation("https://verifier.example.com/r3")

        verify(exactly = 1) { engine.startPresentation("https://verifier.example.com/r1", null, null) }
        verify(exactly = 1) {
            engine.startPresentation("https://verifier.example.com/r2", null, listOf("transaction_data.v1"))
        }
        verify(exactly = 1) { engine.startPresentation("https://verifier.example.com/r3", null, null) }
    }

    // ── transaction_data (EC TS12) end to end, per transport ────────

    private class ScaFixture(
        val wallet: SirosWallet,
        val log: InMemoryTransactionLog,
        val keystore: org.siros.sdk.keystore.WscdKeystoreAdapter,
        val signer: ScaTestSigner,
        val consent: MutableList<TransactionConsentRequest>,
    )

    private val scaFactors = listOf(
        org.siros.sdk.keystore.AuthenticationFactor(org.siros.sdk.keystore.AuthenticationCategory.KNOWLEDGE, "pin_6_or_more_digits"),
        org.siros.sdk.keystore.AuthenticationFactor(org.siros.sdk.keystore.AuthenticationCategory.POSSESSION, "key_in_remote_wscd"),
    )

    /** A wallet holding one SD-JWT VC SCA attestation bound to a real software key. */
    private fun scaFixture(
        enabled: Boolean = true,
        answer: Boolean = true,
        /** What the signer's SCA sign applies; null models a signer that cannot reach two categories. */
        factors: List<org.siros.sdk.keystore.AuthenticationFactor>? = scaFactors,
        declaredEngine: Boolean = enabled,
        declaredWmp: Boolean = enabled,
        extra: Array<Pair<String, Any?>> = emptyArray(),
        userCancelsAuthentication: Boolean = false,
        keystoreWrapper: ((org.siros.sdk.keystore.WscdKeystoreAdapter) -> KeystoreManager)? = null,
    ): ScaFixture {
        val signer = ScaTestSigner(factors, userCancelsAuthentication)
        val keystore = org.siros.sdk.keystore.WscdKeystoreAdapter(signer)
        runBlocking { keystore.unlock(ByteArray(0), ByteArray(0), ByteArray(0), ByteArray(0)) }
        val kid = runBlocking { keystore.generateKey() }
        val cred = StoredCredential(
            id = 1L, format = "dc+sd-jwt",
            raw = org.siros.sdk.wallet.transaction.TransactionTestFixtures.credential().raw, kid = kid,
            metadata = CredentialMetadata(name = "Pay Card"), batchId = 1L, instanceId = 0,
        )
        val log = InMemoryTransactionLog()
        val consent = mutableListOf<TransactionConsentRequest>()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to (keystoreWrapper?.invoke(keystore) ?: keystore),
            "credentialStore" to FakeCredentialStore(mutableListOf(cred)),
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "customTransactionLogStore" to log,
            "transactionMetadataSourceOverride" to org.siros.sdk.wallet.transaction.TransactionTestFixtures.FakeSource(
                org.siros.sdk.wallet.transaction.TransactionTestFixtures.metadata(types = org.siros.sdk.wallet.transaction.TransactionTestFixtures.PAYMENT_TYPES),
            ),
            "engineFlowDeclaredTransactionData" to declaredEngine,
            "wmpSessionDeclaredTransactionData" to declaredWmp,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com", redirectUri = "siros-sample://callback"),
            "json" to Json { ignoreUnknownKeys = true },
            "httpClient" to OkHttpClient(),
            "apiClient" to mockk<BackendApiClient>(relaxed = true),
            *extra,
        )
        wallet.transactionDataEnabled = enabled
        wallet.transactionConsentHandler = TransactionConsentHandler { consent += it; answer }
        return ScaFixture(wallet, log, keystore, signer, consent)
    }

    private val scaRaw = org.siros.sdk.wallet.transaction.TransactionTestFixtures.raw(algs = """["sha-384"]""")

    private fun scaWire() = org.siros.sdk.transport.wmp.openid4x.TransactionData(
        type = "urn:eudi:sca:payment:1", raw = scaRaw, credentialIds = listOf("pay"),
        payload = Json.parseToJsonElement(org.siros.sdk.wallet.transaction.TransactionTestFixtures.PAYMENT_PAYLOAD),
        transactionDataHashesAlg = listOf("sha-384"),
    )

    /** The checks a verifier makes of an SCA KB-JWT, computed here independently of the wallet. */
    private fun assertScaKbJwt(vpToken: String, audience: String, nonce: String, responseMode: String) {
        val kb = SignedJWT.parse(vpToken.split("~").last())
        assertTrue(kb.verify(com.nimbusds.jose.crypto.ECDSAVerifier(kb.header.jwk.toECKey())))
        val c = kb.jwtClaimsSet.claims
        assertEquals("sha-384", c["transaction_data_hashes_alg"])
        assertEquals(
            listOf(
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                    java.security.MessageDigest.getInstance("SHA-384").digest(scaRaw.toByteArray(Charsets.US_ASCII)),
                ),
            ),
            c["transaction_data_hashes"],
        )
        assertEquals(responseMode, c["response_mode"])
        assertTrue((c["jti"] as String).isNotEmpty())
        assertEquals(nonce, c["nonce"])
        assertEquals(listOf(audience), kb.jwtClaimsSet.audience)
        val amr = c["amr"] as List<*>
        assertEquals(2, amr.map { (it as Map<*, *>).keys.single() }.toSet().size)
    }

    private suspend fun sendEngineSignRequest(
        fx: ScaFixture,
        transactionData: List<org.siros.sdk.transport.wmp.openid4x.TransactionData>? = listOf(scaWire()),
    ): Pair<MutableList<String?>, WalletEngineSession> {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        val sent = mutableListOf<String?>()
        every {
            engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
        } answers { sent += args[2] as String? }
        invokeConnectEngine(fx.wallet, "app-token")
        dispatcher.scheduler.advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sca", messageId = "m1", action = "sign_presentation",
                params = SignRequestParams(
                    audience = "x509_san_dns:shop.example.com", nonce = "n-1", responseMode = "direct_post.jwt",
                    credentialsToInclude = listOf(org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pay", credentialId = "1")),
                    transactionData = transactionData,
                ),
            )
        )
        repeat(8) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            dispatcher.scheduler.advanceUntilIdle()
        }
        return sent to engine
    }

    @Test
    fun scaEngine_requestIn_kbJwtOut_andLogged() = runTest(dispatcher) {
        val fx = scaFixture()

        val (sent, _) = sendEngineSignRequest(fx)

        assertEquals(1, sent.size)
        assertScaKbJwt(sent.single()!!, "x509_san_dns:shop.example.com", "n-1", "direct_post.jwt")
        assertEquals(1, fx.consent.size)
        assertEquals("Payee", fx.consent.single().entries.single().fields.first().label)
        assertEquals(TransactionOutcome.CONSENTED, fx.log.items.single().outcome)
    }

    @Test
    fun scaEngine_declined_signsNothing_andTheAppIsToldWhy() = runTest(dispatcher) {
        val listener = mockk<WalletEventListener>(relaxed = true)
        val fx = scaFixture(answer = false, extra = arrayOf("eventListener" to listener))

        val (sent, _) = sendEngineSignRequest(fx)

        assertTrue(sent.isEmpty())
        assertEquals(TransactionOutcome.DECLINED, fx.log.items.single().outcome)
        verify(exactly = 1) { listener.onTransactionDataRefused("flow-sca", org.siros.sdk.credentials.TransactionDataReason.DECLINED) }
    }

    @Test
    fun scaEngine_cancellingTheAuthenticationAfterConsent_isLoggedAsDeclined_notRefused() = runTest(dispatcher) {
        val fx = scaFixture(userCancelsAuthentication = true)

        val (sent, _) = sendEngineSignRequest(fx)

        assertTrue(sent.isEmpty())
        // signing and the log write finish on other dispatchers: keep the test scheduler running while waiting
        val deadline = System.currentTimeMillis() + 5_000
        while (fx.log.items.size < 2 && System.currentTimeMillis() < deadline) {
            dispatcher.scheduler.runCurrent()
            Thread.sleep(20)
        }
        assertEquals(listOf(TransactionOutcome.DECLINED, TransactionOutcome.CONSENTED), fx.log.items.map { it.outcome })
        assertEquals("declined", fx.log.items.first().reason)
    }

    @Test
    fun scaEngine_insufficientFactors_signsNothing() = runTest(dispatcher) {
        val fx = scaFixture(factors = null)

        val (sent, _) = sendEngineSignRequest(fx)

        assertTrue(sent.isEmpty())
        assertEquals("insufficientAuthenticationFactors", fx.log.items.single().reason)
    }

    @Test
    fun scaEngine_orchestratorWithoutRaw_isRefusedAndLogged() = runTest(dispatcher) {
        val fx = scaFixture()

        val (sent, _) = sendEngineSignRequest(fx, listOf(scaWire().copy(raw = null)))

        assertTrue(sent.isEmpty())
        assertEquals(TransactionOutcome.REFUSED, fx.log.items.single().outcome)
        assertEquals("invalidEntry", fx.log.items.single().reason)
    }

    @Test
    fun scaEngine_hintThatDisagreesWithRaw_isRefused() = runTest(dispatcher) {
        val fx = scaFixture()
        val lying = scaWire().copy(payload = Json.parseToJsonElement(org.siros.sdk.wallet.transaction.TransactionTestFixtures.PAYMENT_PAYLOAD.replace("49.99", "1.00")))

        val (sent, _) = sendEngineSignRequest(fx, listOf(lying))

        assertTrue(sent.isEmpty())
        assertTrue(fx.consent.isEmpty())
        assertEquals("inconsistentWithOrchestrator", fx.log.items.single().reason)
    }

    @Test
    fun scaEngine_flagOffAtFlowStart_refusesEvenIfEnabledLater() = runTest(dispatcher) {
        // The flow started disabled; flipping the flag afterwards applies to the NEXT flow only.
        val fx = scaFixture(enabled = false, declaredEngine = false)
        fx.wallet.transactionDataEnabled = true
        fx.wallet.transactionConsentHandler = TransactionConsentHandler { true }

        val (sent, _) = sendEngineSignRequest(fx)

        assertTrue(sent.isEmpty())
        assertEquals("disabled", fx.log.items.single().reason)
    }

    @Test
    fun scaEngine_flagTurnedOffMidFlow_stillCompletesUnderTheStartingSetting() = runTest(dispatcher) {
        val fx = scaFixture(declaredEngine = true)
        fx.wallet.transactionDataEnabled = false

        val (sent, _) = sendEngineSignRequest(fx)

        assertEquals(1, sent.size)
        assertScaKbJwt(sent.single()!!, "x509_san_dns:shop.example.com", "n-1", "direct_post.jwt")
    }

    @Test
    fun scaEngine_nonScaCredentialInTheSameRequestIsPresentedWithoutTransactionData() = runTest(dispatcher) {
        val fx = scaFixture()
        // the second credential answers a query no entry names
        val plain = StoredCredential(
            id = 2L, format = "dc+sd-jwt", raw = org.siros.sdk.wallet.transaction.TransactionTestFixtures.credential(2).raw,
            kid = runBlocking { fx.keystore.generateKey() }, metadata = CredentialMetadata(name = "Age"), batchId = 2L, instanceId = 0,
        )
        setField(fx.wallet, "credentialStore", FakeCredentialStore(mutableListOf(
            runBlocking { (getField(fx.wallet, "credentialStore") as FakeCredentialStore).getAll().first() }, plain,
        )))
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        val sent = mutableListOf<String?>()
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } answers { sent += args[2] as String? }
        invokeConnectEngine(fx.wallet, "app-token")
        dispatcher.scheduler.advanceUntilIdle()

        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-2", messageId = "m2", action = "sign_presentation",
                params = SignRequestParams(
                    audience = "aud", nonce = "n", responseMode = "direct_post",
                    credentialsToInclude = listOf(
                        org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pay", credentialId = "1"),
                        org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "age", credentialId = "2"),
                    ),
                    transactionData = listOf(scaWire()),
                ),
            )
        )
        repeat(8) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            dispatcher.scheduler.advanceUntilIdle()
        }

        val parts = sent.single()!!.split("\n")
        assertEquals(2, parts.size)
        val sca = SignedJWT.parse(parts[0].split("~").last()).jwtClaimsSet.claims
        val plainClaims = SignedJWT.parse(parts[1].split("~").last()).jwtClaimsSet.claims
        assertTrue(sca.containsKey("transaction_data_hashes"))
        assertEquals(setOf("aud", "iat", "nonce", "sd_hash"), plainClaims.keys)
    }

    @Test
    fun wmpGenerateProof_withHolderCommitments_everyProofCarriesTheClaimForTheExactIssuer() = runTest(dispatcher) {
        val asked = mutableListOf<Pair<String, String>>()
        val keystore = pscKeystore(asked)
        val captured = mutableListOf<Map<String, String>>()
        coEvery { keystore.generateProof(any(), any(), any(), any(), capture(captured)) } returns "proof-jwt"
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "keystore" to keystore,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )
        val result = invokeWmpSign(
            wallet,
            org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
                action = "generate_proof", nonce = "n", audience = "https://issuer.example/", count = 2,
                holderCommitments = listOf("psc"), credentialType = "t", credentialIssuer = "https://issuer.example/",
            ),
        )
        assertEquals(2, result.proofs?.size)
        assertEquals(2, captured.size)
        assertTrue(captured.all { it == mapOf("org.siros.psc" to pscClaimFor("t", "https://issuer.example/")) })
        assertEquals(listOf("t" to "https://issuer.example/"), asked)
    }

    @Test
    fun wmpGenerateProof_withHolderCommitments_refusesAnAttestationOnlyRequestWithoutSigning() = runTest(dispatcher) {
        val keystore = pscKeystore(mutableListOf())
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "u", displayName = "A")),
            "keystore" to keystore,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )
        val e = runCatching {
            invokeWmpSign(
                wallet,
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
                    action = "generate_proof", nonce = "n", audience = "aud", proofType = "attestation",
                    holderCommitments = listOf("psc"), credentialType = "t", credentialIssuer = "https://issuer.example",
                ),
            )
        }.exceptionOrNull()
        assertTrue(e is org.siros.sdk.credentials.WalletException)
        coVerify(exactly = 0) { keystore.generateProof(any(), any(), any(), any(), any()) }
        coVerify(exactly = 0) { keystore.generateKeyAttestation(any(), any()) }
    }

    // WMP

    private fun invokeWmpSign(wallet: SirosWallet, params: org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams): org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult {
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        return runBlocking {
            try {
                method.callSuspend(wallet, "flow-wmp", params)
            } catch (e: java.lang.reflect.InvocationTargetException) {
                throw e.cause ?: e
            }
        } as org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult
    }

    private fun wmpParams() = org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
        action = "sign_presentation", nonce = "n-2", audience = "x509_san_dns:shop.example.com",
        responseMode = "direct_post", transactionData = listOf(scaWire()),
        credentialsToInclude = listOf(org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pay", credentialId = "1")),
    )

    @Test
    fun scaWmp_requestIn_kbJwtOut_andLogged() = runTest(dispatcher) {
        val fx = scaFixture()

        val result = invokeWmpSign(fx.wallet, wmpParams())

        assertScaKbJwt(result.vpToken!!, "x509_san_dns:shop.example.com", "n-2", "direct_post")
        assertEquals(TransactionOutcome.CONSENTED, fx.log.items.single().outcome)
    }

    @Test
    fun scaWmp_sessionDeclaredOff_refuses_untilANewSession() = runTest(dispatcher) {
        val fx = scaFixture(enabled = true, declaredWmp = false)

        val e = runCatching { invokeWmpSign(fx.wallet, wmpParams()) }.exceptionOrNull() as TransactionDataError

        assertEquals(org.siros.sdk.credentials.TransactionDataReason.DISABLED, e.reason)
        assertTrue(fx.consent.isEmpty())
    }

    @Test
    fun scaWmp_declined_and_insufficientFactors_signNothing() = runTest(dispatcher) {
        val listener = mockk<WalletEventListener>(relaxed = true)
        val declined = runCatching {
            invokeWmpSign(scaFixture(answer = false, extra = arrayOf("eventListener" to listener)).wallet, wmpParams())
        }.exceptionOrNull() as TransactionDataError
        assertEquals(org.siros.sdk.credentials.TransactionDataReason.DECLINED, declined.reason)
        verify(exactly = 1) { listener.onTransactionDataRefused("flow-wmp", org.siros.sdk.credentials.TransactionDataReason.DECLINED) }
        val few = runCatching { invokeWmpSign(scaFixture(factors = scaFactors.take(1)).wallet, wmpParams()) }.exceptionOrNull() as TransactionDataError
        assertEquals(org.siros.sdk.credentials.TransactionDataReason.INSUFFICIENT_AUTHENTICATION_FACTORS, few.reason)
    }

    // DC API

    private fun dcApiRequest(transactionData: String, responseMode: String = "dc_api") =
        wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
            put("client_id", "web-origin:https://shop.example.com")
            put("response_mode", responseMode)
            put("nonce", "dc-n")
            put("transaction_data", Json.parseToJsonElement(transactionData))
            put("dcql_query", Json.parseToJsonElement("""{"credentials":[{"id":"pay","format":"dc+sd-jwt","meta":{"vct_values":["https://pay.example.com/card"]}}]}"""))
        })

    private fun dcApiWallet(fx: ScaFixture) {
        val api = mockk<BackendApiClient>()
        coEvery { api.evaluateTrust(any()) } returns buildJsonObject { put("decision", true) }
        setField(fx.wallet, "apiClient", api)
        setField(fx.wallet, "trustDecisionCache", TrustDecisionCache(java.time.Duration.ZERO))
        setField(fx.wallet, "_presentationHistory", mutableListOf<PresentationRecord>())
    }

    @Test
    fun scaDcApi_requestIn_kbJwtOut_withWarningForAnUnsignedRequest() = runTest(dispatcher) {
        val fx = scaFixture()
        dcApiWallet(fx)

        val result = fx.wallet.handleDCAPIRequest(dcApiRequest("""["$scaRaw"]"""), "https://shop.example.com")

        val vp = Json.parseToJsonElement(result.responseJson).jsonObject["data"]!!.jsonObject["vp_token"]!!.jsonObject["pay"]!!.jsonArray.single().jsonPrimitive.content
        assertScaKbJwt(vp, "origin:https://shop.example.com", "dc-n", "dc_api")
        assertEquals(false, fx.consent.single().requestSigned)
        assertEquals(TransactionOutcome.CONSENTED, fx.log.items.single().outcome)
    }

    @Test
    fun scaDcApi_flagOff_refusesBeforeTrustAndLogs() = runTest(dispatcher) {
        val fx = scaFixture(enabled = false)
        val api = mockk<BackendApiClient>()
        setField(fx.wallet, "apiClient", api)

        val e = runCatching { fx.wallet.handleDCAPIRequest(dcApiRequest("""["$scaRaw"]"""), "https://shop.example.com") }.exceptionOrNull() as TransactionDataError

        assertEquals(org.siros.sdk.credentials.TransactionDataReason.DISABLED, e.reason)
        coVerify(exactly = 0) { api.evaluateTrust(any()) }
        assertEquals("tx-0001", fx.log.items.single().transactionId)
    }

    @Test
    fun scaDcApi_enabledWithoutHandler_behavesAsDisabled() = runTest(dispatcher) {
        val fx = scaFixture()
        fx.wallet.transactionConsentHandler = null

        val e = runCatching { fx.wallet.handleDCAPIRequest(dcApiRequest("""["$scaRaw"]"""), "https://shop.example.com") }.exceptionOrNull() as TransactionDataError

        assertEquals(org.siros.sdk.credentials.TransactionDataReason.DISABLED, e.reason)
    }

    @Test
    fun scaDcApi_malformedTransactionData_isRefused() = runTest(dispatcher) {
        val fx = scaFixture()
        dcApiWallet(fx)
        for (bad in listOf("""["$scaRaw", 5]""", """{"a":1}""", """"x"""", "[]")) {
            val e = runCatching { fx.wallet.handleDCAPIRequest(dcApiRequest(bad), "https://shop.example.com") }.exceptionOrNull() as TransactionDataError
            assertEquals(bad, org.siros.sdk.credentials.TransactionDataReason.INVALID_ENTRY, e.reason)
        }
        assertEquals("every malformed request is logged, with no payload", 4, fx.log.items.size)
        assertTrue(fx.log.items.all { it.reason == "invalidEntry" && it.outcome == TransactionOutcome.REFUSED && it.transactionId == null })
    }

    @Test
    fun scaDcApi_withoutTransactionData_isUnchangedByTheFlag() = runTest(dispatcher) {
        val fx = scaFixture()
        dcApiWallet(fx)
        val plain = wrapDCAPIRequest("openid4vp-v1-unsigned", buildJsonObject {
            put("client_id", "web-origin:https://shop.example.com"); put("nonce", "dc-n")
            put("dcql_query", Json.parseToJsonElement("""{"credentials":[{"id":"pay","format":"dc+sd-jwt","meta":{"vct_values":["https://pay.example.com/card"]}}]}"""))
        })

        val result = fx.wallet.handleDCAPIRequest(plain, "https://shop.example.com")

        val vp = Json.parseToJsonElement(result.responseJson).jsonObject["data"]!!.jsonObject["vp_token"]!!.jsonObject["pay"]!!.jsonArray.single().jsonPrimitive.content
        assertEquals(setOf("aud", "iat", "nonce", "sd_hash"), SignedJWT.parse(vp.split("~").last()).jwtClaimsSet.claims.keys)
        assertTrue(fx.consent.isEmpty() && fx.log.items.isEmpty())
    }

    // ── review fixes: ordering, defaults, TOCTOU, isolation, wording ──

    @Test
    fun scaDefaults_aSignerThatCannotReachTwoCategoriesRefusesBeforeConsent() = runTest(dispatcher) {
        val fx = scaFixture(factors = null)

        val (sent, _) = sendEngineSignRequest(fx)

        assertTrue(sent.isEmpty())
        assertTrue("the user is not asked", fx.consent.isEmpty())
        assertEquals("insufficientAuthenticationFactors", fx.log.items.single().reason)
    }

    private fun spyKeystore(events: MutableList<String>): (org.siros.sdk.keystore.WscdKeystoreAdapter) -> KeystoreManager = { real ->
        val spy = io.mockk.spyk(real)
        coEvery { spy.signVpToken(any(), any(), any(), any(), any(), any()) } answers { events += "sign"; callOriginal() }
        coEvery { spy.signVpToken(any(), any(), any(), any(), any()) } answers { events += "sign"; callOriginal() }
        coEvery { spy.signPresentation(any(), any(), any(), any()) } answers { events += "sign"; callOriginal() }
        spy
    }

    @Test
    fun scaEngine_nothingIsSignedUntilTheUserHasConsented() = runTest(dispatcher) {
        val events = mutableListOf<String>()
        val fx = scaFixture(keystoreWrapper = spyKeystore(events))
        fx.wallet.transactionConsentHandler = TransactionConsentHandler { events += "consent"; true }

        val (sent, _) = sendEngineSignRequest(fx)

        assertEquals(1, sent.size)
        assertEquals(listOf("consent", "sign"), events)
    }

    @Test
    fun scaWmp_nothingIsSignedUntilTheUserHasConsented() = runTest(dispatcher) {
        val events = mutableListOf<String>()
        val fx = scaFixture(keystoreWrapper = spyKeystore(events))
        fx.wallet.transactionConsentHandler = TransactionConsentHandler { events += "consent"; true }

        invokeWmpSign(fx.wallet, wmpParams())

        assertEquals(listOf("consent", "sign"), events)
    }

    @Test
    fun scaDcApi_nothingIsSignedUntilTheUserHasConsented() = runTest(dispatcher) {
        val events = mutableListOf<String>()
        val fx = scaFixture(keystoreWrapper = spyKeystore(events))
        dcApiWallet(fx)
        fx.wallet.transactionConsentHandler = TransactionConsentHandler { events += "consent"; true }

        fx.wallet.handleDCAPIRequest(dcApiRequest("""["$scaRaw"]"""), "https://shop.example.com")

        assertEquals(listOf("consent", "sign"), events)
    }

    @Test
    fun scaDcApi_aPerRequestHandlerStandsInForTheGlobalOne() = runTest(dispatcher) {
        val fx = scaFixture()
        dcApiWallet(fx)
        fx.wallet.transactionConsentHandler = null
        val seen = mutableListOf<TransactionConsentRequest>()

        val result = fx.wallet.handleDCAPIRequest(
            dcApiRequest("""["$scaRaw"]"""), "https://shop.example.com",
            consentHandler = TransactionConsentHandler { seen += it; true },
        )

        assertEquals(1, seen.size)
        assertTrue(result.responseJson.contains("vp_token"))
        assertTrue("the global handler was not used", fx.consent.isEmpty())
    }

    @Test
    fun scaEngine_theCredentialSignedIsTheOneThatWasShown_evenIfTheStoreChangesDuringConsent() = runTest(dispatcher) {
        val fx = scaFixture()
        val original = runBlocking { (getField(fx.wallet, "credentialStore") as FakeCredentialStore).getAll().single() }
        fx.wallet.transactionConsentHandler = TransactionConsentHandler {
            // while the user thinks, the stored credential is replaced by a different one under the same id
            setField(fx.wallet, "credentialStore", FakeCredentialStore(mutableListOf(
                original.copy(raw = org.siros.sdk.wallet.transaction.TransactionTestFixtures.credential(claims = """{"vct":"https://pay.example.com/card","swapped":true}""").raw),
            )))
            true
        }

        val (sent, _) = sendEngineSignRequest(fx)

        assertEquals(original.raw.substringBefore("~"), sent.single()!!.substringBefore("~"))
    }

    @Test
    fun scaEngine_aSlowConsentDoesNotStallOtherSignRequests() = runTest(dispatcher) {
        // runCurrent, never advanceUntilIdle: advancing virtual time would fire the consent time limit.
        val gate = kotlinx.coroutines.CompletableDeferred<Boolean>()
        val fx = scaFixture()
        fx.wallet.transactionConsentHandler = TransactionConsentHandler { gate.await() }
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        val sent = mutableListOf<Pair<String, String?>>()
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } answers { sent += (args[0] as String) to (args[2] as String?) }
        invokeConnectEngine(fx.wallet, "app-token")
        dispatcher.scheduler.runCurrent()

        signFlow.emit(SignRequestMessage(flowId = "slow", messageId = "m1", action = "sign_presentation", params = SignRequestParams(
            audience = "aud", nonce = "n", responseMode = "direct_post",
            credentialsToInclude = listOf(org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pay", credentialId = "1")),
            transactionData = listOf(scaWire()),
        )))
        repeat(4) { runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }; dispatcher.scheduler.runCurrent() }
        signFlow.emit(SignRequestMessage(flowId = "other", messageId = "m2", action = "sign_presentation", params = SignRequestParams(audience = "aud", nonce = "n")))
        repeat(6) { runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }; dispatcher.scheduler.runCurrent() }

        assertEquals("the other request was answered while consent was pending", listOf("other"), sent.map { it.first })

        gate.complete(true)
        repeat(8) { runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }; dispatcher.scheduler.runCurrent() }
        assertEquals(listOf("other", "slow"), sent.map { it.first })
    }

    @Test
    fun scaEngine_refusalTextIsGenericAndADeclineIsNotAnError() = runTest(dispatcher) {
        val refused = mockk<WalletEventListener>(relaxed = true)
        val a = scaFixture(factors = null, extra = arrayOf("eventListener" to refused))
        sendEngineSignRequest(a)
        verify(exactly = 1) { refused.onFlowError("flow-sca", "Payment confirmation refused: insufficientAuthenticationFactors", any()) }

        val declined = mockk<WalletEventListener>(relaxed = true)
        val b = scaFixture(answer = false, extra = arrayOf("eventListener" to declined))
        sendEngineSignRequest(b)
        verify(exactly = 0) { declined.onFlowError(any(), any(), any()) }
        verify(exactly = 1) { declined.onTransactionDataRefused("flow-sca", org.siros.sdk.credentials.TransactionDataReason.DECLINED) }
    }

    @Test
    fun scaEngine_aKeystoreWithoutTheBindingOverloadIsARefusalNotAnError() = runTest(dispatcher) {
        val fx = scaFixture(keystoreWrapper = { real ->
            val spy = io.mockk.spyk(real)
            coEvery { spy.signVpToken(any(), any(), any(), any(), any(), any()) } throws AbstractMethodError("old keystore")
            spy
        })

        val (sent, _) = sendEngineSignRequest(fx)

        assertTrue(sent.isEmpty())
        assertEquals(listOf(TransactionOutcome.REFUSED, TransactionOutcome.CONSENTED), fx.log.items.map { it.outcome })
        assertEquals("signingFailed", fx.log.items.first().reason)
    }

    @Test
    fun scaWmp_anMdocInTheSameRequestIsRefusedBeforeConsent() = runTest(dispatcher) {
        val fx = scaFixture()
        val mdoc = StoredCredential(id = 2L, format = "mso_mdoc", raw = "AAAA", batchId = 2L, instanceId = 0)
        setField(fx.wallet, "credentialStore", FakeCredentialStore(mutableListOf(
            runBlocking { (getField(fx.wallet, "credentialStore") as FakeCredentialStore).getAll().first() }, mdoc,
        )))
        val params = wmpParams().copy(
            credentialsToInclude = listOf(
                org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pay", credentialId = "1"),
                org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "id", credentialId = "2"),
            ),
        )

        val e = runCatching { invokeWmpSign(fx.wallet, params) }.exceptionOrNull() as TransactionDataError

        assertEquals(org.siros.sdk.credentials.TransactionDataReason.UNSUPPORTED_FORMAT, e.reason)
        assertTrue(fx.consent.isEmpty())
        assertEquals(TransactionOutcome.REFUSED, fx.log.items.single().outcome)
    }

    @Test
    fun scaEngine_theConsentModelListsWhatWillBeDisclosed() = runTest(dispatcher) {
        val fx = scaFixture()
        sendEngineSignRequest(fx)

        val d = fx.consent.single().disclosures
        assertEquals(1, d.size)
        assertEquals("Pay Card", d.single().credentialName)
        assertEquals(true, d.single().bindsTransaction)
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
        state: MutableStateFlow<WalletEngineSession.State> = MutableStateFlow(WalletEngineSession.State.CONNECTED),
        generations: MutableStateFlow<Int> = MutableStateFlow(0),
    ): WalletEngineSession {
        val engine = mockk<WalletEngineSession>()
        every { engine.connect(any(), any(), any()) } just runs
        coEvery { engine.awaitConnected(any()) } just runs
        // Each reconnect opens a new connection generation, as the real session does.
        coEvery { engine.forceReconnect() } coAnswers { engineGeneration.incrementAndGet() }
        every { engine.connectionGeneration } answers { engineGeneration.get() }
        every { engine.state } returns state
        every { engine.connectionGenerations } returns generations
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

    private class InMemoryTransactionLog : TransactionLogStore {
        val items = mutableListOf<TransactionLogEntry>()
        override suspend fun append(entry: TransactionLogEntry) { items.add(0, entry) }
        override suspend fun entries(): List<TransactionLogEntry> = items.toList()
        override suspend fun clear() { items.clear() }
    }

    // ── Issuer-delivered credential_metadata (secret_seed) receipt ───────────

    /** A store that, like the production one, keeps the credential in the keystore too. */
    private class KeystoreMirroringStore(
        private val keystore: org.siros.sdk.keystore.JweKeystore,
        val inner: FakeCredentialStore = FakeCredentialStore(mutableListOf()),
        private val mirror: Boolean = true,
    ) : CredentialStore by inner {
        override suspend fun save(credential: StoredCredential) {
            inner.save(credential)
            if (mirror) keystore.saveCredential(credential.id, Json.encodeToString(StoredCredential.serializer(), credential))
        }

        override suspend fun delete(id: Long) {
            inner.delete(id)
            keystore.deleteCredential(id)
        }
    }

    private class DeliveredScenario(
        val wallet: SirosWallet,
        val store: KeystoreMirroringStore,
        val keystore: org.siros.sdk.keystore.JweKeystore,
        val listener: WalletEventListener,
        val engine: WalletEngineSession,
        val blind: BlindIssuance,
    )

    /** What an issuer does with the wallet's advertised key: encrypt the Credential Response to it. */
    private fun issuerEncrypt(jwk: JsonObject, alg: String, enc: String, plaintext: String): String {
        val header = com.nimbusds.jose.JWEHeader.Builder(com.nimbusds.jose.JWEAlgorithm.parse(alg), com.nimbusds.jose.EncryptionMethod.parse(enc)).build()
        val obj = com.nimbusds.jose.JWEObject(header, com.nimbusds.jose.Payload(plaintext))
        obj.encrypt(com.nimbusds.jose.crypto.ECDHEncrypter(com.nimbusds.jose.jwk.ECKey.parse(jwk.toString())))
        return obj.serialize()
    }

    private val deliveredMember = org.siros.sdk.credentials.SecretSeedDelivery.MEMBER
    private val deliveredNamespace = org.siros.sdk.credentials.SecretSeedDelivery.DEFAULT_NAMESPACE

    private fun deliveredMetadata(hex: String = NymTestCredentials.seedHex) = org.siros.sdk.transport.ResponseCredentialMetadata(
        buildJsonObject {
            put(deliveredMember, buildJsonObject { put(deliveredNamespace, JsonPrimitive(hex)) })
            put("example.other", JsonPrimitive("kept as is"))
        },
    )

    private fun deliveredResult(
        credential: String = NymTestCredentials.sdJwt(),
        notificationId: String? = "notif-1",
        format: String = "dc+sd-jwt",
    ) = CredentialResult(format = format, credential = credential, notificationId = notificationId)

    private suspend fun kotlinx.coroutines.test.TestScope.deliveredScenario(
        results: List<CredentialResult>,
        metadata: org.siros.sdk.transport.ResponseCredentialMetadata? = deliveredMetadata(),
        /** True: the issuer's response was a JWE the WALLET opened (the engine never held it); false: a plain issuance. */
        encrypted: Boolean = true,
        advertised: Boolean = false,
        redactedMembers: Set<String> = emptySet(),
        /** True: the engine reports an encrypted issuance but the wallet holds no decrypted response for it. */
        lostResponse: Boolean = false,
        /** The number of credential entries the engine's completion lists, when it is not [results]'s size. */
        engineEntries: Int? = null,
        /** The raw `credential_metadata` member of the engine's completion frame (decoded by the real allowlist). */
        wireMetadata: String? = null,
        /** True: a response key was offered although the issuer then answered in clear (an optional encryption). */
        offeredKey: Boolean = false,
        /** With [offeredKey]: the socket the flow lived on was replaced (and the sweep ran) before the completion arrived. */
        socketReplacedSinceOffer: Boolean = false,
        /** The engine delivers the very same completion a SECOND time (the transport does not de-duplicate). */
        repeatCompletion: Boolean = false,
        /** Runs after the key was offered and before the completion arrives (to put the holder under pressure, say). */
        beforeCompletion: (BlindIssuance) -> Unit = {},
        /** The `notification_id` the engine's ENCRYPTED completion frame carries on its entries (it should never be read). */
        frameNotificationId: String? = null,
        /** True: another flow (`flow-other`) holds an issuance key and an opened response while this one completes. */
        bystander: Boolean = false,
        refreshToken: String? = null,
        preexisting: List<StoredCredential> = emptyList(),
        renewalSourceBatchId: Long? = null,
        configure: (WalletConfig) -> WalletConfig = { it },
        mirrorToKeystore: Boolean = true,
        issuerTrust: org.siros.sdk.transport.engine.IssuerTrustReport? = null,
        /** False: the wallet has no active offer (a replayed or resumed completion in a fresh wallet). */
        withOffer: Boolean = true,
    ): DeliveredScenario {
        val flowId = "flow-delivered"
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val keystore = org.siros.sdk.keystore.JweKeystore()
        keystore.unlock(ByteArray(32) { it.toByte() }, ByteArray(0), ByteArray(32) { 5 }, "info".toByteArray())
        val store = KeystoreMirroringStore(keystore, mirror = mirrorToKeystore)
        preexisting.forEach { store.save(it) }
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        every { sessionStore.privateDataJwe } returns null
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        val engine = mockEngineConstructor(flowComplete = completeFlow)
        every { engine.sendCredentialNotification(any(), any(), any(), any()) } just runs
        // An encrypted issuance: the wallet generated the key, the issuer encrypted to it, the wallet opened the
        // response. The engine's completion then carries no credential, no notification_id and no metadata.
        val blind = BlindIssuance()
        // Opened after the engine connects: a new connection drops the keys of the flows of the one it replaces.
        val openResponse = {
            val jwk = blind.offer(flowId, org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))!!
            val body = buildJsonObject {
                put("credentials", kotlinx.serialization.json.JsonArray(results.map { buildJsonObject { put("credential", JsonPrimitive(it.credential)) } }))
                results.firstNotNullOfOrNull { it.notificationId }?.let { put("notification_id", JsonPrimitive(it)) }
                metadata?.let { put("credential_metadata", if (it.malformed) JsonPrimitive("not-an-object") else JsonObject(it.members)) }
            }
            blind.open(flowId, issuerEncrypt(jwk, "ECDH-ES", "A256GCM", body.toString()), deferred = false)
        }
        val completionResults = if (encrypted) {
            List(engineEntries ?: results.size) { results.first().copy(credential = "", notificationId = frameNotificationId) }
        } else {
            results
        }
        val fields = mutableListOf<Pair<String, Any?>>(
            "blindIssuance" to blind,
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(
                    userId = "user-1", displayName = "Alice", flowId = flowId,
                    flowType = "issuance", status = "in_progress", credentials = emptyList(),
                ),
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to configure(WalletConfig(backendUrl = "https://wallet.example.com")),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
            "secretSeedAdvertised" to advertisedSelections(advertised),
        )
        if (renewalSourceBatchId != null) fields += "pendingRenewalSourceBatchId" to renewalSourceBatchId
        if (withOffer) {
            fields += "activeOffer" to org.siros.sdk.credentials.CredentialOffer(
                credentialConfigurationId = "nym", credentialIssuerIdentifier = "https://issuer.example", credentialName = "Nym", issuerName = "Issuer",
            )
        }
        val wallet = newWallet(*fields.toTypedArray())
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        if (encrypted && !lostResponse) openResponse()
        if (bystander) {
            val other = blind.offer("flow-other", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))!!
            blind.open("flow-other", issuerEncrypt(other, "ECDH-ES", "A256GCM", issuerBody("bystander credential").toString()), deferred = false)
        }
        if (offeredKey) {
            blind.offer(flowId, org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false), generation = 0)
            if (socketReplacedSinceOffer) blind.markStaleBefore(1)
            beforeCompletion(blind)
        }
        val completionMessage = FlowCompleteMessage(
            flowId = flowId, credentials = completionResults,
            credentialIssuer = "https://issuer.example", selectedCredentialConfigurationId = "nym",
            credentialResponseEncrypted = encrypted,
            credentialMetadata = wireMetadata?.let {
                Json.decodeFromString(FlowCompleteMessage.serializer(), """{"flow_id":"$flowId","credential_metadata":$it}""").credentialMetadata
            },
            redactedMembers = redactedMembers, refreshToken = refreshToken, dpopKeyId = refreshToken?.let { "key-1" },
            issuerTrust = issuerTrust,
        )
        completeFlow.emit(completionMessage)
        advanceUntilIdle()
        if (repeatCompletion) {
            completeFlow.emit(completionMessage)
            advanceUntilIdle()
        }
        return DeliveredScenario(wallet, store, keystore, listener, engine, blind)
    }

    private fun storedCopy(id: Long, batchId: Long) = StoredCredential(
        id = id, format = "dc+sd-jwt", raw = NymTestCredentials.sdJwt(), batchId = batchId, instanceId = 0,
    )

    private suspend fun assertNothingStored(s: DeliveredScenario) {
        assertEquals(0, s.store.getAll().size)
        assertEquals(0, s.keystore.getAllCredentials().size)
        verify(exactly = 0) { s.listener.onCredentialReceived(any()) }
        verify(exactly = 0) { s.listener.onFlowComplete(any(), any()) }
    }

    private fun assertNoSecretIn(text: String?) {
        val t = text.orEmpty()
        assertFalse(t.contains(NymTestCredentials.seedHex))
        assertFalse(t.contains(NymTestCredentials.hex(NymTestCredentials.goodSsc)))
        assertFalse(t.contains(NymTestCredentials.hex(NymTestCredentials.wrongSsc)))
    }

    private fun wrongSscCredential() = NymTestCredentials.sdJwt(sscValues = listOf(NymTestCredentials.hex(NymTestCredentials.wrongSsc)))

    @Test
    fun deliveredSeed_matchingSsc_storesCredentialAndMetadata_andAccepts() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult()))
        val stored = s.store.getAll().single()
        val md = s.keystore.getCredentialMetadata(stored.id)!!
        assertEquals(2, md.size)
        assertEquals(JsonPrimitive(deliveredMember), md[0].jsonObject["type"])
        assertEquals(
            JsonPrimitive(NymTestCredentials.seedHex),
            md[0].jsonObject["value"]!!.jsonObject[deliveredNamespace],
        )
        assertEquals(JsonPrimitive("kept as is"), md[1].jsonObject["value"])
        // The secret never reaches the stored credential JSON, display metadata or the wallet state.
        assertNoSecretIn(s.keystore.getCredential(stored.id))
        assertNoSecretIn(Json.encodeToString(StoredCredential.serializer(), stored))
        assertNoSecretIn((s.wallet.state.value as WalletState.Ready).credentials.toString())
        verify(exactly = 1) {
            s.engine.sendCredentialNotification(flowId = "flow-delivered", notificationId = "notif-1", event = CredentialNotificationEvent.ACCEPTED)
        }
        verify(exactly = 1) { s.listener.onFlowComplete("flow-delivered", any()) }
    }

    @Test
    fun aCompletionWithNoActiveOffer_keepsTheIssuerTheEngineStates() = runTest(dispatcher) {
        // A replayed or resumed flow_complete in a fresh wallet: no offer, no preceding sign request. The stored credential must
        // still be bound to the exact issuer (its private_seed derives from that string), not to null.
        val withOffer = deliveredScenario(listOf(deliveredResult()))
        assertEquals("https://issuer.example", withOffer.store.getAll().single().credentialIssuerIdentifier)
        val fresh = deliveredScenario(listOf(deliveredResult()), withOffer = false)
        assertEquals("https://issuer.example", fresh.store.getAll().single().credentialIssuerIdentifier)
    }

    @Test
    fun deliveredSeed_everyCopyOfABatchCarriesTheSameMetadata() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult(), deliveredResult(), deliveredResult()))
        val all = s.store.getAll()
        assertEquals(3, all.size)
        val first = s.keystore.getCredentialMetadata(all[0].id)!!
        for (c in all) assertEquals(first, s.keystore.getCredentialMetadata(c.id))
        assertEquals(2, first.size)
    }

    @Test
    fun deliveredMetadata_withoutTheSeedMember_isStoredUninterpreted() = runTest(dispatcher) {
        val md = org.siros.sdk.transport.ResponseCredentialMetadata(buildJsonObject { put("example.other", JsonPrimitive("v")) })
        val s = deliveredScenario(listOf(deliveredResult()), metadata = md)
        assertEquals(1, s.keystore.getCredentialMetadata(s.store.getAll().single().id)!!.size)
    }

    /** The wallet-opened response whose `credential_metadata` is the raw JSON [metadataJson], however malformed. */
    private suspend fun kotlinx.coroutines.test.TestScope.deliveredScenarioOfJson(metadataJson: String, notificationId: String = "notif-1") =
        deliveredScenario(
            listOf(deliveredResult(notificationId = notificationId)),
            metadata = Json.decodeFromString(org.siros.sdk.transport.ResponseCredentialMetadata.serializer(), metadataJson),
        )

    @Test
    fun deliveredMetadata_membersAreStoredExactlyAsReceived_inOrder_withLiteralsVerbatim() = runTest(dispatcher) {
        val wire = """{"z.last":{"n":1.50,"nested":{"a":[1,2.0,null]}},"a.first":1}"""
        val s = deliveredScenarioOfJson(wire)
        val stored = s.keystore.getCredentialMetadata(s.store.getAll().single().id)!!
        assertEquals(listOf("z.last", "a.first"), stored.map { it.jsonObject["type"]!!.jsonPrimitive.content })
        val text = stored[0].toString()
        assertTrue(text, "\"n\":1.50" in text && "[1,2.0,null]" in text)
    }

    @Test
    fun deliveredSeed_fromAnUntrustedIssuer_isRefusedByTheTrustGate_nothingStoredAndNoSeedKept() = runTest(dispatcher) {
        // A valid seed + a matching ssc would be accepted on its own (see deliveredSeed_matchingSsc_...);
        // the engine's negative issuer trust must still refuse the whole issuance, fail closed.
        val s = deliveredScenario(
            listOf(deliveredResult()),
            issuerTrust = org.siros.sdk.transport.engine.IssuerTrustReport("https://issuer.example", false, "fw", "not listed"),
        )
        assertNothingStored(s)
        verify(exactly = 1) { s.listener.onIssuerNotTrusted("flow-delivered", "https://issuer.example", any()) }
        verify(exactly = 1) { s.engine.sendCredentialNotification("flow-delivered", "notif-1", CredentialNotificationEvent.FAILURE, any()) }
        verify(exactly = 0) { s.engine.sendCredentialNotification(any(), any(), CredentialNotificationEvent.ACCEPTED, any()) }
    }

    @Test
    fun deliveredSeed_wrongSeed_failsTheIssuance_storesNothing_andNotifiesFailure() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult(credential = wrongSscCredential())))
        assertNothingStored(s)
        verify(exactly = 1) {
            s.engine.sendCredentialNotification(
                flowId = "flow-delivered", notificationId = "notif-1",
                event = CredentialNotificationEvent.FAILURE, eventDescription = any(),
            )
        }
        verify(exactly = 0) {
            s.engine.sendCredentialNotification(any(), any(), CredentialNotificationEvent.ACCEPTED, any())
        }
        val message = slot<String>()
        verify(exactly = 1) { s.listener.onFlowError("flow-delivered", capture(message), any()) }
        assertNoSecretIn(message.captured)
        assertTrue(s.wallet.state.value is WalletState.Ready)
    }

    @Test
    fun deliveredSeed_aPlainResponseOfAnAdvertisedConfiguration_failsTheIssuance() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult()), encrypted = false, advertised = true)
        assertNothingStored(s)
        verify(exactly = 1) {
            s.engine.sendCredentialNotification(any(), "notif-1", CredentialNotificationEvent.FAILURE, any())
        }
    }

    @Test
    fun deliveredSeed_malformedValue_failsTheIssuance() = runTest(dispatcher) {
        assertNothingStored(deliveredScenario(listOf(deliveredResult()), metadata = deliveredMetadata(NymTestCredentials.seedHex.uppercase())))
    }

    @Test
    fun deliveredSeed_withoutANotificationId_failsLocally_andSaysSo() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult(notificationId = null)))
        assertNothingStored(s)
        verify(exactly = 0) { s.engine.sendCredentialNotification(any(), any(), any(), any()) }
        val message = slot<String>()
        verify(exactly = 1) { s.listener.onFlowError("flow-delivered", capture(message), any()) }
        assertTrue(message.captured, message.captured.contains("could not be notified"))
        assertNoSecretIn(message.captured)
    }

    @Test
    fun deliveredSeed_oneBadCopyFailsTheWholeBatch() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult(), deliveredResult(credential = wrongSscCredential())))
        assertNothingStored(s)
        verify(exactly = 1) { s.engine.sendCredentialNotification(any(), "notif-1", CredentialNotificationEvent.FAILURE, any()) }
    }

    @Test
    fun deliveredSeed_failedRenewalKeepsTheOldBatch() = runTest(dispatcher) {
        val s = deliveredScenario(
            listOf(deliveredResult(credential = wrongSscCredential())),
            preexisting = listOf(storedCopy(id = 41L, batchId = 77L)),
            renewalSourceBatchId = 77L,
        )
        assertEquals(listOf(41L), s.store.getAll().map { it.id })
        verify(exactly = 0) { s.listener.onFlowComplete(any(), any()) }
    }

    @Test
    fun aLiveCompletionCapturesTheRenewalMaterial() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult()), refreshToken = "rt-1")
        val batch = s.store.getAll().single().batchId!!
        val entry = s.keystore.exportCredentialRefreshTokens()[batch]!!
        assertEquals("rt-1", entry.refreshToken)
        assertEquals("key-1", entry.dpopKeyId)
    }

    @Test
    fun aReplayedCompletion_storesItsCredentials_butCapturesNoRenewalMaterial_andIsNotRenewable() = runTest(dispatcher) {
        // No seed is needed (a credential without a commitment): the credentials are stored normally.
        val plain = NymTestCredentials.sdJwt(sscValues = emptyList())
        val s = deliveredScenario(listOf(deliveredResult(credential = plain)), metadata = null, redactedMembers = setOf("dpop_key_id", "refresh_token"), refreshToken = "rt-must-not-be-kept")
        val stored = s.store.getAll()
        assertEquals(1, stored.size)
        assertTrue(s.keystore.exportCredentialRefreshTokens().isEmpty())
        verify(exactly = 1) { s.listener.onFlowComplete("flow-delivered", any()) }
        // Renewal of that batch is unavailable: nothing stale is reused.
        val e = try {
            kotlinx.coroutines.runBlocking { s.wallet.renewCredential(stored.single().batchId!!) }
            null
        } catch (t: Exception) {
            t
        }
        assertTrue(e?.message.orEmpty(), e?.message.orEmpty().contains("No refresh_token stored"))
    }

    @Test
    fun anEncryptedCompletionTheWalletHoldsNoResponseFor_failsAndStoresNothing() = runTest(dispatcher) {
        // A replayed or resumed completion (the app restarted mid-flow, say): the engine never had the credentials, so
        // nothing can be recovered and nothing is invented.
        val s = deliveredScenario(listOf(deliveredResult()), lostResponse = true)
        assertNothingStored(s)
        // The engine never told the wallet a notification_id either: there is no channel to the issuer.
        verify(exactly = 0) { s.engine.sendCredentialNotification(any(), any(), any(), any()) }
        val message = slot<String>()
        verify(exactly = 1) { s.listener.onFlowError("flow-delivered", capture(message), any()) }
        assertTrue(message.captured, message.captured.contains("not available in this wallet"))
        assertTrue(s.keystore.exportCredentialRefreshTokens().isEmpty())
    }

    @Test
    fun anAdvertisedConfiguration_refusesAnUnencryptedCompletion_evenWithoutMetadata() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult()), metadata = null, encrypted = false, advertised = true)
        assertNothingStored(s)
        verify(exactly = 1) { s.engine.sendCredentialNotification(any(), "notif-1", CredentialNotificationEvent.FAILURE, any()) }
        // An encrypted one that carries the seed is fine.
        val ok = deliveredScenario(listOf(deliveredResult()), encrypted = true, advertised = true)
        assertEquals(1, ok.store.getAll().size)
    }

    @Test
    fun malformedDeliveredMetadataOnTheWire_endsTheIssuanceAsARefusal() = runTest(dispatcher) {
        listOf("""[{"type":"other","value":1}]""", """"text"""", "5").forEach { md ->
            val s = deliveredScenarioOfJson(md)
            assertNothingStored(s)
            verify(exactly = 1) {
                s.engine.sendCredentialNotification(flowId = "flow-delivered", notificationId = "notif-1", event = CredentialNotificationEvent.FAILURE, eventDescription = any())
            }
            verify(exactly = 1) { s.listener.onFlowError("flow-delivered", any(), any()) }
            assertTrue(md, s.wallet.state.value is WalletState.Ready)
        }
    }

    @Test
    fun wellFormedDeliveredMetadataOnTheWire_isUnaffected() = runTest(dispatcher) {
        val s = deliveredScenarioOfJson("""{"example.other":{"scope":"issuer"}}""")
        assertEquals(1, s.store.getAll().size)
        verify(exactly = 0) { s.listener.onFlowError(any(), any(), any()) }
    }

    @Test
    fun wmpFlowComplete_refusesMalformedAndUnencryptedSeedMetadata_withItsNotificationIds() = runTest(dispatcher) {
        val flowId = "flow-wmp"
        val seedBody = buildJsonObject { put(deliveredMember, buildJsonObject { put(deliveredNamespace, JsonPrimitive(NymTestCredentials.seedHex)) }) }
        /** A wallet that opened an issuer response whose `credential_metadata` is [metadata] (null: none). */
        fun walletHolding(metadata: kotlinx.serialization.json.JsonElement?, advertised: Boolean = false): SirosWallet {
            val blind = BlindIssuance()
            val jwk = blind.offer(flowId, org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A128GCM", false))!!
            val body = buildJsonObject {
                put("credentials", kotlinx.serialization.json.JsonArray(listOf(buildJsonObject { put("credential", JsonPrimitive(NymTestCredentials.sdJwt())) })))
                put("notification_id", JsonPrimitive("n9"))
                metadata?.let { put("credential_metadata", it) }
            }
            blind.open(flowId, issuerEncrypt(jwk, "ECDH-ES", "A128GCM", body.toString()), deferred = false)
            return newWallet(
                "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
                "keystore" to org.siros.sdk.keystore.JweKeystore(),
                "blindIssuance" to blind,
                "secretSeedAdvertised" to advertisedSelections(advertised),
            )
        }
        val encrypted = Json.parseToJsonElement(
            """{"credentials":[{"format":"dc+sd-jwt"}],"credential_response_encrypted":true,"credential_issuer":"https://issuer.example"}""",
        ).jsonObject
        val refused = walletHolding(Json.parseToJsonElement("""[{"type":"other"}]""")).wmpDeliveredMetadataRefusal(flowId, encrypted)
        assertEquals(DeliveredMetadataRefusal.MALFORMED, refused!!.first)
        assertEquals(listOf("n9"), refused.second)
        assertEquals(DeliveredMetadataRefusal.MALFORMED, walletHolding(JsonPrimitive("text")).wmpDeliveredMetadataRefusal(flowId, encrypted)!!.first)
        assertEquals(null, walletHolding(Json.parseToJsonElement("""{"example.other":1}""")).wmpDeliveredMetadataRefusal(flowId, encrypted))
        // The seed, wallet-decrypted, opens the credential's ssc: accepted.
        assertEquals(null, walletHolding(seedBody).wmpDeliveredMetadataRefusal(flowId, encrypted))
        // A plain completion delivers no metadata the engine could have relayed: nothing to refuse. (The WMP completion
        // names no configuration id, so the advertised-but-plain refusal is the legacy transport's alone.)
        val plain = Json.parseToJsonElement(
            """{"credentials":[{"format":"dc+sd-jwt","credential":${JsonPrimitive(NymTestCredentials.sdJwt())},"notification_id":"n9"}],"credential_issuer":"https://issuer.example"}""",
        ).jsonObject
        val advertisedWallet = walletHolding(null, advertised = true)
        assertEquals(null, advertisedWallet.wmpDeliveredMetadataRefusal("other-flow", plain))
        // A plain completion's relayed metadata is read (display-only): one that is not an object is refused as malformed,
        // while a seed in the frame is dropped and so neither refused nor taken.
        fun plainWith(md: String) = Json.parseToJsonElement(
            """{"credentials":[{"format":"dc+sd-jwt","credential":${JsonPrimitive(NymTestCredentials.sdJwt(sscValues = emptyList()))},"notification_id":"n9"}],"credential_metadata":$md}""",
        ).jsonObject
        assertEquals(DeliveredMetadataRefusal.MALFORMED, advertisedWallet.wmpDeliveredMetadataRefusal("p", plainWith("\"text\""))!!.first)
        assertEquals(null, advertisedWallet.wmpDeliveredMetadataRefusal("p", plainWith(seedBody.toString())))
        // An encrypted completion with no response held for the flow cannot be completed, and nothing is invented.
        val lost = advertisedWallet.wmpDeliveredMetadataRefusal("unknown-flow", encrypted)
        assertEquals(DeliveredMetadataRefusal.RESPONSE_UNAVAILABLE, lost!!.first)
        assertEquals(null, advertisedWallet.wmpDeliveredMetadataRefusal("x", null))
    }

    @Test
    fun deliveredSeed_aKeystoreThatRefusesTheMetadata_rollsBackTheWholeBatch() = runTest(dispatcher) {
        // The store never put the credentials into the keystore, so attaching their metadata fails.
        val s = deliveredScenario(listOf(deliveredResult(), deliveredResult()), mirrorToKeystore = false)
        assertEquals(0, s.store.getAll().size)
        verify(exactly = 0) { s.listener.onCredentialReceived(match { false }) }
        verify(exactly = 0) { s.listener.onFlowComplete(any(), any()) }
        verify(exactly = 1) { s.engine.sendCredentialNotification(any(), "notif-1", CredentialNotificationEvent.FAILURE, any()) }
        verify(exactly = 0) { s.engine.sendCredentialNotification(any(), any(), CredentialNotificationEvent.ACCEPTED, any()) }
    }

    @Test
    fun deliveredSeed_aConfiguredNamespaceIsTheOneVerified() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult()), configure = { it.copy(secretSeedNamespace = "example.designated") })
        assertNothingStored(s)
    }

    @Test
    fun anAdvertisementWithAValueInPublicIssuerMetadata_makesTheConfigurationNotOffered() = runTest(dispatcher) {
        val wallet = newWallet(
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "secretSeedAdvertised" to advertisedSelections(false),
        )
        fun offer(secretSeed: String?): Any? {
            val member = if (secretSeed != null) ""","org.siros.secret_seed":$secretSeed""" else ""
            val metadata = Json { ignoreUnknownKeys = true }.decodeFromString(
                org.siros.sdk.credentials.IssuerMetadata.serializer(),
                """{"credential_issuer":"https://issuer.example","credential_endpoint":"https://issuer.example/c","credential_configurations_supported":{"nym":{"format":"dc+sd-jwt","vct":"urn:nym","credential_metadata":{"display":[{"name":"Nym"}]$member}}}}""",
            )
            val m = wallet.javaClass.getDeclaredMethod("buildCredentialOfferFromMetadata", String::class.java, String::class.java, org.siros.sdk.credentials.IssuerMetadata::class.java)
            m.isAccessible = true
            return m.invoke(wallet, "https://issuer.example", "nym", metadata)
        }
        assertNotNull(offer(null))
        assertNotNull(offer("""{"namespaces":["org.siros.nym_auth"]}"""))
        assertEquals(null, offer("""{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"}"""))
        assertEquals(null, offer("""{"namespaces":["org.siros.nym_auth"],"org.siros.nym_auth":"00112233445566778899aabbccddeeff"}"""))
    }

    @Test
    fun deliveredSeed_aKeystoreThatCannotHoldItFailsClosed() = runTest(dispatcher) {
        // The shared mock keystore of the older tests is neither a JweKeystore nor a WscdKeystoreAdapter.
        val completeFlow = MutableSharedFlow<FlowCompleteMessage>()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val store = FakeCredentialStore(mutableListOf())
        val keystore = mockk<KeystoreManager>()
        val sessionStore = mockk<SessionStore>(relaxed = true)
        val apiClient = mockk<BackendApiClient>(relaxed = true)
        every { keystore.isUnlocked } returns true
        coEvery { keystore.exportEncryptedContainer() } returns """{"prfKeys":[],"jwe":"j"}""".toByteArray()
        coEvery { apiClient.updatePrivateData(any()) } returns buildJsonObject {}
        val engine = mockEngineConstructor(flowComplete = completeFlow)
        every { engine.sendCredentialNotification(any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "blindIssuance" to blind,
            "_state" to MutableStateFlow<WalletState>(
                WalletState.FlowActive(userId = "u", displayName = null, flowId = "f", flowType = "issuance", status = "in_progress", credentials = emptyList()),
            ),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to store,
            "keystore" to keystore,
            "sessionStore" to sessionStore,
            "apiClient" to apiClient,
            "eventListener" to listener,
            "secretSeedAdvertised" to advertisedSelections(false),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        val jwk = blind.offer("f", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A128GCM", false))!!
        val body = buildJsonObject {
            put("credentials", kotlinx.serialization.json.JsonArray(listOf(buildJsonObject { put("credential", JsonPrimitive(deliveredResult().credential)) })))
            put("notification_id", JsonPrimitive("notif-1"))
            put("credential_metadata", JsonObject(deliveredMetadata().members))
        }
        blind.open("f", issuerEncrypt(jwk, "ECDH-ES", "A128GCM", body.toString()), deferred = false)
        completeFlow.emit(FlowCompleteMessage(flowId = "f", credentials = listOf(deliveredResult(notificationId = null).copy(credential = "")), credentialResponseEncrypted = true))
        advanceUntilIdle()
        assertEquals(0, store.getAll().size)
        verify(exactly = 1) { engine.sendCredentialNotification("f", "notif-1", CredentialNotificationEvent.FAILURE, any()) }
    }

    // ---- engine-blind encryption: the wallet holds the response key and builds the encrypted responses ----

    private val blindVerifier: com.nimbusds.jose.jwk.ECKey = com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
        .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION).keyID("verifier-1").generate()

    private fun blindResponseEncryption() = org.siros.sdk.transport.ResponseEncryptionRequest(
        jwk = Json.parseToJsonElement(blindVerifier.toPublicJWK().toJSONString()).jsonObject,
        alg = "ECDH-ES",
        enc = "A128GCM",
    )

    /** The claims of a compact JARM JWE, opened with the verifier's private key. */
    private fun openJarm(jwe: String): JsonObject {
        val obj = com.nimbusds.jose.JWEObject.parse(jwe)
        obj.decrypt(com.nimbusds.jose.crypto.ECDHDecrypter(blindVerifier))
        return Json.parseToJsonElement(obj.payload.toString()).jsonObject
    }

    private fun issuerBody(vararg credentials: String, extra: Map<String, kotlinx.serialization.json.JsonElement> = emptyMap()) = buildJsonObject {
        put("credentials", kotlinx.serialization.json.JsonArray(credentials.map { buildJsonObject { put("credential", JsonPrimitive(it)) } }))
        extra.forEach { (k, v) -> put(k, v) }
    }

    @Test
    fun legacyGenerateProof_withAResponseEncryptionRequest_answersWithAFreshPublicKeyAndHoldsThePrivateOne() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.isWscdOnboarded() } returns true
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "nonce-1", freshKey = any(), holderBinding = any()) } returns "proof-jwt"
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-enc",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1", nonce = "nonce-1",
                    proofTypesSupported = buildJsonObject { putJsonObject("jwt") {} },
                    credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES+A256KW", "A128GCM", required = true),
                ),
            )
        )
        advanceUntilIdle()

        val jwk = slot<JsonObject>()
        verify(exactly = 1) {
            engine.sendSignResponse(
                "flow-enc",
                proofs = listOf(ProofObject(proofType = "jwt", jwt = "proof-jwt")),
                messageId = null,
                credentialResponseEncryptionJwk = capture(jwk),
            )
        }
        assertEquals("enc", jwk.captured["use"]!!.jsonPrimitive.content)
        assertEquals("ECDH-ES+A256KW", jwk.captured["alg"]!!.jsonPrimitive.content)
        assertFalse("the private part never leaves the wallet", jwk.captured.containsKey("d"))
        assertTrue(blind.holdsKey("flow-enc"))
    }

    @Test
    fun legacyGenerateProof_aRequiredEncryptionTheWalletCannotProvide_failsBeforeAnyProofIsMade() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.isWscdOnboarded() } returns true
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val listener = mockk<WalletEventListener>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
            "eventListener" to listener,
            "credentialStore" to FakeCredentialStore(mutableListOf()),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-enc",
                action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1", nonce = "nonce-1",
                    credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("RSA-OAEP", "A128GCM", required = true),
                ),
            )
        )
        advanceUntilIdle()

        coVerify(exactly = 0) { keystore.generateProof(any(), any(), any(), any()) }
        coVerify(exactly = 0) { keystore.generateProof(any(), any(), any(), any(), any()) }
        verify(exactly = 1) { listener.onFlowError("flow-enc", match { it.contains("requires an encrypted credential response") }, any()) }
        verify(exactly = 0) { engine.sendSignResponse(any(), any(), any(), proofs = any(), messageId = any()) }
    }

    @Test
    fun legacyDecryptCredentialResponse_opensTheJweAndAnswersWithTheControlFieldsOnly() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        val jwk = blind.offer("flow-d", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))!!
        val jwe = issuerEncrypt(
            jwk, "ECDH-ES", "A256GCM",
            buildJsonObject { put("transaction_id", JsonPrimitive("tx-77")); put("interval", JsonPrimitive(5)) }.toString(),
        )
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-d", messageId = "msg-d", action = "decrypt_credential_response",
                params = SignRequestParams(jwe = jwe, deferred = false),
            )
        )
        advanceUntilIdle()

        verify(exactly = 1) {
            engine.sendSignResponse(flowId = "flow-d", messageId = "msg-d", transactionId = "tx-77", interval = 5)
        }
    }

    @Test
    fun legacyGenerateProof_keyOnly_returnsTheKeyAndNoProofsAndMakesNoProof() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val keystore = mockk<KeystoreManager>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to keystore,
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-key", messageId = "msg-key", action = "generate_proof",
                // A configuration with no proof_types_supported that still wants an encrypted response.
                params = SignRequestParams(credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", required = true)),
            )
        )
        advanceUntilIdle()

        val jwk = slot<JsonObject>()
        verify(exactly = 1) { engine.sendSignResponse("flow-key", messageId = "msg-key", credentialResponseEncryptionJwk = capture(jwk)) }
        assertEquals(setOf("kty", "crv", "x", "y", "use", "alg"), jwk.captured.keys)
        assertTrue(blind.holdsKey("flow-key"))
        // The strict keystore mock would have thrown had a proof been attempted.
    }

    @Test
    fun legacyDecryptCredentialResponse_ofIssuedCredentials_answersWithTheCountOnly() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        val jwk = blind.offer("flow-d", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))!!
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-d", messageId = "msg-d", action = "decrypt_credential_response",
                params = SignRequestParams(jwe = issuerEncrypt(jwk, "ECDH-ES", "A256GCM", issuerBody("c1", "c2").toString()), deferred = false),
            )
        )
        advanceUntilIdle()
        verify(exactly = 1) { engine.sendSignResponse(flowId = "flow-d", messageId = "msg-d", credentialCount = 2) }
    }

    @Test
    fun legacyDecryptCredentialResponse_aResponseTheWalletReadButRejects_isReportedToTheIssuerBeforeTheErrorAnswer() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        every { engine.sendCredentialNotification(any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        val jwk = blind.offer("flow-d", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))!!
        // Decrypts, but carries neither credentials nor a transaction_id: refused, with its notification_id.
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-d", messageId = "msg-d", action = "decrypt_credential_response",
                params = SignRequestParams(
                    jwe = issuerEncrypt(jwk, "ECDH-ES", "A256GCM", buildJsonObject { put("notification_id", JsonPrimitive("n-r")) }.toString()),
                    deferred = false,
                ),
            )
        )
        advanceUntilIdle()
        io.mockk.verifyOrder {
            engine.sendCredentialNotification("flow-d", "n-r", CredentialNotificationEvent.FAILURE, "credential_response_rejected")
            engine.sendSignResponse(flowId = "flow-d", messageId = "msg-d", error = any())
        }
        verify(exactly = 0) { engine.sendSignResponse(flowId = "flow-d", messageId = "msg-d", credentialCount = any()) }
    }

    @Test
    fun legacyDecryptCredentialResponse_aDeferredAnswerThatAgainReportsATransactionId_isAnsweredWithItAgain() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        val jwk = blind.offer("flow-d", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))!!
        for ((n, deferred) in listOf("tx-1" to false, "tx-2" to true)) {
            signFlow.emit(
                SignRequestMessage(
                    flowId = "flow-d", messageId = "msg-$n", action = "decrypt_credential_response",
                    params = SignRequestParams(
                        jwe = issuerEncrypt(jwk, "ECDH-ES", "A256GCM", buildJsonObject { put("transaction_id", JsonPrimitive(n)); put("interval", JsonPrimitive(3)) }.toString()),
                        deferred = deferred,
                    ),
                )
            )
            advanceUntilIdle()
            verify(exactly = 1) { engine.sendSignResponse(flowId = "flow-d", messageId = "msg-$n", transactionId = n, interval = 3) }
        }
    }

    @Test
    fun wmpGenerateProof_keyOnly_returnsTheKeyAndNoProofs() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>() // strict: a proof attempt would throw
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to keystore,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "blindIssuance" to blind,
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        val result = runBlocking {
            method.callSuspend(
                wallet, "flow-w",
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
                    action = "generate_proof",
                    credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", true),
                ),
            )
        } as org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult
        assertEquals(null, result.proofs)
        assertEquals(setOf("kty", "crv", "x", "y", "use", "alg"), result.credentialResponseEncryptionJwk!!.keys)
        assertTrue(blind.holdsKey("flow-w"))
    }

    @Test
    fun wmpDecryptCredentialResponse_answersWithTheCount_andAResponseItRejectsIsReportedToTheIssuer() = runTest(dispatcher) {
        val blind = BlindIssuance()
        val peer = mockk<org.siros.sdk.transport.wmp.WmpPeer>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "wmpPeer" to peer,
            "blindIssuance" to blind,
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        val jwk = blind.offer("flow-w", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))!!
        val counted = runBlocking {
            method.callSuspend(
                wallet, "flow-w",
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
                    action = "decrypt_credential_response", deferred = false,
                    jwe = issuerEncrypt(jwk, "ECDH-ES", "A256GCM", issuerBody("c1", "c2", "c3").toString()),
                ),
            )
        } as org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult
        assertEquals(3, counted.credentialCount)
        assertEquals(null, counted.transactionId)

        val thrown = runCatching {
            runBlocking {
                method.callSuspend(
                    wallet, "flow-w",
                    org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
                        action = "decrypt_credential_response", deferred = true,
                        jwe = issuerEncrypt(jwk, "ECDH-ES", "A256GCM", buildJsonObject { put("notification_id", JsonPrimitive("n-r")) }.toString()),
                    ),
                )
            }
        }.exceptionOrNull()
        assertTrue(unwrapped(thrown ?: throw AssertionError("expected a refusal")) is BlindIssuanceException)
        coVerify(exactly = 1) {
            peer.sendCredentialNotification(flowId = "flow-w", notificationId = "n-r", event = CredentialNotificationEvent.FAILURE, eventDescription = "credential_response_rejected")
        }
    }

    @Test
    fun aPlainDirectPostPresentation_isUnchangedOnBothTransports_evenWithAVerifiedRequest() = runTest(dispatcher) {
        val verifiedPlain = org.siros.sdk.transport.VerifiedRequest(clientId = "client-id-1", responseMode = "direct_post", responseUri = "https://v.example/r")
        // Legacy transport.
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signVpToken(any(), any(), any(), any(), any()) } returns "plain-vp-token"
        coEvery { keystore.signPresentation(any(), any(), any()) } returns "plain-vp-token"
        val cred = StoredCredential(id = 7L, format = "dc+sd-jwt", raw = "raw-sd-jwt", batchId = 1L, instanceId = 0)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to keystore,
            "credentialStore" to FakeCredentialStore(mutableListOf(cred)),
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-plain", messageId = "msg-plain", action = "sign_presentation",
                params = SignRequestParams(
                    audience = "admin", nonce = "n",
                    credentialsToInclude = listOf(org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pid", credentialId = "7")),
                    verifiedRequest = verifiedPlain,
                ),
            )
        )
        repeat(5) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            advanceUntilIdle()
        }
        verify(exactly = 1) { engine.sendSignResponse(flowId = "flow-plain", vpToken = "plain-vp-token", messageId = "msg-plain") }
        verify(exactly = 0) { engine.sendSignResponse(flowId = any(), responseJwe = any()) }
        // WMP transport.
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        val result = runBlocking {
            method.callSuspend(
                wallet, "flow-w",
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(action = "sign_presentation", nonce = "n", audience = "admin", verifiedRequest = verifiedPlain),
            )
        } as org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult
        assertEquals("plain-vp-token", result.vpToken)
        assertEquals(null, result.responseJwe)
    }

    @Test
    fun anEncryptedResponseForAModeThatIsNotDirectPostJwt_isRefusedOnBothTransports() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signPresentation(any(), any(), any()) } returns "vp"
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to keystore,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        for (mode in listOf("direct_post", "query", "fragment")) {
            val thrown = runCatching {
                runBlocking {
                    method.callSuspend(
                        wallet, "flow-w",
                        org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
                            action = "sign_presentation", nonce = "n", audience = "admin",
                            responseEncryption = blindResponseEncryption(),
                            verifiedRequest = org.siros.sdk.transport.VerifiedRequest(clientId = "c", responseMode = mode),
                        ),
                    )
                }
            }.exceptionOrNull()
            assertTrue(mode, unwrapped(thrown ?: throw AssertionError("expected a refusal for $mode")).message.orEmpty().contains("not direct_post.jwt"))
        }
    }

    // ---- review follow-ups: the response key and opened responses are released on every teardown, failure and end ----

    /** A holder with a key for two flows and a response opened for one of them. */
    private fun heldBlindIssuance(): BlindIssuance {
        val blind = BlindIssuance()
        val request = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false)
        val jwk = blind.offer("flow-a", request)!!
        blind.open("flow-a", issuerEncrypt(jwk, "ECDH-ES", "A256GCM", issuerBody("secret credential!").toString()), deferred = false)
        blind.offer("flow-b", request)
        return blind
    }

    private fun assertBlindEmpty(blind: BlindIssuance) {
        assertFalse(blind.holdsKey("flow-a"))
        assertFalse(blind.holdsKey("flow-b"))
        assertEquals("what was opened is gone too", null, blind.take("flow-a"))
    }

    @Test
    fun logout_clearsTheResponseKeysAndTheOpenedResponses() = runTest(dispatcher) {
        val blind = heldBlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "sessionStore" to mockk<SessionStore>(relaxed = true),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "blindIssuance" to blind,
        )
        wallet.logout()
        assertBlindEmpty(blind)
    }

    private fun recordedCommitment() = listOf(org.siros.sdk.credentials.HolderCommitment(listOf("psc"), "sha-256", true, ByteArray(32) { 7 }))

    @Test
    fun logout_dropsAndZeroesEveryRecordedHolderCommitment() = runTest(dispatcher) {
        val recorded = java.util.concurrent.ConcurrentHashMap<String, List<org.siros.sdk.credentials.HolderCommitment>>()
        val c = recordedCommitment()
        recorded["f1"] = c
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "sessionStore" to mockk<SessionStore>(relaxed = true),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "holderCommitmentsByFlow" to recorded,
        )
        wallet.logout()
        assertTrue(recorded.isEmpty())
        assertTrue("zeroed, not merely forgotten", c.single().commitment.all { it == 0.toByte() })
    }

    @Test
    fun cancellingAnIssuanceDropsAndZeroesItsRecordedHolderCommitments() = runTest(dispatcher) {
        val recorded = java.util.concurrent.ConcurrentHashMap<String, List<org.siros.sdk.credentials.HolderCommitment>>()
        val c = recordedCommitment()
        recorded["flow-x"] = c
        recorded["other"] = recordedCommitment()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.FlowActive(userId = "user-1", displayName = "Alice", flowId = "flow-x", flowType = "issuance", status = "s")),
            "engineSession" to mockk<WalletEngineSession>(relaxed = true),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "holderCommitmentsByFlow" to recorded,
        )
        wallet.cancelCurrentFlow()
        assertEquals(setOf("other"), recorded.keys)
        assertTrue(c.single().commitment.all { it == 0.toByte() })
    }

    @Test
    fun destroy_clearsTheResponseKeysAndTheOpenedResponses() = runTest(dispatcher) {
        val blind = heldBlindIssuance()
        val app = mockk<android.content.Context>(relaxed = true)
        val activity = mockk<android.app.Activity>(relaxed = true)
        every { activity.applicationContext } returns app
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "supervisorJob" to SupervisorJob(),
            "activity" to activity,
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "defaultCircuitZkProverHolder" to lazy<org.siros.sdk.keystore.CatalogCircuitZkProver> { error("not initialised") },
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "blindIssuance" to blind,
        )
        wallet.destroy()
        assertBlindEmpty(blind)
    }

    @Test
    fun aWmpGenerateProofThatFailsAfterTheKeyWasOffered_releasesTheFlowsKey() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateProof(any(), any(), any(), any()) } throws org.siros.sdk.credentials.KeystoreException("signing failed")
        coEvery { keystore.generateProof(any(), any(), any(), any(), any()) } throws org.siros.sdk.credentials.KeystoreException("signing failed")
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to keystore,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        val thrown = runCatching {
            runBlocking {
                method.callSuspend(
                    wallet, "flow-w",
                    org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
                        action = "generate_proof", nonce = "n", audience = "aud",
                        proofTypesSupported = buildJsonObject { putJsonObject("jwt") {} },
                        credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", true),
                    ),
                )
            }
        }.exceptionOrNull()
        assertTrue("the failure still reaches the profile", thrown != null)
        assertFalse("the private key of a failed request is released", blind.holdsKey("flow-w"))
    }

    @Test
    fun aWmpFlowError_releasesTheFlowsKeyAndOpenedResponseAndStillTellsTheListener() = runTest(dispatcher) {
        val blind = heldBlindIssuance()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "eventListener" to listener,
            "blindIssuance" to blind,
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "onWmpFlowError" }
        method.isAccessible = true
        runBlocking { method.callSuspend(wallet, "flow-a", "CREDENTIAL_ERROR", "boom") }
        assertFalse(blind.holdsKey("flow-a"))
        assertEquals(null, blind.take("flow-a"))
        assertTrue("another flow's key is not touched", blind.holdsKey("flow-b"))
        verify(exactly = 1) { listener.onFlowError("flow-a", "CREDENTIAL_ERROR: boom", any()) }
    }

    @Test
    fun aMalformedPlainWmpCompletion_isNeverReportedAsSuccess() = runTest(dispatcher) {
        val listener = mockk<WalletEventListener>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to org.siros.sdk.keystore.JweKeystore(),
            "eventListener" to listener,
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to BlindIssuance(),
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "onWmpFlowComplete" }
        method.isAccessible = true
        val malformed = Json.parseToJsonElement("""{"credentials":[{"format":"dc+sd-jwt"}]}""").jsonObject
        runBlocking { method.callSuspend(wallet, null, "flow-m", malformed) }
        verify(exactly = 0) { listener.onFlowComplete(any(), any()) }
        verify(exactly = 1) { listener.onFlowError("flow-m", any(), any()) }
    }

    @Test
    fun aRenewalWhoseReplacementIsRejectedOrUnreadable_leavesTheOldBatchInPlace() = runTest(dispatcher) {
        val old = listOf(storedCopy(id = 41L, batchId = 77L))
        // Plain, non-empty but unreadable: no replacement could be stored.
        val unreadable = deliveredScenario(
            listOf(deliveredResult(credential = "not-a-credential")),
            encrypted = false, preexisting = old, renewalSourceBatchId = 77L,
        )
        assertEquals(listOf(41L), unreadable.store.getAll().map { it.id })
        // Encrypted, but the wallet holds no response for it.
        val lost = deliveredScenario(listOf(deliveredResult()), lostResponse = true, preexisting = old, renewalSourceBatchId = 77L)
        assertEquals(listOf(41L), lost.store.getAll().map { it.id })
        // Encrypted, but the entry count differs from what the wallet opened.
        val mismatch = deliveredScenario(listOf(deliveredResult()), engineEntries = 2, preexisting = old, renewalSourceBatchId = 77L)
        assertEquals(listOf(41L), mismatch.store.getAll().map { it.id })
    }

    @Test
    fun aRenewalWhoseReplacementIsStored_stillSupersedesTheOldBatch() = runTest(dispatcher) {
        val s = deliveredScenario(
            listOf(deliveredResult(credential = NymTestCredentials.sdJwt(sscValues = emptyList()))),
            encrypted = false, preexisting = listOf(storedCopy(id = 41L, batchId = 77L)), renewalSourceBatchId = 77L,
        )
        val ids = s.store.getAll().map { it.id }
        assertEquals(1, ids.size)
        assertFalse("the superseded batch is gone", 41L in ids)
    }

    @Test
    fun aBufferedPlainCompletionAfterASocketReplacement_isStillRefusedAsADowngrade() = runTest(dispatcher) {
        // Controlled interleaving: a key was held for the flow, the socket was replaced (the sweep dropped the key), THEN the plaintext
        // completion that was buffered before the replacement is processed.
        val s = deliveredScenario(
            listOf(deliveredResult(credential = NymTestCredentials.sdJwt(sscValues = emptyList()))),
            encrypted = false, offeredKey = true, socketReplacedSinceOffer = true,
        )
        assertFalse("the sweep did drop the key", s.blind.holdsKey("flow-delivered"))
        assertNothingStored(s)
        verify(exactly = 1) { s.engine.sendCredentialNotification("flow-delivered", "notif-1", CredentialNotificationEvent.FAILURE, any()) }
        verify(exactly = 1) { s.listener.onFlowError("flow-delivered", match { it.contains("answered in clear") }, any()) }
        assertFalse("the marker ends with the flow", s.blind.wasOffered("flow-delivered"))
    }

    @Test
    fun aRepeatedPlaintextCompletionOfARefusedFlow_isIgnored_neverStoredAsAFreshOne() = runTest(dispatcher) {
        val s = deliveredScenario(
            listOf(deliveredResult(credential = NymTestCredentials.sdJwt(sscValues = emptyList()))),
            encrypted = false, offeredKey = true, repeatCompletion = true,
        )
        // The first plaintext completion was refused (a key was offered) and the flow is terminal; the repeat finds no marker any
        // more, so without the terminal-flow check it would be accepted as an ordinary plain completion and stored.
        assertNothingStored(s)
        verify(exactly = 1) { s.listener.onFlowError("flow-delivered", match { it.contains("answered in clear") }, any()) }
        verify(exactly = 1) { s.engine.sendCredentialNotification("flow-delivered", "notif-1", CredentialNotificationEvent.FAILURE, any()) }
    }

    @Test
    fun aRepeatedAcceptedCompletion_isNotStoredTwice() = runTest(dispatcher) {
        val s = deliveredScenario(
            listOf(deliveredResult(credential = NymTestCredentials.sdJwt(sscValues = emptyList()))),
            encrypted = false, repeatCompletion = true,
        )
        assertEquals(1, s.store.getAll().size)
        verify(exactly = 1) { s.listener.onFlowComplete("flow-delivered", any()) }
    }

    @Test
    fun aPlainCompletionForTheOldestFlowAfterCapacityPressure_isStillRefusedAndTheNewOfferIsTheOneRefused() = runTest(dispatcher) {
        val request = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false)
        val s = deliveredScenario(
            listOf(deliveredResult(credential = NymTestCredentials.sdJwt(sscValues = emptyList()))),
            encrypted = false, offeredKey = true, socketReplacedSinceOffer = true,
            beforeCompletion = { blind ->
                // Fill the table to capacity with other flows, then offer one more: THAT offer is refused, nothing is evicted.
                repeat(BlindIssuance.MAX_OFFERED_MARKERS - 1) { blind.offer("filler-$it", request, generation = 0) }
                org.junit.Assert.assertThrows(BlindIssuanceException::class.java) { blind.offer("one-too-many", request) }
                assertTrue("the oldest flow is still expected to be encrypted", blind.wasOffered("flow-delivered"))
            },
        )
        // Its plaintext completion is refused: nothing stored, the issuer told.
        assertNothingStored(s)
        verify(exactly = 1) { s.engine.sendCredentialNotification("flow-delivered", "notif-1", CredentialNotificationEvent.FAILURE, any()) }
        verify(exactly = 1) { s.listener.onFlowError("flow-delivered", match { it.contains("answered in clear") }, any()) }
    }

    @Test
    fun aBufferedPlainWmpCompletionAfterASocketReplacement_isStillRefusedAsADowngrade() = runTest(dispatcher) {
        val blind = BlindIssuance()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to org.siros.sdk.keystore.JweKeystore(),
            "eventListener" to listener,
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        blind.offer("flow-b", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false), generation = 0)
        blind.markStaleBefore(1)
        assertFalse(blind.holdsKey("flow-b"))
        val method = wallet::class.declaredMemberFunctions.first { it.name == "onWmpFlowComplete" }
        method.isAccessible = true
        runBlocking { method.callSuspend(wallet, null, "flow-b", Json.parseToJsonElement("""{"credentials":[{"format":"dc+sd-jwt","credential":"x"}]}""").jsonObject) }
        verify(exactly = 0) { listener.onFlowComplete("flow-b", any()) }
        verify(exactly = 1) { listener.onFlowError("flow-b", match { it.contains("answered in clear") }, any()) }
        assertFalse(blind.wasOffered("flow-b"))
    }

    @Test
    fun aWmpPlainCompletion_releasesTheKeyOfAnOptionalEncryptionOffer_andAnEncryptedOneStillReadsItsResponseFirst() = runTest(dispatcher) {
        val blind = heldBlindIssuance()
        val listener = mockk<WalletEventListener>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to org.siros.sdk.keystore.JweKeystore(),
            "eventListener" to listener,
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "onWmpFlowComplete" }
        method.isAccessible = true
        // flow-b: the issuer answered in clear although a key was offered.
        val plain = Json.parseToJsonElement("""{"credentials":[{"format":"dc+sd-jwt","credential":"x"}]}""").jsonObject
        runBlocking { method.callSuspend(wallet, null, "flow-b", plain) }
        assertFalse("a plain completion releases the key", blind.holdsKey("flow-b"))
        // ... and is an error, not a success: a key was offered.
        verify(exactly = 0) { listener.onFlowComplete("flow-b", any()) }
        verify(exactly = 1) { listener.onFlowError("flow-b", match { it.contains("answered in clear") }, any()) }
        // flow-a: an encrypted completion is processed against the opened response, and only then released.
        val encrypted = Json.parseToJsonElement("""{"credentials":[{"format":"dc+sd-jwt"}],"credential_response_encrypted":true}""").jsonObject
        runBlocking { method.callSuspend(wallet, null, "flow-a", encrypted) }
        verify(exactly = 1) { listener.onFlowComplete("flow-a", any()) }
        verify(exactly = 0) { listener.onFlowError("flow-a", any(), any()) }
        assertFalse(blind.holdsKey("flow-a"))
        assertEquals(null, blind.take("flow-a"))
    }

    @Test
    fun aLegacyPlainCompletion_releasesTheKeyOfAnOptionalEncryptionOffer() = runTest(dispatcher) {
        val s = deliveredScenario(
            listOf(deliveredResult(credential = NymTestCredentials.sdJwt(sscValues = emptyList()))),
            encrypted = false, offeredKey = true,
        )
        // A key was offered, so a plaintext completion is an ERROR and nothing is stored; the issuer is told.
        assertNothingStored(s)
        verify(exactly = 1) { s.engine.sendCredentialNotification("flow-delivered", "notif-1", CredentialNotificationEvent.FAILURE, any()) }
        verify(exactly = 1) { s.listener.onFlowError("flow-delivered", match { it.contains("answered in clear") }, any()) }
        assertFalse(s.blind.holdsKey("flow-delivered"))
    }

    @Test
    fun legacyGenerateProof_aRequiredEncryptionTheWalletCannotProvide_answersTheEngineWithAnErrorForThatMessage() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val listener = mockk<WalletEventListener>(relaxed = true)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "eventListener" to listener,
            "credentialStore" to FakeCredentialStore(mutableListOf()),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-enc", messageId = "msg-original", action = "generate_proof",
                params = SignRequestParams(
                    audience = "aud-1", nonce = "nonce-1",
                    credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("RSA-OAEP", "A128GCM", required = true),
                ),
            )
        )
        advanceUntilIdle()
        val error = slot<String>()
        verify(exactly = 1) { engine.sendSignResponse(flowId = "flow-enc", messageId = "msg-original", error = capture(error)) }
        assertTrue(error.captured, error.captured.contains("requires an encrypted credential response"))
        verify(exactly = 1) { listener.onFlowError("flow-enc", any(), any()) }
    }

    @Test
    fun legacyDecryptCredentialResponse_aJweThatDoesNotOpen_answersWithAnErrorAndEndsTheFlow() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val listener = mockk<WalletEventListener>(relaxed = true)
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "eventListener" to listener,
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        blind.offer("flow-d", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-d", messageId = "msg-d", action = "decrypt_credential_response",
                params = SignRequestParams(jwe = "not.a.valid.jwe.value"),
            )
        )
        advanceUntilIdle()

        val error = slot<String>()
        verify(exactly = 1) { engine.sendSignResponse(flowId = "flow-d", messageId = "msg-d", error = capture(error)) }
        assertFalse(error.captured.contains("not.a.valid.jwe.value"))
        verify(exactly = 1) { listener.onFlowError("flow-d", any(), any()) }
        assertFalse("the issuance is over, so is its key", blind.holdsKey("flow-d"))
    }

    @Test
    fun legacySignPresentation_overDirectPostJwt_answersWithTheEncryptedResponseAndNeverTheVpToken() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signVpToken(any(), any(), any(), any(), any()) } returns "secret vp token!"
        val cred = StoredCredential(id = 7L, format = "dc+sd-jwt", raw = "raw-sd-jwt", batchId = 1L, instanceId = 0)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to keystore,
            "credentialStore" to FakeCredentialStore(mutableListOf(cred)),
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-vp", messageId = "msg-vp", action = "sign_presentation",
                params = SignRequestParams(
                    // The admin-configured audience differs from the request's own client_id: the JARM aud is the latter.
                    audience = "admin-audience", nonce = "n", state = "st-9",
                    credentialsToInclude = listOf(org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pid", credentialId = "7")),
                    responseEncryption = blindResponseEncryption(),
                    verifiedRequest = org.siros.sdk.transport.VerifiedRequest(clientId = "client-id-1", clientIdScheme = "x509_san_dns", responseMode = "direct_post.jwt", responseUri = "https://verifier.example.com/response", signed = true, signatureVerification = "verified"),
                ),
            )
        )
        repeat(5) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            advanceUntilIdle()
        }

        val jwe = slot<String>()
        verify(exactly = 1) { engine.sendSignResponse(flowId = "flow-vp", messageId = "msg-vp", responseJwe = capture(jwe)) }
        verify(exactly = 0) { engine.sendSignResponse(any(), any(), vpToken = any(), proofs = any(), messageId = any()) }
        assertFalse(jwe.captured.contains("secret vp token!"))
        val claims = openJarm(jwe.captured)
        assertEquals("client-id-1", claims["aud"]!!.jsonPrimitive.content)
        assertEquals("st-9", claims["state"]!!.jsonPrimitive.content)
        assertEquals(
            JsonObject(mapOf("pid" to kotlinx.serialization.json.JsonArray(listOf(JsonPrimitive("secret vp token!"))))),
            claims["vp_token"],
        )
    }

    @Test
    fun legacySignPresentation_overDirectPostJwt_withoutAVerifiedClientId_buildsNothingAndRefusesLocally() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val listener = mockk<WalletEventListener>(relaxed = true)
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signVpToken(any(), any(), any(), any(), any()) } returns "secret vp token!"
        val cred = StoredCredential(id = 7L, format = "dc+sd-jwt", raw = "raw-sd-jwt", batchId = 1L, instanceId = 0)
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to keystore,
            "credentialStore" to FakeCredentialStore(mutableListOf(cred)),
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "eventListener" to listener,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        // `audience` is present but is not the request's validated client_id: nothing may be built from it.
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-vp", messageId = "msg-vp", action = "sign_presentation",
                params = SignRequestParams(
                    audience = "admin-audience", nonce = "n",
                    credentialsToInclude = listOf(org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pid", credentialId = "7")),
                    responseEncryption = blindResponseEncryption(),
                ),
            )
        )
        repeat(5) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            advanceUntilIdle()
        }

        verify(exactly = 0) { engine.sendSignResponse(any(), any(), responseJwe = any(), proofs = any(), messageId = any()) }
        verify(exactly = 0) { engine.sendSignResponse(any(), any(), vpToken = any(), proofs = any(), messageId = any()) }
        verify(exactly = 1) { listener.onFlowError("flow-vp", match { it.contains("no verified client_id") }, any()) }
    }

    @Test
    fun wmpSignPresentation_overDirectPostJwt_withoutAVerifiedClientId_isRefused() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signPresentation(any(), any(), any()) } returns "secret vp token!"
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to keystore,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        val thrown = runCatching {
            runBlocking {
                method.callSuspend(
                    wallet, "flow-w",
                    org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
                        action = "sign_presentation", nonce = "n", audience = "admin-audience",
                        responseEncryption = blindResponseEncryption(),
                    ),
                )
            }
        }.exceptionOrNull()
        assertTrue(thrown.toString(), unwrapped(thrown ?: throw AssertionError("expected a refusal")).message.orEmpty().contains("no verified client_id"))
    }

    @Test
    fun wmpGenerateProof_andDecryptCredentialResponse_carryTheSameAnswersAsTheLegacyTransport() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>()
        coEvery { keystore.generateProof(audience = "aud-1", nonce = "nonce-1", freshKey = any(), holderBinding = any()) } returns "proof-jwt"
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to keystore,
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "blindIssuance" to blind,
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true

        val proof = runBlocking {
            method.callSuspend(
                wallet, "flow-w",
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
                    action = "generate_proof", nonce = "nonce-1", audience = "aud-1",
                    credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false),
                ),
            )
        } as org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult
        val jwk = proof.credentialResponseEncryptionJwk!!
        assertEquals("enc", jwk["use"]!!.jsonPrimitive.content)
        assertFalse(jwk.containsKey("d"))
        assertTrue(blind.holdsKey("flow-w"))

        val jwe = issuerEncrypt(jwk, "ECDH-ES", "A256GCM", buildJsonObject { put("transaction_id", JsonPrimitive("tx-5")) }.toString())
        val opened = runBlocking {
            method.callSuspend(
                wallet, "flow-w",
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(action = "decrypt_credential_response", jwe = jwe, deferred = false),
            )
        } as org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult
        assertEquals("tx-5", opened.transactionId)
        assertEquals(null, opened.proofs)
    }

    @Test
    fun wmpDecryptCredentialResponse_aJweThatDoesNotOpen_isRefusedAndDropsTheKey() = runTest(dispatcher) {
        val blind = BlindIssuance()
        blind.offer("flow-w", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        val thrown = runCatching {
            runBlocking {
                method.callSuspend(
                    wallet, "flow-w",
                    org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(action = "decrypt_credential_response", jwe = "a.b.c.d.e"),
                )
            }
        }.exceptionOrNull()
        assertTrue(thrown.toString(), unwrapped(thrown ?: throw AssertionError("expected a refusal")) is BlindIssuanceException)
        assertFalse(blind.holdsKey("flow-w"))
    }

    @Test
    fun wmpSignPresentation_overDirectPostJwt_answersWithTheEncryptedResponse() = runTest(dispatcher) {
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signPresentation(any(), any(), any()) } returns "secret vp token!"
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to keystore,
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        val result = runBlocking {
            method.callSuspend(
                wallet, "flow-w",
                org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(
                    action = "sign_presentation", nonce = "n", audience = "admin-audience", state = "st-9",
                    credentialsToInclude = listOf(org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pid", credentialId = "7")),
                    responseEncryption = blindResponseEncryption(),
                    verifiedRequest = org.siros.sdk.transport.VerifiedRequest(clientId = "client-id-1", clientIdScheme = "x509_san_dns", responseMode = "direct_post.jwt", responseUri = "https://verifier.example.com/response", signed = true, signatureVerification = "verified"),
                ),
            )
        } as org.siros.sdk.transport.wmp.openid4x.SignSubFlowResult

        assertEquals(null, result.vpToken)
        val claims = openJarm(result.responseJwe!!)
        assertEquals("client-id-1", claims["aud"]!!.jsonPrimitive.content)
        assertEquals("st-9", claims["state"]!!.jsonPrimitive.content)
        assertEquals("secret vp token!", claims["vp_token"]!!.jsonObject["pid"]!!.jsonArray[0].jsonPrimitive.content)
    }

    @Test
    fun aPlainCompletion_storesTheRelayedDisplayMetadata_butNeverASeedTheEngineFrameCarries() = runTest(dispatcher) {
        val wire = """{"display":[{"name":"Nym"}],"org.siros.secret_seed":{"$deliveredNamespace":"${NymTestCredentials.seedHex}"},"claims":[{"path":["a"]}]}"""
        // The credential carries no commitment, so no seed is needed and the response is plain.
        val s = deliveredScenario(
            listOf(deliveredResult(credential = NymTestCredentials.sdJwt(sscValues = emptyList()))),
            encrypted = false, wireMetadata = wire,
        )
        val stored = s.keystore.getCredentialMetadata(s.store.getAll().single().id)!!
        assertEquals(listOf("display", "claims"), stored.map { it.jsonObject["type"]!!.jsonPrimitive.content })
        assertNoSecretIn(stored.toString())
        assertNoSecretIn(s.keystore.getCredential(s.store.getAll().single().id))
    }

    @Test
    fun aPlainCompletionCarryingOnlyASeed_deliversNoSeedAndIsRefusedWhenTheConfigurationAdvertisedOne() = runTest(dispatcher) {
        val wire = """{"org.siros.secret_seed":{"$deliveredNamespace":"${NymTestCredentials.seedHex}"}}"""
        // Advertised: the response had to be encrypted, and the frame's seed is not taken either way.
        val advertised = deliveredScenario(listOf(deliveredResult()), encrypted = false, advertised = true, wireMetadata = wire)
        assertNothingStored(advertised)
        // Not advertised: the credential needs a seed it never receives, so nothing is verified against a seed and no seed is kept.
        val plain = deliveredScenario(listOf(deliveredResult()), encrypted = false, wireMetadata = wire)
        for (c in plain.store.getAll()) {
            assertTrue(plain.keystore.getCredentialMetadata(c.id).orEmpty().isEmpty())
            assertNoSecretIn(plain.keystore.getCredential(c.id))
        }
    }

    @Test
    fun anEncryptedCompletion_ignoresAnyCredentialMetadataTheEngineFrameCarries() = runTest(dispatcher) {
        // The wallet decrypted {example.other}; the frame claims a different object, including a seed.
        val md = org.siros.sdk.transport.ResponseCredentialMetadata(buildJsonObject { put("example.other", JsonPrimitive("from-the-wallet")) })
        val wire = """{"display":[{"name":"from-the-engine"}],"org.siros.secret_seed":{"$deliveredNamespace":"${NymTestCredentials.seedHex}"}}"""
        val s = deliveredScenario(
            listOf(deliveredResult(credential = NymTestCredentials.sdJwt(sscValues = emptyList()))),
            metadata = md, wireMetadata = wire,
        )
        val stored = s.keystore.getCredentialMetadata(s.store.getAll().single().id)!!
        assertEquals(listOf("example.other"), stored.map { it.jsonObject["type"]!!.jsonPrimitive.content })
        assertNoSecretIn(stored.toString())
    }

    @Test
    fun anEncryptedCompletion_isFilledFromTheWalletsOwnResponse_andTheKeyIsGoneAfterwards() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult()))
        assertEquals(1, s.store.getAll().size)
        assertEquals(NymTestCredentials.sdJwt(), s.store.getAll().single().raw)
        assertFalse(s.blind.holdsKey("flow-delivered"))
    }

    @Test
    fun anEncryptedCompletionWhoseEntryCountDiffersFromTheOpenedResponse_isRefusedAndStoresNothing() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult()), engineEntries = 2)
        assertNothingStored(s)
        // The wallet's own notification_id still reaches the issuer, so the refusal can be reported.
        verify(exactly = 1) { s.engine.sendCredentialNotification(any(), "notif-1", CredentialNotificationEvent.FAILURE, any()) }
        assertFalse(s.blind.holdsKey("flow-delivered"))
    }

    @Test
    fun theResponseKeyIsDroppedWhenTheFlowFailsAndWhenTheConnectionIsReplaced() = runTest(dispatcher) {
        val flowErrors = MutableSharedFlow<FlowErrorMessage>()
        val engine = mockEngineConstructor(flowErrors = flowErrors)
        every { engine.disconnect() } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        val request = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false)
        blind.offer("flow-e", request)
        flowErrors.emit(FlowErrorMessage(flowId = "flow-e", error = FlowError(code = "CREDENTIAL_ERROR", message = "boom")))
        advanceUntilIdle()
        assertFalse("a failed flow forgets its key", blind.holdsKey("flow-e"))

        blind.offer("flow-f", request)
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        assertFalse("a replaced connection abandons its flows' keys", blind.holdsKey("flow-f"))
    }

    // ---- review round 2: notification ids, flow-scoped release, cancel, partial presentations, answered failures ----

    @Test
    fun anEncryptedCompletion_neverTakesTheFramesNotificationId_aMissingOneInTheResponseStaysMissing() = runTest(dispatcher) {
        // The decrypted response carries a seed but no notification_id; the engine frame supplies one. It must not stand in.
        val s = deliveredScenario(listOf(deliveredResult(notificationId = null)), frameNotificationId = "frame-n")
        assertNothingStored(s)
        verify(exactly = 0) { s.engine.sendCredentialNotification(any(), "frame-n", any(), any()) }
        val message = slot<String>()
        verify(exactly = 1) { s.listener.onFlowError("flow-delivered", capture(message), any()) }
        assertTrue(message.captured, message.captured.contains("could not be notified"))
    }

    @Test
    fun anEncryptedCompletion_aConflictingFrameNotificationIdIsIgnored_theDecryptedOneIsReported() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult(credential = wrongSscCredential())), frameNotificationId = "frame-evil")
        assertNothingStored(s)
        verify(exactly = 1) { s.engine.sendCredentialNotification("flow-delivered", "notif-1", CredentialNotificationEvent.FAILURE, any()) }
        verify(exactly = 0) { s.engine.sendCredentialNotification(any(), "frame-evil", any(), any()) }
    }

    @Test
    fun anEncryptedCompletion_anEmptyFrameNotificationIdIsIgnored_andTheDecryptedOneIsUsed() = runTest(dispatcher) {
        val s = deliveredScenario(listOf(deliveredResult()), frameNotificationId = "")
        assertEquals(1, s.store.getAll().size)
        verify(exactly = 1) { s.engine.sendCredentialNotification("flow-delivered", "notif-1", CredentialNotificationEvent.ACCEPTED, any()) }
    }

    @Test
    fun aPlainCompletionKeepsTheNotificationIdTheEngineSupplied() = runTest(dispatcher) {
        val s = deliveredScenario(
            listOf(deliveredResult(credential = NymTestCredentials.sdJwt(sscValues = emptyList()), notificationId = "plain-n")),
            encrypted = false,
        )
        assertEquals(1, s.store.getAll().size)
        verify(exactly = 1) { s.engine.sendCredentialNotification("flow-delivered", "plain-n", CredentialNotificationEvent.ACCEPTED, any()) }
    }

    @Test
    fun wmpEncryptedCompletion_neverTakesTheFramesNotificationId() = runTest(dispatcher) {
        val flowId = "flow-wmp"
        fun walletHolding(notificationInBody: String?): SirosWallet {
            val blind = BlindIssuance()
            val jwk = blind.offer(flowId, org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A128GCM", false))!!
            val body = buildJsonObject {
                put("credentials", kotlinx.serialization.json.JsonArray(listOf(buildJsonObject { put("credential", JsonPrimitive(NymTestCredentials.sdJwt())) })))
                notificationInBody?.let { put("notification_id", JsonPrimitive(it)) }
                put("credential_metadata", buildJsonObject { put(deliveredMember, buildJsonObject { put(deliveredNamespace, JsonPrimitive(NymTestCredentials.seedHex)) }) })
            }
            blind.open(flowId, issuerEncrypt(jwk, "ECDH-ES", "A128GCM", body.toString()), deferred = false)
            return newWallet(
                "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
                "keystore" to org.siros.sdk.keystore.JweKeystore(),
                "blindIssuance" to blind,
            )
        }
        fun frame(id: String?) = Json.parseToJsonElement(
            """{"credentials":[{"format":"dc+sd-jwt"${id?.let { ""","notification_id":"$it"""" } ?: ""}}],"credential_response_encrypted":true}""",
        ).jsonObject
        // Missing in the response, supplied by the frame: refused as having no notification_id, the frame's id unused.
        val missing = walletHolding(null).wmpDeliveredMetadataRefusal(flowId, frame("frame-n"))!!
        assertEquals(DeliveredMetadataRefusal.NO_NOTIFICATION_ID, missing.first)
        assertEquals(emptyList<String>(), missing.second)
        // Conflicting: the decrypted id is the one reported.
        val conflicting = walletHolding("decrypted-n").wmpDeliveredMetadataRefusal(flowId, frame("frame-evil"))
        assertEquals(null, conflicting)
        // Empty in the frame: ignored.
        assertEquals(null, walletHolding("decrypted-n").wmpDeliveredMetadataRefusal(flowId, frame("")))
        // A refusal reports the decrypted id, whatever the frame said.
        val refused = walletHolding("decrypted-n").wmpDeliveredMetadataRefusal(flowId, Json.parseToJsonElement(
            """{"credentials":[{"format":"mso_mdoc","notification_id":"frame-evil"}],"credential_response_encrypted":true}""",
        ).jsonObject)!!
        assertEquals(listOf("decrypted-n"), refused.second)
    }

    @Test
    fun aPresentationEndingNeverReleasesAnotherFlowsIssuanceKeyAndOpenedResponse() = runTest(dispatcher) {
        // An unrelated plain completion (a presentation, say) goes through the global issuance reset.
        val s = deliveredScenario(
            listOf(deliveredResult(credential = NymTestCredentials.sdJwt(sscValues = emptyList()))),
            encrypted = false, bystander = true,
        )
        assertTrue("the other flow keeps its key", s.blind.holdsKey("flow-other"))
        assertEquals(listOf("bystander credential"), s.blind.take("flow-other")!!.credentials)
    }

    @Test
    fun aPresentationSignFailureNeverReleasesAnotherFlowsIssuanceKeyAndOpenedResponse() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signPresentation(any(), any(), any()) } throws org.siros.sdk.credentials.KeystoreException("no key")
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to keystore,
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "lastTrustResults" to mutableMapOf<String, TrustResult>(),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        // Opened after connecting: a new connection drops the keys of the flows of the one it replaces.
        val other = blind.offer("flow-other", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))!!
        blind.open("flow-other", issuerEncrypt(other, "ECDH-ES", "A256GCM", issuerBody("bystander credential").toString()), deferred = false)
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-p", messageId = "msg-p", action = "sign_presentation",
                params = SignRequestParams(audience = "https://verifier.example.com", nonce = "n"),
            )
        )
        repeat(5) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            advanceUntilIdle()
        }
        assertTrue("the failure of the presentation flow reached the failure path", wallet.state.value is WalletState.Ready)
        assertTrue(blind.holdsKey("flow-other"))
        assertEquals(listOf("bystander credential"), blind.take("flow-other")!!.credentials)
    }

    @Test
    fun aWmpCancel_releasesThatFlowsKeyAndOpenedResponseOnly() = runTest(dispatcher) {
        val blind = heldBlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "blindIssuance" to blind,
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "onWmpFlowCancel" }
        method.isAccessible = true
        // flow-b holds only a key (cancelled after key generation); flow-a also an opened response (after decryption).
        method.call(wallet, "flow-b")
        assertFalse(blind.holdsKey("flow-b"))
        assertTrue("another flow is untouched", blind.holdsKey("flow-a"))
        method.call(wallet, "flow-a")
        assertFalse(blind.holdsKey("flow-a"))
        assertEquals(null, blind.take("flow-a"))
    }

    @Test
    fun theWalletsWmpProfile_releasesAFlowsKeyWhenTheOrchestratorCancelsIt() = runTest(dispatcher) {
        val blind = heldBlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "blindIssuance" to blind,
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "wmpProfile" }
        method.isAccessible = true
        val profile = method.call(wallet, null) as org.siros.sdk.transport.wmp.openid4x.OpenID4xProfile
        runBlocking {
            profile.handleCancel(org.siros.sdk.transport.wmp.FlowCancelParams(flowId = "flow-a", reason = "user"))
        }
        assertFalse(blind.holdsKey("flow-a"))
        assertEquals(null, blind.take("flow-a"))
        assertTrue("another flow is untouched", blind.holdsKey("flow-b"))
    }

    @Test
    fun aFailedReauthentication_stillReleasesTheIssuanceMaterialOfTheEndedSession() = runTest(dispatcher) {
        val blind = heldBlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "blindIssuance" to blind,
        )
        val method = wallet::class.declaredMemberFunctions.first { it.name == "reloginAfterCutOff" }
        method.isAccessible = true
        // The teardown is cut short here (no token store in this fixture), as a login that ends in an error leaves nothing to
        // replace the old connection: the holder must already be empty.
        runCatching { runBlocking { method.callSuspend(wallet, 0) } }
        assertBlindEmpty(blind)
    }

    @Test
    fun aSocketReplacedOnTheSameSession_dropsTheAbandonedFlowsKey_keepsWhatItOpenedForAGraceOnly() = runTest(dispatcher) {
        val state = MutableStateFlow(WalletEngineSession.State.CONNECTED)
        val generations = MutableStateFlow(0)
        val engine = mockEngineConstructor(state = state, generations = generations)
        val blind = BlindIssuance(clock = { dispatcher.scheduler.currentTime })
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        val request = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false)
        val jwk = blind.offer("flow-a", request, engine.connectionGeneration)!!
        blind.open("flow-a", issuerEncrypt(jwk, "ECDH-ES", "A256GCM", issuerBody("buffered credential").toString()), deferred = false)
        blind.offer("flow-b", request, engine.connectionGeneration)
        // The SAME session object gets a new socket (forceReconnect() or an automatic reconnect): none is constructed.
        engineGeneration.incrementAndGet()
        generations.value = engineGeneration.get()
        dispatcher.scheduler.runCurrent()
        assertFalse("the abandoned flow's private key is gone", blind.holdsKey("flow-a"))
        assertFalse(blind.holdsKey("flow-b"))
        // A completion buffered before the replacement still finds what its flow opened...
        // ...but only within the grace.
        dispatcher.scheduler.advanceTimeBy(SirosWallet.BLIND_STALE_GRACE_MS + 1)
        dispatcher.scheduler.runCurrent()
        assertEquals("forgotten after the grace", null, blind.take("flow-a"))
    }

    @Test
    fun anAutomaticReconnect_isNoticedWhenItsGenerationIsIncrementedAfterTheBackoff_withNoFurtherStateChange() = runTest(dispatcher) {
        val state = MutableStateFlow(WalletEngineSession.State.CONNECTED)
        val generations = MutableStateFlow(0)
        val engine = mockEngineConstructor(state = state, generations = generations)
        val blind = BlindIssuance(clock = { dispatcher.scheduler.currentTime })
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        blind.offer("flow-a", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false), engine.connectionGeneration)
        // Production order: RECONNECTING is published BEFORE the backoff, the generation is incremented when the new socket
        // opens, and nothing is published on the state afterwards.
        state.value = WalletEngineSession.State.RECONNECTING
        dispatcher.scheduler.runCurrent()
        dispatcher.scheduler.advanceTimeBy(5_000)
        dispatcher.scheduler.runCurrent()
        assertTrue("nothing is replaced yet: the old socket's flow still has its key", blind.holdsKey("flow-a"))
        engineGeneration.incrementAndGet()
        generations.value = engineGeneration.get()
        dispatcher.scheduler.runCurrent()
        assertFalse("the replacement is noticed without another state change", blind.holdsKey("flow-a"))
    }

    @Test
    fun aRegistrationOrLoginThatBumpsTheSessionGenerationAfterConnectingStillServesWmpSignRequests_andRefusesAfterLogoutOrDestroy() = runTest(dispatcher) {
        for (ending in listOf<(SirosWallet) -> Unit>({ it.logout() }, { it.destroy() })) {
            val blind = BlindIssuance()
            val peer = mockk<org.siros.sdk.transport.wmp.WmpPeer>(relaxed = true)
            val profileSlot = slot<org.siros.sdk.transport.wmp.WmpProfile>()
            every { peer.use(capture(profileSlot)) } just runs
            val previous = SirosWallet.createWmpPeer
            SirosWallet.createWmpPeer = { peer }
            try {
                val wallet = newWallet(
                    "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
                    "scope" to CoroutineScope(dispatcher + SupervisorJob()),
                    "supervisorJob" to SupervisorJob(),
                    "keystore" to mockk<KeystoreManager>(relaxed = true),
                    "sessionStore" to mockk<SessionStore>(relaxed = true),
                    "activity" to mockk<android.app.Activity>(relaxed = true).also { every { it.applicationContext } returns mockk(relaxed = true) },
                    "defaultCircuitZkProverHolder" to lazy<org.siros.sdk.keystore.CatalogCircuitZkProver> { error("not initialised") },
                    "legacyAppToken" to "app-token",
                    "config" to WalletConfig(backendUrl = "https://wallet.example.com", engineUrl = "https://engine.example.com", useWmpProtocol = true),
                    "blindIssuance" to blind,
                )
                // The path registration and login take: connect the engine, THEN end the previous session generation.
                val connect = wallet::class.declaredMemberFunctions.first { it.name == "connectEngineForNewSession" }
                connect.isAccessible = true
                runBlocking { connect.callSuspend(wallet) }
                val profile = profileSlot.captured as org.siros.sdk.transport.wmp.openid4x.OpenID4xProfile
                val ctx = RecordingPeerContext()
                profile.init(ctx)

                runBlocking { profile.handleProgress(wmpKeyOnlyRequest()) }
                assertTrue("a sign request of the live session is served", blind.holdsKey("flow-late"))
                assertTrue(ctx.notifications.any { it.second?.containsKey("credential_response_encryption_jwk") == true })

                ending(wallet)
                val after = RecordingPeerContext()
                profile.init(after)
                blind.offer("x", null)
                runBlocking {
                    profile.handleProgress(wmpKeyOnlyRequest().copy(flowId = "flow-after"))
                }
                assertFalse("after logout or destroy the same peer's request is refused", blind.holdsKey("flow-after"))
                assertTrue(after.notifications.none { it.second?.containsKey("credential_response_encryption_jwk") == true })
            } finally {
                SirosWallet.createWmpPeer = previous
            }
        }
    }

    @Test
    fun aLoginOnTheLegacyTransportStillServesSignRequestsAfterTheGenerationBump() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "legacyAppToken" to "app-token",
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "blindIssuance" to blind,
        )
        val connect = wallet::class.declaredMemberFunctions.first { it.name == "connectEngineForNewSession" }
        connect.isAccessible = true
        runBlocking { connect.callSuspend(wallet) }
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-k", messageId = "m", action = "generate_proof",
                params = SignRequestParams(credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", true)),
            )
        )
        advanceUntilIdle()
        assertTrue(blind.holdsKey("flow-k"))
        verify(exactly = 1) { engine.sendSignResponse("flow-k", messageId = "m", credentialRequestExtras = any(), credentialResponseEncryptionJwk = any()) }
    }

    @Test
    fun aKeyOfferedByTheLegacyHandler_isTiedToTheSocketItWasOfferedOn() = runTest(dispatcher) {
        val state = MutableStateFlow(WalletEngineSession.State.CONNECTED)
        val generations = MutableStateFlow(0)
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow, state = state, generations = generations)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-k", messageId = "m", action = "generate_proof",
                params = SignRequestParams(credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", true)),
            )
        )
        advanceUntilIdle()
        assertTrue(blind.holdsKey("flow-k"))
        engineGeneration.incrementAndGet()
        generations.value = engineGeneration.get()
        dispatcher.scheduler.runCurrent()
        assertFalse("the new socket abandons the flow of the old one", blind.holdsKey("flow-k"))
    }

    @Test
    fun aSocketReplacedOnTheSameSession_leavesABufferedCompletionItsOpenedResponseWithinTheGrace() = runTest(dispatcher) {
        val state = MutableStateFlow(WalletEngineSession.State.CONNECTED)
        val generations = MutableStateFlow(0)
        val engine = mockEngineConstructor(state = state, generations = generations)
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        val jwk = blind.offer("flow-a", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false), engine.connectionGeneration)!!
        blind.open("flow-a", issuerEncrypt(jwk, "ECDH-ES", "A256GCM", issuerBody("buffered credential").toString()), deferred = false)
        engineGeneration.incrementAndGet()
        generations.value = engineGeneration.get()
        dispatcher.scheduler.runCurrent()
        assertFalse(blind.holdsKey("flow-a"))
        assertEquals(listOf("buffered credential"), blind.take("flow-a")!!.credentials)
    }

    // ---- review round 4: ended sessions allocate nothing; the peer is really closed; obsolete socket requests are dropped ----

    private class RecordingPeerContext : org.siros.sdk.transport.wmp.WmpPeerContext {
        override val codec = org.siros.sdk.transport.wmp.WmpCodec()
        val notifications = mutableListOf<Pair<String, JsonObject?>>()
        override suspend fun notify(method: String, params: JsonObject?) { notifications += method to params }
        override suspend fun call(method: String, params: JsonObject?) = org.siros.sdk.transport.wmp.JsonRpcResponse(id = null)
    }

    private fun wmpKeyOnlyRequest() = org.siros.sdk.transport.wmp.FlowProgressParams(
        flowId = "flow-late", step = "sign_request",
        payload = buildJsonObject {
            put("action", JsonPrimitive("generate_proof"))
            put("credential_response_encryption", buildJsonObject { put("alg", JsonPrimitive("ECDH-ES")); put("enc", JsonPrimitive("A256GCM")); put("required", JsonPrimitive(true)) })
        },
    )

    private fun endedSessionWallet(blind: BlindIssuance, peer: org.siros.sdk.transport.wmp.WmpPeer? = null): SirosWallet = newWallet(
        "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
        "scope" to CoroutineScope(dispatcher + SupervisorJob()),
        "supervisorJob" to SupervisorJob(),
        "keystore" to mockk<KeystoreManager>(relaxed = true),
        "sessionStore" to mockk<SessionStore>(relaxed = true),
        "activity" to mockk<android.app.Activity>(relaxed = true).also { every { it.applicationContext } returns mockk(relaxed = true) },
        "defaultCircuitZkProverHolder" to lazy<org.siros.sdk.keystore.CatalogCircuitZkProver> { error("not initialised") },
        "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        "blindIssuance" to blind,
    ).also { w -> if (peer != null) { val f = SirosWallet::class.java.getDeclaredField("wmpPeer"); f.isAccessible = true; f.set(w, peer) } }

    @Test
    fun logout_reallyClosesTheWmpPeer_notWhateverTheFieldHoldsAfterwards() = runTest(dispatcher) {
        val peer = mockk<org.siros.sdk.transport.wmp.WmpPeer>(relaxed = true)
        val wallet = endedSessionWallet(BlindIssuance(), peer)
        wallet.logout()
        coVerify(exactly = 1, timeout = 3000) { peer.close(any()) }
    }

    @Test
    fun destroy_closesTheWmpPeerEvenThoughItCancelsTheWalletsOwnScope() = runTest(dispatcher) {
        val peer = mockk<org.siros.sdk.transport.wmp.WmpPeer>(relaxed = true)
        val wallet = endedSessionWallet(BlindIssuance(), peer)
        wallet.destroy()
        coVerify(exactly = 1, timeout = 3000) { peer.close(any()) }
    }

    @Test
    fun aKeyOnlyRequestArrivingOverWmpAfterLogoutOrDestroy_allocatesNothing() = runTest(dispatcher) {
        for (teardown in listOf<(SirosWallet) -> Unit>({ it.logout() }, { it.destroy() })) {
            val blind = BlindIssuance()
            val wallet = endedSessionWallet(blind)
            val method = wallet::class.declaredMemberFunctions.first { it.name == "wmpProfile" }
            method.isAccessible = true
            // The profile (and so the callbacks the peer would still deliver to) was built while the session was live.
            val profile = method.call(wallet, null) as org.siros.sdk.transport.wmp.openid4x.OpenID4xProfile
            val ctx = RecordingPeerContext()
            profile.init(ctx)
            teardown(wallet)
            runBlocking { profile.handleProgress(wmpKeyOnlyRequest()) }
            assertFalse("no key is generated for an ended session", blind.holdsKey("flow-late"))
            assertTrue("the request is answered with a flow error", ctx.notifications.isNotEmpty())
            assertTrue(ctx.notifications.none { it.second?.containsKey("credential_response_encryption_jwk") == true })
        }
    }

    @Test
    fun aKeyOnlyRequestArrivingOverTheLegacyTransportAfterLogout_allocatesNothingAndIsNotAnswered() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.disconnect() } just runs
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = endedSessionWallet(blind)
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        wallet.logout()
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-late", messageId = "m", action = "generate_proof",
                params = SignRequestParams(credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", true)),
            )
        )
        advanceUntilIdle()
        assertFalse(blind.holdsKey("flow-late"))
        verify(exactly = 0) { engine.sendSignResponse(flowId = "flow-late") }
    }

    @Test
    fun aSignRequestOfAReplacedSocketProcessedAfterTheSweep_getsNoKeyAndNoAnswer_aCurrentOneDoes() = runTest(dispatcher) {
        val state = MutableStateFlow(WalletEngineSession.State.CONNECTED)
        val generations = MutableStateFlow(0)
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow, state = state, generations = generations)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        // The socket is replaced and the sweep has run, THEN a request stamped with the old socket is processed (the channel is buffered).
        engineGeneration.incrementAndGet()
        generations.value = engineGeneration.get()
        dispatcher.scheduler.runCurrent()
        val encryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", true)
        signFlow.emit(
            SignRequestMessage(flowId = "flow-old", messageId = "m-old", action = "generate_proof", params = SignRequestParams(credentialResponseEncryption = encryption))
                .also { it.connectionGeneration = 0 },
        )
        advanceUntilIdle()
        assertFalse("no key is allocated for a replaced socket's request", blind.holdsKey("flow-old"))
        verify(exactly = 0) { engine.sendSignResponse(flowId = "flow-old") }
        // One of the current socket is served and tied to it.
        signFlow.emit(
            SignRequestMessage(flowId = "flow-new", messageId = "m-new", action = "generate_proof", params = SignRequestParams(credentialResponseEncryption = encryption))
                .also { it.connectionGeneration = engine.connectionGeneration },
        )
        advanceUntilIdle()
        assertTrue(blind.holdsKey("flow-new"))
    }

    @Test
    fun aWmpCallbackPausedBetweenItsLivenessCheckAndTheKeyClaim_retainsNothingAfterTeardown() = runTest(dispatcher) {
        for (teardown in listOf<(SirosWallet) -> Unit>({ it.logout() }, { it.destroy() })) {
            val paused = java.util.concurrent.CountDownLatch(1)
            val release = java.util.concurrent.CountDownLatch(1)
            val blind = BlindIssuance()
            val wallet = endedSessionWallet(blind)
            wallet.signDispatchHook = { paused.countDown(); release.await() }
            val method = wallet::class.declaredMemberFunctions.first { it.name == "wmpProfile" }
            method.isAccessible = true
            val profile = method.call(wallet, null) as org.siros.sdk.transport.wmp.openid4x.OpenID4xProfile
            val ctx = RecordingPeerContext()
            profile.init(ctx)
            // The callback passes its liveness check and stops just before it claims the flow's state.
            val running = java.util.concurrent.Executors.newSingleThreadExecutor().submit { runBlocking { profile.handleProgress(wmpKeyOnlyRequest()) } }
            assertTrue(paused.await(5, java.util.concurrent.TimeUnit.SECONDS))
            teardown(wallet)
            release.countDown()
            running.get(5, java.util.concurrent.TimeUnit.SECONDS)
            assertFalse("the teardown is not undone by the late claim", blind.holdsKey("flow-late"))
            assertEquals(null, blind.take("flow-late"))
            assertTrue("no key is answered", ctx.notifications.none { it.second?.containsKey("credential_response_encryption_jwk") == true })
        }
    }

    @Test
    fun aLegacyRequestPausedBetweenItsGuardAndTheKeyClaim_retainsNothingAfterLogout_andIsNotAnswered() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.disconnect() } just runs
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val paused = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "scope" to CoroutineScope(Dispatchers.IO + SupervisorJob()),
            "supervisorJob" to SupervisorJob(),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "sessionStore" to mockk<SessionStore>(relaxed = true),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        wallet.signDispatchHook = { paused.countDown(); release.await() }
        invokeConnectEngine(wallet, "app-token")
        runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(200) }
        val emitter = kotlinx.coroutines.GlobalScope.launch(Dispatchers.Default) {
            signFlow.emit(
                SignRequestMessage(
                    flowId = "flow-late", messageId = "m", action = "generate_proof",
                    params = SignRequestParams(credentialResponseEncryption = org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", true)),
                )
            )
        }
        assertTrue(paused.await(5, java.util.concurrent.TimeUnit.SECONDS))
        wallet.logout()
        release.countDown()
        runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(300) }
        emitter.cancel()
        assertFalse("the logout is not undone by the late claim", blind.holdsKey("flow-late"))
        verify(exactly = 0) { engine.sendSignResponse(flowId = "flow-late", messageId = any(), error = any()) }
        verify(exactly = 0) { engine.sendSignResponse(flowId = "flow-late", messageId = any(), credentialResponseEncryptionJwk = any()) }
    }

    @Test
    fun aPendingDeferredResponseCarryingASeed_isReportedToTheIssuerOnBothTransports() = runTest(dispatcher) {
        val seedBody = """{"transaction_id":"tx","interval":5,"notification_id":"n-seed","credential_metadata":{"org.siros.secret_seed":{"$deliveredNamespace":"${NymTestCredentials.seedHex}"}}}"""
        // Legacy transport.
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        every { engine.sendCredentialNotification(any(), any(), any(), any()) } just runs
        val blind = BlindIssuance()
        val wallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Disconnected()),
            "scope" to CoroutineScope(dispatcher + SupervisorJob()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "blindIssuance" to blind,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        val jwk = blind.offer("flow-d", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))!!
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-d", messageId = "msg-d", action = "decrypt_credential_response",
                params = SignRequestParams(jwe = issuerEncrypt(jwk, "ECDH-ES", "A256GCM", seedBody), deferred = true),
            )
        )
        advanceUntilIdle()
        io.mockk.verifyOrder {
            engine.sendCredentialNotification("flow-d", "n-seed", CredentialNotificationEvent.FAILURE, "credential_response_rejected")
            engine.sendSignResponse(flowId = "flow-d", messageId = "msg-d", error = any())
        }
        verify(exactly = 0) { engine.sendSignResponse(flowId = "flow-d", messageId = "msg-d", transactionId = any(), interval = any()) }
        // WMP transport.
        val peer = mockk<org.siros.sdk.transport.wmp.WmpPeer>(relaxed = true)
        val wmpBlind = BlindIssuance()
        val wmpWallet = newWallet(
            "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
            "keystore" to mockk<KeystoreManager>(relaxed = true),
            "credentialStore" to FakeCredentialStore(mutableListOf()),
            "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
            "wmpPeer" to peer,
            "blindIssuance" to wmpBlind,
        )
        val method = wmpWallet::class.declaredMemberFunctions.first { it.name == "handleWmpSignRequest" }
        method.isAccessible = true
        val wjwk = wmpBlind.offer("flow-w", org.siros.sdk.transport.CredentialResponseEncryptionRequest("ECDH-ES", "A256GCM", false))!!
        val thrown = runCatching {
            runBlocking {
                method.callSuspend(
                    wmpWallet, "flow-w",
                    org.siros.sdk.transport.wmp.openid4x.SignSubFlowParams(action = "decrypt_credential_response", deferred = true, jwe = issuerEncrypt(wjwk, "ECDH-ES", "A256GCM", seedBody)),
                )
            }
        }.exceptionOrNull()
        assertTrue(unwrapped(thrown ?: throw AssertionError("expected a refusal")) is BlindIssuanceException)
        coVerify(exactly = 1) {
            peer.sendCredentialNotification(flowId = "flow-w", notificationId = "n-seed", event = CredentialNotificationEvent.FAILURE, eventDescription = "credential_response_rejected")
        }
    }

    private fun legacyEncryptedPresentationWallet(
        credentials: List<StoredCredential>,
        keystore: KeystoreManager,
        listener: WalletEventListener,
    ): SirosWallet = newWallet(
        "_state" to MutableStateFlow<WalletState>(WalletState.Ready(userId = "user-1", displayName = "Alice")),
        "scope" to CoroutineScope(dispatcher + SupervisorJob()),
        "keystore" to keystore,
        "credentialStore" to FakeCredentialStore(credentials.toMutableList()),
        "lastTrustResults" to mutableMapOf<String, TrustResult>(),
        "config" to WalletConfig(backendUrl = "https://wallet.example.com"),
        "eventListener" to listener,
    )

    @Test
    fun legacySignPresentation_overDirectPostJwt_aSelectedCredentialThatIsGone_isNeverPresentedPartially() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val listener = mockk<WalletEventListener>(relaxed = true)
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signVpToken(any(), any(), any(), any(), any()) } returns "secret vp token!"
        val wallet = legacyEncryptedPresentationWallet(
            listOf(StoredCredential(id = 7L, format = "dc+sd-jwt", raw = "raw", batchId = 1L, instanceId = 0)), keystore, listener,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-vp", messageId = "msg-vp", action = "sign_presentation",
                params = SignRequestParams(
                    audience = "admin", nonce = "n", state = "st",
                    // Credential 8 is no longer in the store.
                    credentialsToInclude = listOf(
                        org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pid", credentialId = "7"),
                        org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "age", credentialId = "8"),
                    ),
                    responseEncryption = blindResponseEncryption(),
                    verifiedRequest = org.siros.sdk.transport.VerifiedRequest(clientId = "client-id-1", responseMode = "direct_post.jwt"),
                ),
            )
        )
        repeat(5) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            advanceUntilIdle()
        }
        verify(exactly = 0) { engine.sendSignResponse(flowId = any(), responseJwe = any()) }
        verify(exactly = 0) { engine.sendSignResponse(flowId = any(), vpToken = any()) }
        val error = slot<String>()
        verify(exactly = 1) { engine.sendSignResponse(flowId = "flow-vp", messageId = "msg-vp", error = capture(error)) }
        assertFalse("the answer names no credential or token", error.captured.contains("secret vp token!") || error.captured.contains("raw"))
        verify(exactly = 1) { listener.onFlowError("flow-vp", any(), any()) }
    }

    @Test
    fun legacySignPresentation_overDirectPostJwt_aFailureBuildingTheResponse_isAnsweredBeforeLocalCleanup_andNeverFallsBackToPlain() = runTest(dispatcher) {
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        val listener = mockk<WalletEventListener>(relaxed = true)
        val keystore = mockk<KeystoreManager>(relaxed = true)
        coEvery { keystore.signVpToken(any(), any(), any(), any(), any()) } returns "secret vp token!"
        val wallet = legacyEncryptedPresentationWallet(
            listOf(StoredCredential(id = 7L, format = "dc+sd-jwt", raw = "raw", batchId = 1L, instanceId = 0)), keystore, listener,
        )
        invokeConnectEngine(wallet, "app-token")
        advanceUntilIdle()
        // No verified_request: the audience of the response cannot be established.
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-vp", messageId = "msg-vp", action = "sign_presentation",
                params = SignRequestParams(
                    audience = "admin", nonce = "n",
                    credentialsToInclude = listOf(org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pid", credentialId = "7")),
                    responseEncryption = blindResponseEncryption(),
                ),
            )
        )
        repeat(5) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            advanceUntilIdle()
        }
        io.mockk.verifyOrder {
            engine.sendSignResponse(flowId = "flow-vp", messageId = "msg-vp", error = any())
            listener.onFlowError("flow-vp", any(), any())
        }
        verify(exactly = 0) { engine.sendSignResponse(flowId = any(), vpToken = any()) }
        verify(exactly = 0) { engine.sendSignResponse(flowId = any(), responseJwe = any()) }
    }

    @Test
    fun scaEngine_overDirectPostJwt_aFailureBuildingTheResponse_isAnsweredBeforeLocalCleanup() = runTest(dispatcher) {
        val fx = scaFixture()
        val signFlow = MutableSharedFlow<SignRequestMessage>()
        val engine = mockEngineConstructor(signRequests = signFlow)
        every { engine.sendSignResponse(any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()) } just runs
        invokeConnectEngine(fx.wallet, "app-token")
        dispatcher.scheduler.advanceUntilIdle()
        signFlow.emit(
            SignRequestMessage(
                flowId = "flow-sca", messageId = "m1", action = "sign_presentation",
                params = SignRequestParams(
                    audience = "x509_san_dns:shop.example.com", nonce = "n-1", responseMode = "direct_post.jwt",
                    credentialsToInclude = listOf(org.siros.sdk.transport.engine.CredentialRef(credentialQueryId = "pay", credentialId = "1")),
                    transactionData = listOf(scaWire()),
                    responseEncryption = blindResponseEncryption(),
                    // no verified_request: the response cannot be built
                ),
            )
        )
        repeat(8) {
            runBlocking(Dispatchers.Default) { kotlinx.coroutines.delay(50) }
            dispatcher.scheduler.advanceUntilIdle()
        }
        verify(exactly = 1) { engine.sendSignResponse(flowId = "flow-sca", messageId = "m1", error = any()) }
        verify(exactly = 0) { engine.sendSignResponse(flowId = any(), vpToken = any()) }
        verify(exactly = 0) { engine.sendSignResponse(flowId = any(), responseJwe = any()) }
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
