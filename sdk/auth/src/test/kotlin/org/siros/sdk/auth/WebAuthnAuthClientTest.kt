package org.siros.sdk.auth

import org.siros.sdk.credentials.AuthException
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class WebAuthnAuthClientTest {

    private lateinit var server: MockWebServer

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun register_calls_begin_and_finish_and_returns_session() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "challengeId": "reg-ch-1",
                  "createOptions": {
                    "publicKey": {
                      "rp": { "id": "example.com", "name": "Example RP" },
                      "challenge": "Y2hhbGxlbmdl",
                      "user": { "id": "dXNlcjEyMw", "name": "alice" }
                    }
                  }
                }
                """.trimIndent()
            )
        )
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "appToken": "app-token-123",
                  "uuid": "user-123",
                  "displayName": "Alice",
                  "refreshToken": "refresh-abc",
                  "tenantId": "default"
                }
                """.trimIndent()
            )
        )

        val fakeProvider = FakeAuthProvider(
            registerResult = RegisterResult(
                credentialId = byteArrayOf(1, 2, 3),
                attestationObject = "attestation".toByteArray(),
                clientDataJSON = "client-data".toByteArray(),
                prfOutput = null,
            ),
            authenticateResult = defaultAuthenticateResult(),
        )

        val baseUrl = server.url("/").toString().trimEnd('/')
        val client = WebAuthnAuthClient(baseUrl = baseUrl, authProvider = fakeProvider)

        val session = client.register(displayName = "Alice")

        assertEquals("app-token-123", session.appToken)
        assertEquals("user-123", session.uuid)
        assertNotNull(fakeProvider.lastRegisterOptions)
        assertArrayEquals("challenge".toByteArray(), fakeProvider.lastRegisterOptions!!.challenge)
        assertEquals("example.com", fakeProvider.lastRegisterOptions!!.rpId)

        val beginReq = server.takeRequest()
        val finishReq = server.takeRequest()
        assertEquals("/user/register-webauthn-begin", beginReq.path)
        assertEquals("/user/register-webauthn-finish", finishReq.path)
        assertTrue(beginReq.getHeader("X-Tenant-ID") == "default")
        assertTrue(finishReq.getHeader("X-Tenant-ID") == "default")
    }

    @Test
    fun login_calls_begin_and_finish_and_returns_session() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "challengeId": "login-ch-1",
                  "getOptions": {
                    "publicKey": {
                      "rpId": "example.com",
                      "challenge": "bG9naW4tY2hhbGxlbmdl"
                    }
                  }
                }
                """.trimIndent()
            )
        )
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "appToken": "app-token-login",
                  "uuid": "user-456",
                  "displayName": "Bob"
                }
                """.trimIndent()
            )
        )

        val fakeProvider = FakeAuthProvider(
            registerResult = defaultRegisterResult(),
            authenticateResult = defaultAuthenticateResult(),
        )

        val baseUrl = server.url("/").toString().trimEnd('/')
        val client = WebAuthnAuthClient(baseUrl = baseUrl, authProvider = fakeProvider)

        val session = client.login()

        assertEquals("app-token-login", session.appToken)
        assertEquals("user-456", session.uuid)
        assertNotNull(fakeProvider.lastAuthenticateOptions)
        assertArrayEquals("login-challenge".toByteArray(), fakeProvider.lastAuthenticateOptions!!.challenge)

        val beginReq = server.takeRequest()
        val finishReq = server.takeRequest()
        assertEquals("/user/login-webauthn-begin", beginReq.path)
        assertEquals("/user/login-webauthn-finish", finishReq.path)
    }

    @Test
    fun login_decodes_tagged_binary_private_data_in_finish_response() = runBlocking {
        // privatedata-spec §3.3: privateData is tagged binary ({"$b64u": "..."}),
        // not a plain string - AuthSession.privateData is typed as String?, so
        // the raw finish response must be run through TaggedBinary.decode
        // first or deserialization throws JsonDecodingException. decode()
        // only unwraps the {"$b64u": ...} object shape to a plain string - it
        // does NOT base64-decode the content (that's a separate step callers
        // do if they need it; the legacy login path here never actually
        // consumes session.privateData at all, it always re-fetches the
        // container via a dedicated endpoint instead) - so the still-encoded
        // string is exactly the correct, expected result.
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "challengeId": "login-ch-1",
                  "getOptions": {
                    "publicKey": {
                      "rpId": "example.com",
                      "challenge": "bG9naW4tY2hhbGxlbmdl"
                    }
                  }
                }
                """.trimIndent()
            )
        )
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "appToken": "app-token-login",
                  "uuid": "user-456",
                  "displayName": "Bob",
                  "privateData": { "${"$"}b64u": "eyJmb28iOiJiYXIifQ" }
                }
                """.trimIndent()
            )
        )

        val fakeProvider = FakeAuthProvider(
            registerResult = defaultRegisterResult(),
            authenticateResult = defaultAuthenticateResult(),
        )

        val baseUrl = server.url("/").toString().trimEnd('/')
        val client = WebAuthnAuthClient(baseUrl = baseUrl, authProvider = fakeProvider)

        val session = client.login()

        assertEquals("user-456", session.uuid)
        assertEquals("eyJmb28iOiJiYXIifQ", session.privateData)
    }

    /**
     * The legacy login finishes at the wallet API rather than at the
     * authorization server, so a SID-AUTH-06 refusal met there arrives through
     * this client. Discarding the body's `error` and `scope` - as this client
     * did until the refusal-scope work - makes a refusal indistinguishable
     * from any other 4xx, and a deactivated wallet is then never recognised on
     * the legacy path at all.
     */
    @Test
    fun a_lifecycle_refusal_carries_its_code_scope_and_message() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "challengeId": "login-ch-1",
                  "getOptions": {
                    "publicKey": {
                      "rpId": "example.com",
                      "challenge": "Y2hhbGxlbmdl"
                    }
                  }
                }
                """.trimIndent()
            )
        )
        server.enqueue(
            MockResponse().setResponseCode(403).setBody(
                """{"error":"WALLET_REVOKED","scope":"wallet","message":"This wallet has been deactivated"}"""
            )
        )

        val fakeProvider = FakeAuthProvider(
            registerResult = defaultRegisterResult(),
            authenticateResult = defaultAuthenticateResult(),
        )
        val baseUrl = server.url("/").toString().trimEnd('/')
        val client = WebAuthnAuthClient(baseUrl = baseUrl, authProvider = fakeProvider)

        val e = assertThrows(AuthException::class.java) { runBlocking { client.login() } }
        assertEquals(403, e.code)
        assertEquals("WALLET_REVOKED", e.errorCode)
        assertEquals("wallet", e.serverScope)
        assertEquals("This wallet has been deactivated", e.serverMessage)
        assertEquals(
            WalletLifecycleRefusal.DEACTIVATED,
            WalletLifecycleRefusal.fromRefusal(e.errorCode, e.serverScope),
        )
    }

    @Test
    fun register_throws_when_public_key_missing() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "challengeId": "reg-ch-2",
                  "createOptions": {}
                }
                """.trimIndent()
            )
        )

        val fakeProvider = FakeAuthProvider(
            registerResult = defaultRegisterResult(),
            authenticateResult = defaultAuthenticateResult(),
        )
        val baseUrl = server.url("/").toString().trimEnd('/')
        val client = WebAuthnAuthClient(baseUrl = baseUrl, authProvider = fakeProvider)

        try {
            client.register(displayName = "Alice")
            throw AssertionError("Expected AuthException")
        } catch (e: AuthException) {
            assertTrue(e.message?.contains("Missing publicKey") == true)
        }
    }

    @Test
    fun register_uses_public_key_fallbacks_and_forwards_prf_salt() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "challengeId": "reg-ch-3",
                  "publicKey": {
                    "rp": { "id": "example.com" },
                    "challenge": "Y2hhbGxlbmdl",
                    "user": { "id": "dXNlcjEyMw" }
                  }
                }
                """.trimIndent()
            )
        )
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "appToken": "app-token-fallback",
                  "uuid": "user-fallback",
                  "displayName": "Alice"
                }
                """.trimIndent()
            )
        )

        val prfSalt = "salt-123".toByteArray()
        val fakeProvider = FakeAuthProvider(
            registerResult = defaultRegisterResult(),
            authenticateResult = defaultAuthenticateResult(),
        )
        val baseUrl = server.url("/").toString().trimEnd('/')
        val client = WebAuthnAuthClient(baseUrl = baseUrl, authProvider = fakeProvider)

        client.register(displayName = "Alice", prfSalt = prfSalt)

        val options = fakeProvider.lastRegisterOptions!!
        assertEquals("example.com", options.rpName)
        assertEquals("Alice", options.userName)
        assertArrayEquals(prfSalt, options.prfSalt)

        server.takeRequest()
        val finishReq = server.takeRequest()
        assertTrue(finishReq.body.readUtf8().contains("\"challengeId\":\"reg-ch-3\""))
    }

    @Test
    fun login_uses_custom_tenant_and_includes_user_handle_in_finish_request() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "challengeId": "login-ch-2",
                  "publicKey": {
                    "rpId": "example.com",
                    "challenge": "bG9naW4tY2hhbGxlbmdl"
                  }
                }
                """.trimIndent()
            )
        )
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "appToken": "app-token-login-2",
                  "uuid": "user-789",
                  "displayName": "Carol",
                  "tenantId": "tenant-42"
                }
                """.trimIndent()
            )
        )

        val fakeProvider = FakeAuthProvider(
            registerResult = defaultRegisterResult(),
            authenticateResult = defaultAuthenticateResult().copy(userHandle = "user-handle".toByteArray()),
        )
        val baseUrl = server.url("/").toString().trimEnd('/')
        val client = WebAuthnAuthClient(
            baseUrl = baseUrl,
            tenantId = "tenant-42",
            authProvider = fakeProvider,
        )

        val session = client.login(prfSalt = "salt-xyz".toByteArray())

        assertEquals("tenant-42", session.tenantId)
        assertArrayEquals("salt-xyz".toByteArray(), fakeProvider.lastAuthenticateOptions!!.prfSalt)

        val beginReq = server.takeRequest()
        val finishReq = server.takeRequest()
        assertEquals("tenant-42", beginReq.getHeader("X-Tenant-ID"))
        assertEquals("tenant-42", finishReq.getHeader("X-Tenant-ID"))
        assertTrue(finishReq.body.readUtf8().contains("\"userHandle\":\"dXNlci1oYW5kbGU\""))
    }

    @Test
    fun login_throws_when_backend_returns_error_status() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(401).setBody("{\"error\":\"unauthorized\"}"))

        val fakeProvider = FakeAuthProvider(
            registerResult = defaultRegisterResult(),
            authenticateResult = defaultAuthenticateResult(),
        )
        val baseUrl = server.url("/").toString().trimEnd('/')
        val client = WebAuthnAuthClient(baseUrl = baseUrl, authProvider = fakeProvider)

        val error = assertThrows(AuthException::class.java) {
            runBlocking { client.login() }
        }

        assertTrue(error.message?.contains("Auth request failed: 401") == true)
    }

    @Test
    fun login_throws_when_rp_id_missing() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """
                {
                  "challengeId": "login-ch-3",
                  "publicKey": {
                    "challenge": "bG9naW4tY2hhbGxlbmdl"
                  }
                }
                """.trimIndent()
            )
        )

        val fakeProvider = FakeAuthProvider(
            registerResult = defaultRegisterResult(),
            authenticateResult = defaultAuthenticateResult(),
        )
        val baseUrl = server.url("/").toString().trimEnd('/')
        val client = WebAuthnAuthClient(baseUrl = baseUrl, authProvider = fakeProvider)

        val error = assertThrows(AuthException::class.java) {
            runBlocking { client.login() }
        }

        assertTrue(error.message?.contains("Missing rpId") == true)
    }

    private fun defaultRegisterResult() = RegisterResult(
        credentialId = byteArrayOf(9, 9, 9),
        attestationObject = "attestation".toByteArray(),
        clientDataJSON = "client-data".toByteArray(),
        prfOutput = null,
    )

    private fun defaultAuthenticateResult() = AuthenticateResult(
        credentialId = byteArrayOf(9, 9, 9),
        authenticatorData = "auth-data".toByteArray(),
        clientDataJSON = "client-data".toByteArray(),
        signature = "sig".toByteArray(),
        userHandle = null,
        prfOutput = null,
    )

    private class FakeAuthProvider(
        private val registerResult: RegisterResult,
        private val authenticateResult: AuthenticateResult,
    ) : AuthProvider {
        var lastRegisterOptions: RegisterOptions? = null
        var lastAuthenticateOptions: AuthenticateOptions? = null

        override suspend fun register(options: RegisterOptions): RegisterResult {
            lastRegisterOptions = options
            return registerResult
        }

        override suspend fun authenticate(options: AuthenticateOptions): AuthenticateResult {
            lastAuthenticateOptions = options
            return authenticateResult
        }

        override suspend fun getPrfOutput(credentialId: ByteArray, salt: ByteArray, rpId: String): PrfOutput {
            return PrfOutput(first = credentialId + salt)
        }
    }
}
