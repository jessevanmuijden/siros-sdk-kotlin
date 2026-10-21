package org.siros.sdk.transport.wmp.openid4x

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.siros.sdk.transport.wmp.FlowActionParams
import org.siros.sdk.transport.wmp.FlowCancelParams
import org.siros.sdk.transport.wmp.FlowCompleteParams
import org.siros.sdk.transport.wmp.FlowErrorParams
import org.siros.sdk.transport.wmp.FlowProgressParams
import org.siros.sdk.transport.wmp.FlowStartParams
import org.siros.sdk.transport.wmp.JsonRpcResponse
import org.siros.sdk.transport.wmp.WmpCodec
import org.siros.sdk.transport.wmp.WmpMeta
import org.siros.sdk.transport.wmp.WmpMethods
import org.siros.sdk.transport.wmp.WmpPeerContext

class OpenID4xProfileTest {

    // ---------------------------------------------------------------------------
    // Fake peer context
    // ---------------------------------------------------------------------------

    private class FakePeerContext : WmpPeerContext {
        override val codec = WmpCodec()
        val notifications = mutableListOf<Pair<String, JsonObject?>>()

        override suspend fun notify(method: String, params: JsonObject?) {
            notifications.add(method to params)
        }

        override suspend fun call(method: String, params: JsonObject?): JsonRpcResponse =
            JsonRpcResponse(id = null)
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private fun buildSignPayload(): JsonObject = buildJsonObject {
        put("action", JsonPrimitive("generate_proof"))
        put("nonce", JsonPrimitive("abc123"))
        put("audience", JsonPrimitive("https://issuer.example.com/token"))
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    @Test
    fun startFlowReturnsMatchingFlowId() = runBlocking {
        val profile = OpenID4xProfile()
        val ctx = FakePeerContext()
        profile.init(ctx)

        val result = profile.startFlow(
            FlowStartParams(wmp = WmpMeta(), flowId = "f1", flowType = OID4FlowTypes.OID4VCI)
        )

        assertEquals("f1", result.flowId)
        assertEquals(OID4FlowTypes.OID4VCI, result.flowType)
    }

    @Test
    fun handleProgressSignRequestInvokesCallbackAndSendsNotification() = runBlocking {
        var capturedFlowId: String? = null
        var capturedParams: SignSubFlowParams? = null

        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { flowId, params ->
                    capturedFlowId = flowId
                    capturedParams = params
                    SignSubFlowResult(proofs = listOf(ProofObject(jwt = "jwt-token")))
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f1",
                step = "sign_request",
                payload = buildSignPayload(),
            )
        )

        assertEquals("f1", capturedFlowId)
        assertNotNull(capturedParams)
        assertEquals("abc123", capturedParams!!.nonce)

        // Profile must send wmp.flow.action notification with action=sign_response
        val notification = ctx.notifications.firstOrNull { it.first == WmpMethods.FLOW_ACTION }
        assertNotNull("Expected FLOW_ACTION notification", notification)
        val params = notification!!.second
        assertNotNull(params)
        assertEquals(JsonPrimitive("sign_response"), params!!["action"])
        assertEquals(JsonPrimitive("f1"), params["flow_id"])
    }

    @Test
    fun handleProgressGeneratingProofAlsoInvokesSignCallback() = runBlocking {
        var called = false
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { _, _ ->
                    called = true
                    SignSubFlowResult()
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f1",
                step = VCIStep.GENERATING_PROOF,
                payload = buildSignPayload(),
            )
        )

        assertTrue("onSignRequest should be called for GENERATING_PROOF step", called)
    }

    @Test
    fun handleProgressMatchRequestInvokesCallbackAndSendsNotification() = runBlocking {
        var capturedFlowId: String? = null

        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onMatchRequest = { flowId, _ ->
                    capturedFlowId = flowId
                    MatchResult(matches = listOf(CredentialMatch(credentialId = "cred-1")))
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f2",
                step = "match_request",
            )
        )

        assertEquals("f2", capturedFlowId)

        val notification = ctx.notifications.firstOrNull { it.first == WmpMethods.FLOW_ACTION }
        assertNotNull("Expected FLOW_ACTION notification for match", notification)
        val params = notification!!.second
        assertNotNull(params)
        assertEquals(JsonPrimitive("match_response"), params!!["action"])
    }

    @Test
    fun handleProgressMatchingCredentialsAlsoInvokesMatchCallback() = runBlocking {
        var called = false
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onMatchRequest = { _, _ ->
                    called = true
                    MatchResult(matches = emptyList())
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f2",
                step = VPStep.MATCHING_CREDENTIALS,
            )
        )

        assertTrue("onMatchRequest should be called for MATCHING_CREDENTIALS step", called)
    }

    @Test
    fun emptyMatchSetIsAlsoReportedAsCredentialsMatchedWithItsReason() = runBlocking {
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onMatchRequest = { _, _ ->
                    MatchResult(
                        matches = emptyList(),
                        noMatchReason = "This wallet holds no credential matching the request",
                    )
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f-nomatch", step = "match_request")
        )

        val actions = ctx.notifications.filter { it.first == WmpMethods.FLOW_ACTION }.mapNotNull { it.second }
        val matchResponse = actions.first { it["action"] == JsonPrimitive("match_response") }
        assertEquals(
            JsonPrimitive("This wallet holds no credential matching the request"),
            matchResponse["no_match_reason"],
        )
        // The engine's OID4VP flow never reads a match_response; this is the
        // action it acts on, and without it the presentation stalls until the
        // user-interaction timeout.
        val credentialsMatched = actions.firstOrNull {
            it["action"] == JsonPrimitive(OID4Action.CREDENTIALS_MATCHED)
        }
        assertNotNull("Expected a credentials_matched action for an empty match set", credentialsMatched)
        assertEquals(
            JsonPrimitive("This wallet holds no credential matching the request"),
            credentialsMatched!!["no_match_reason"],
        )
        assertEquals(0, credentialsMatched["matches"]!!.jsonArray.size)
    }

    @Test
    fun aNonEmptyMatchSetIsNotReportedAsCredentialsMatched() = runBlocking {
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onMatchRequest = { _, _ ->
                    MatchResult(matches = listOf(CredentialMatch(credentialId = "cred-1")))
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f-match", step = "match_request")
        )

        val actions = ctx.notifications.filter { it.first == WmpMethods.FLOW_ACTION }.mapNotNull { it.second }
        assertTrue(
            "A wallet with something to offer must not report an empty match set",
            actions.none { it["action"] == JsonPrimitive(OID4Action.CREDENTIALS_MATCHED) },
        )
    }

    @Test
    fun handleProgressTrustEvaluationInvokesCallbackAndSendsNotification() = runBlocking {
        var capturedFlowId: String? = null

        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onTrustEvaluation = { flowId, _ ->
                    capturedFlowId = flowId
                    TrustResult(trusted = true, framework = "EUCS")
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f3",
                step = "trust_evaluation_required",
            )
        )

        assertEquals("f3", capturedFlowId)

        val notification = ctx.notifications.firstOrNull { it.first == WmpMethods.FLOW_ACTION }
        assertNotNull("Expected FLOW_ACTION notification for trust", notification)
        val params = notification!!.second
        assertNotNull(params)
        assertEquals(JsonPrimitive("trust_result"), params!!["action"])
        assertEquals(JsonPrimitive(true), params["trusted"])
        assertEquals(JsonPrimitive("EUCS"), params["framework"])
    }

    @Test
    fun handleProgressUnknownStepCallsOnProgress() = runBlocking {
        var capturedStep: String? = null
        var capturedFlowId: String? = null

        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onProgress = { flowId, step, _ ->
                    capturedFlowId = flowId
                    capturedStep = step
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f4",
                step = VCIStep.RESOLVING_METADATA,
            )
        )

        assertEquals("f4", capturedFlowId)
        assertEquals(VCIStep.RESOLVING_METADATA, capturedStep)
        assertTrue("No notification should be sent for general progress", ctx.notifications.isEmpty())
    }

    @Test
    fun flowCompleteResultOfAnEncryptedIssuanceHasEmptyCredentialsAndSaysSo() {
        val result = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"credentials":[{"format":"mso_mdoc"},{"format":"dc+sd-jwt","vct":"urn:v"}],"credential_response_encrypted":true}""",
        ) as JsonObject
        val decoded = FlowCompleteResult.decode(result)!!
        assertTrue(decoded.credentialResponseEncrypted)
        assertEquals(listOf("", ""), decoded.credentials!!.map { it.credential })
        assertEquals("urn:v", decoded.credentials!![1].vct)
        assertEquals(false, FlowCompleteResult.decode(JsonObject(emptyMap()))!!.credentialResponseEncrypted)
        assertNull(FlowCompleteResult.decode(null))
    }

    @Test
    fun flowCompleteResultKeepsOnlyTheDisplayMembersOfAPlainResponsesMetadata() {
        val result = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"credentials":[{"format":"dc+sd-jwt","credential":"x"}],"credential_metadata":{"display":[{"name":"N"}],""" +
                """"org.siros.secret_seed":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"},"claims":[],"ext":1}}""",
        ) as JsonObject
        val metadata = FlowCompleteResult.decode(result)!!.credentialMetadata!!
        assertEquals(listOf("display", "claims"), metadata.members.keys.toList())
        assertTrue(!metadata.members.toString().contains("00112233445566778899aabbccddeeff"))
        assertNull(FlowCompleteResult.decode(JsonObject(emptyMap()))!!.credentialMetadata)
        val malformed = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"credentials":[{"format":"dc+sd-jwt","credential":"x","notification_id":"n1"}],"credential_metadata":"text"}""",
        ) as JsonObject
        assertTrue(FlowCompleteResult.decode(malformed)!!.credentialMetadata!!.malformed)
    }

    @Test
    fun flowCompleteResultWithANonBooleanEncryptedMarkerReadsItAsFalse() {
        listOf(""""true"""", "1", "null", "{}").forEach { flag ->
            val result = kotlinx.serialization.json.Json.parseToJsonElement(
                """{"credentials":[{"format":"dc+sd-jwt","credential":"x","notification_id":"n1"}],"credential_response_encrypted":$flag}""",
            ) as JsonObject
            val decoded = FlowCompleteResult.decode(result)!!
            assertEquals(flag, false, decoded.credentialResponseEncrypted)
            assertEquals(flag, "n1", decoded.credentials!!.single().notificationId)
        }
    }

    @Test
    fun flowCompleteResultDecodesRedactedMembers() {
        fun decode(members: String?) = FlowCompleteResult.decode(
            kotlinx.serialization.json.Json.parseToJsonElement(
                """{"credentials":[{"format":"mso_mdoc","credential":"AA","notification_id":"n"}]""" +
                    (members?.let { ""","redacted_members":$it""" } ?: "") + "}",
            ) as JsonObject,
        )!!
        assertEquals(emptySet<String>(), decode(null).redactedMembers)
        assertEquals(false, decode("[]").renewalMaterialRedacted)
        val replay = decode("""["dpop_jwk","refresh_token"]""")
        assertEquals(setOf("dpop_jwk", "refresh_token"), replay.redactedMembers)
        assertTrue(replay.renewalMaterialRedacted)
        // Only part of the renewal material: still unavailable.
        assertTrue(decode("""["dpop_key_id"]""").renewalMaterialRedacted)
        // A marker that cannot be read says nothing reliable: everything it can list is withheld.
        for (bad in listOf(""""refresh_token"""", "5", "[1]", """[null]""", "{}")) {
            assertTrue(bad, decode(bad).renewalMaterialRedacted)
        }
    }

    @Test
    fun theCredentialIsInNoStringFormOfTheDecodedResult() {
        val result = kotlinx.serialization.json.Json.parseToJsonElement(
            """{"credentials":[{"format":"mso_mdoc","credential":"secret-credential"}]}""",
        ) as JsonObject
        val decoded = FlowCompleteResult.decode(result)!!
        assertTrue(!decoded.toString().contains("secret-credential"))
        assertTrue(!decoded.credentials.toString().contains("secret-credential"))
    }

    @Test
    fun aSignSubFlowDecodesTheBlindEncryptionMembers() {
        val codec = WmpCodec()
        val issuance = codec.json.decodeFromJsonElement(
            SignSubFlowParams.serializer(),
            kotlinx.serialization.json.Json.parseToJsonElement(
                """{"action":"generate_proof","nonce":"n","audience":"a","credential_response_encryption":{"alg":"ECDH-ES","enc":"A256GCM","required":true}}""",
            ),
        )
        assertEquals("ECDH-ES", issuance.credentialResponseEncryption!!.alg)
        assertEquals(true, issuance.credentialResponseEncryption!!.required)
        val decrypt = codec.json.decodeFromJsonElement(
            SignSubFlowParams.serializer(),
            kotlinx.serialization.json.Json.parseToJsonElement("""{"action":"decrypt_credential_response","jwe":"a.b.c.d.e","deferred":true}"""),
        )
        assertEquals("a.b.c.d.e", decrypt.jwe)
        assertEquals(true, decrypt.deferred)
        val vp = codec.json.decodeFromJsonElement(
            SignSubFlowParams.serializer(),
            kotlinx.serialization.json.Json.parseToJsonElement(
                """{"action":"sign_presentation","nonce":"n","audience":"v","state":"st","response_encryption":{"jwk":{"kty":"EC","kid":"k1"},"alg":"ECDH-ES","enc":"A128GCM"}}""",
            ),
        )
        assertEquals("st", vp.state)
        assertEquals("A128GCM", vp.responseEncryption!!.enc)
    }

    @Test
    fun theSignResponseCarriesTheBlindEncryptionAnswersUnderTheLegacyWireNames() = runBlocking {
        val jwk = buildJsonObject { put("kty", JsonPrimitive("EC")) }
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { _, _ ->
                    SignSubFlowResult(
                        credentialResponseEncryptionJwk = jwk,
                        transactionId = "tx-1",
                        interval = 5,
                        responseJwe = "h.k.i.c.t",
                    )
                },
            ),
        )
        val ctx = FakePeerContext()
        profile.init(ctx)
        profile.handleProgress(FlowProgressParams(wmp = WmpMeta(), flowId = "f9", step = "sign_request", payload = buildSignPayload()))

        val params = ctx.notifications.single().second!!
        assertEquals(jwk, params["credential_response_encryption_jwk"])
        assertEquals(JsonPrimitive("tx-1"), params["transaction_id"])
        assertEquals(JsonPrimitive(5), params["interval"])
        assertEquals(JsonPrimitive("h.k.i.c.t"), params["response_jwe"])
    }

    @Test
    fun aFailedDecryptionAnswersWithAnErrorMemberAlone() = runBlocking {
        val profile = OpenID4xProfile(OpenID4xConfig(onSignRequest = { _, _ -> SignSubFlowResult(error = "could not be decrypted") }))
        val ctx = FakePeerContext()
        profile.init(ctx)
        profile.handleProgress(FlowProgressParams(wmp = WmpMeta(), flowId = "f9", step = "sign_request", payload = buildSignPayload()))
        val params = ctx.notifications.single().second!!
        assertEquals(JsonPrimitive("could not be decrypted"), params["error"])
        assertNull(params["response_jwe"])
    }

    @Test
    fun aSignSubFlowDecodesTheVerifiedRequest() {
        val codec = WmpCodec()
        val p = codec.json.decodeFromJsonElement(
            SignSubFlowParams.serializer(),
            kotlinx.serialization.json.Json.parseToJsonElement(
                """{"action":"sign_presentation","nonce":"n","audience":"admin","verified_request":{"client_id":"x509_san_dns:v.example",""" +
                    """"response_uri":"https://v.example/r","signed":true,"signature_verification":"verified","extra":1}}""",
            ),
        )
        assertEquals("x509_san_dns:v.example", p.verifiedRequest!!.clientId)
        assertEquals(true, p.verifiedRequest!!.signed)
        assertNull(codec.json.decodeFromJsonElement(SignSubFlowParams.serializer(), buildSignPayload()).verifiedRequest)
    }

    @Test
    fun aSignResultWithAnErrorCannotCarryAResponseJwe() {
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { SignSubFlowResult(responseJwe = "h.k.i.c.t", error = "nope") }
    }

    @Test
    fun aRefusedSignRequestIsAFlowErrorNeverASignResponseCarryingAResponseJwe() = runBlocking {
        val profile = OpenID4xProfile(
            OpenID4xConfig(onSignRequest = { _, _ -> throw org.siros.sdk.credentials.WalletException("the user declined") }),
        )
        val ctx = FakePeerContext()
        profile.init(ctx)
        profile.handleProgress(FlowProgressParams(wmp = WmpMeta(), flowId = "f9", step = "sign_request", payload = buildSignPayload()))

        val sent = ctx.notifications
        assertTrue(sent.toString(), sent.none { (_, params) -> params?.get("action") == JsonPrimitive("sign_response") })
        assertTrue(sent.none { (_, params) -> params?.containsKey("response_jwe") == true })
        assertTrue("the refusal still reaches the engine", sent.isNotEmpty())
    }

    @Test
    fun anOrdinarySignResponseCarriesNoBlindEncryptionMembers() = runBlocking {
        val profile = OpenID4xProfile(OpenID4xConfig(onSignRequest = { _, _ -> SignSubFlowResult(proofs = listOf(ProofObject(jwt = "t"))) }))
        val ctx = FakePeerContext()
        profile.init(ctx)
        profile.handleProgress(FlowProgressParams(wmp = WmpMeta(), flowId = "f9", step = "sign_request", payload = buildSignPayload()))
        val params = ctx.notifications.single().second!!
        for (member in listOf("credential_response_encryption_jwk", "transaction_id", "interval", "response_jwe", "error")) {
            assertNull(member, params[member])
        }
    }

    @Test
    fun handleCompleteCallsOnComplete() = runBlocking {
        var capturedFlowId: String? = null
        var capturedResult: JsonObject? = null

        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onComplete = { flowId, result ->
                    capturedFlowId = flowId
                    capturedResult = result
                }
            )
        )
        profile.init(FakePeerContext())

        val result = buildJsonObject { put("status", JsonPrimitive("ok")) }
        profile.handleComplete(FlowCompleteParams(wmp = WmpMeta(), flowId = "f5", result = result))

        assertEquals("f5", capturedFlowId)
        assertEquals(result, capturedResult)
    }

    @Test
    fun handleErrorCallsOnError() = runBlocking {
        var capturedCode: String? = null
        var capturedMessage: String? = null

        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onError = { _, code, message ->
                    capturedCode = code
                    capturedMessage = message
                }
            )
        )
        profile.init(FakePeerContext())

        profile.handleError(
            FlowErrorParams(wmp = WmpMeta(), flowId = "f6", code = "ISSUER_ERROR", message = "rejected")
        )

        assertEquals("ISSUER_ERROR", capturedCode)
        assertEquals("rejected", capturedMessage)
    }

    @Test
    fun signHandlerExceptionSendsFlowErrorNotification() = runBlocking {
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { _, _ -> throw RuntimeException("key unavailable") }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f7",
                step = "sign_request",
                payload = buildSignPayload(),
            )
        )

        val notification = ctx.notifications.firstOrNull { it.first == WmpMethods.FLOW_ERROR }
        assertNotNull("Expected FLOW_ERROR notification on sign handler exception", notification)
        val params = notification!!.second
        assertNotNull(params)
        assertEquals(JsonPrimitive("SIGN_ERROR"), params!!["code"])
        assertEquals(JsonPrimitive("key unavailable"), params["message"])
    }

    @Test
    fun trustHandlerExceptionSendsTrustedFalse() = runBlocking {
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onTrustEvaluation = { _, _ -> throw RuntimeException("trust store unavailable") }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f8",
                step = "trust_evaluation_required",
            )
        )

        val notification = ctx.notifications.firstOrNull { it.first == WmpMethods.FLOW_ACTION }
        assertNotNull("Expected FLOW_ACTION notification with trusted=false on exception", notification)
        val params = notification!!.second
        assertEquals(JsonPrimitive("trust_result"), params!!["action"])
        assertEquals(JsonPrimitive(false), params["trusted"])
        assertEquals(JsonPrimitive("trust store unavailable"), params["reason"])
    }

    @Test
    fun noNotificationSentWhenPeerNotInitialized() = runBlocking {
        // Profile never had init() called → all send helpers should be no-ops
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { _, _ -> SignSubFlowResult(proofs = listOf(ProofObject(jwt = "t"))) }
            )
        )
        // No init() call — peer is null

        // Should not throw
        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f9",
                step = "sign_request",
                payload = buildSignPayload(),
            )
        )
        // Passes as long as no NPE is thrown
    }

    @Test
    fun handleActionAlwaysAccepts() = runBlocking {
        val profile = OpenID4xProfile()
        profile.init(FakePeerContext())

        val result = profile.handleAction(
            FlowActionParams(wmp = WmpMeta(), flowId = "f10", action = OID4Action.ACCEPT_OFFER)
        )

        assertTrue(result.accepted)
        assertEquals("f10", result.flowId)
    }

    @Test
    fun noCallbacksConfiguredDoesNotSendAnyNotifications() = runBlocking {
        val profile = OpenID4xProfile(OpenID4xConfig())
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f11", step = "sign_request", payload = buildSignPayload())
        )
        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f11", step = "match_request")
        )
        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f11", step = "trust_evaluation_required")
        )
        profile.handleComplete(FlowCompleteParams(wmp = WmpMeta(), flowId = "f11"))
        profile.handleError(FlowErrorParams(wmp = WmpMeta(), flowId = "f11"))
        profile.handleCancel(FlowCancelParams(wmp = WmpMeta(), flowId = "f11"))

        assertTrue("No notifications should be sent when no callbacks are configured", ctx.notifications.isEmpty())
    }

    @Test
    fun profileHasCorrectNameAndCapabilities() {
        val profile = OpenID4xProfile()
        assertEquals("openid4x", profile.name)
        assertTrue(profile.capabilities.contains("oid4vci"))
        assertTrue(profile.capabilities.contains("oid4vp"))
        assertTrue(profile.flowTypes.contains(OID4FlowTypes.OID4VCI))
        assertTrue(profile.flowTypes.contains(OID4FlowTypes.OID4VP))
    }

    @Test
    fun signResponseIncludesVpToken() = runBlocking {
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { _, _ ->
                    SignSubFlowResult(vpToken = "vp-token-value")
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(
                wmp = WmpMeta(),
                flowId = "f12",
                step = "sign_request",
                payload = buildSignPayload(),
            )
        )

        val params = ctx.notifications.first { it.first == WmpMethods.FLOW_ACTION }.second
        assertNotNull(params)
        assertEquals(JsonPrimitive("vp-token-value"), params!!["vp_token"])
        assertNull(params["proofs"])
    }

    @Test
    fun refusedTransactionDataIsReportedWithItsVerifierErrorCode() = runBlocking {
        val profile = OpenID4xProfile(
            OpenID4xConfig(
                onSignRequest = { _, _ ->
                    throw org.siros.sdk.credentials.TransactionDataError(
                        org.siros.sdk.credentials.TransactionDataReason.DISABLED,
                        "refused",
                    )
                }
            )
        )
        val ctx = FakePeerContext()
        profile.init(ctx)

        profile.handleProgress(
            FlowProgressParams(wmp = WmpMeta(), flowId = "f8", step = "sign_request", payload = buildSignPayload())
        )

        val params = ctx.notifications.first { it.first == WmpMethods.FLOW_ERROR }.second!!
        assertEquals(JsonPrimitive("invalid_transaction_data"), params["code"])
        assertEquals(JsonPrimitive("disabled"), params["message"])
    }
}
