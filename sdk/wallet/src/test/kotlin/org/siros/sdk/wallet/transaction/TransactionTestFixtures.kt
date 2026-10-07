package org.siros.sdk.wallet.transaction

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.Json
import org.siros.sdk.credentials.StoredCredential
import java.util.Base64

/** Shared builders for the transaction_data tests. */
internal object TransactionTestFixtures {
    const val SCA = "urn:eu:europa:ec:eudi:sca:sca-placeholder"
    const val PAYMENT = "urn:eudi:sca:payment:1"

    fun b64(text: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(text.toByteArray(Charsets.UTF_8))

    /** A compliant (TS12 4.3.1 / the official schema) payment payload. */
    const val PAYMENT_PAYLOAD =
        """{"transaction_id":"tx-0001","payee":{"name":"Shop AB","id":"SE1234567890"},"currency":"EUR","amount":49.99}"""

    /** A raw entry exactly as a verifier would send it. */
    fun raw(
        type: String = PAYMENT,
        credentialIds: String = """["pay"]""",
        payload: String = PAYMENT_PAYLOAD,
        algs: String? = null,
    ): String {
        val algMember = algs?.let { ""","transaction_data_hashes_alg":$it""" }.orEmpty()
        return b64("""{"type":"$type","credential_ids":$credentialIds,"payload":$payload$algMember}""")
    }

    /** An unsigned JWT with [claims] as payload: enough for code that only reads the payload. */
    fun jwt(claims: String): String = "e30.${b64(claims)}.c2ln"

    fun credential(
        id: Long = 1,
        format: String = "dc+sd-jwt",
        claims: String = """{"vct":"https://pay.example.com/card"}""",
        kid: String = "kid-$id",
    ) = StoredCredential(
        id = id,
        format = format,
        raw = "${jwt(claims)}~",
        kid = kid,
        credentialIssuerIdentifier = "https://issuer.example.com",
        credentialConfigurationId = "card",
        batchId = id,
        instanceId = 0,
    )

    fun metadata(
        category: String? = "urn:eu:europa:ec:eudi:sua:sca",
        types: String? = null,
    ): JsonObject {
        val parts = mutableListOf("\"vct\":\"https://pay.example.com/card\"")
        category?.let { parts += "\"category\":\"$it\"" }
        types?.let { parts += "\"transaction_data_types\":$it" }
        return Json.parseToJsonElement("{${parts.joinToString(",")}}") as JsonObject
    }

    /** A [TransactionMetadataSource] backed by maps; `null` metadata or a missing document is "unavailable". */
    class FakeSource(
        private val metadata: JsonObject? = metadata(),
        private val documents: Map<String, String> = emptyMap(),
    ) : TransactionMetadataSource {
        val fetched = mutableListOf<String>()
        var metadataCalls = 0
        override suspend fun typeMetadata(credential: StoredCredential): JsonObject? {
            metadataCalls++
            return metadata
        }
        override suspend fun document(uri: String): String? {
            fetched += uri
            return documents[uri]
        }
    }

    fun request(
        entries: List<TransactionDataEntry>,
        credentials: Map<String, List<StoredCredential>> = mapOf("pay" to listOf(credential())),
        responseMode: String? = "direct_post",
    ) = TransactionDataRequest(entries = entries, responseMode = responseMode, credentials = credentials)
}
