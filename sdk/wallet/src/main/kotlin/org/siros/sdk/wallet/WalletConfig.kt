// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
package org.siros.sdk.wallet

import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import org.siros.sdk.credentials.CredentialStore
import org.siros.sdk.credentials.ZkCircuitClient
import org.siros.sdk.keystore.KeystoreManager
import org.siros.sdk.keystore.NativeAttestationProvider

/**
 * Configuration for [SirosWallet].
 *
 * @param backendUrl The wallet backend URL (e.g. "https://wallet.sirosid.dev").
 * @param tenantId  Tenant identifier. Defaults to "default".
 * @param redirectUri OAuth redirect URI for authorization code flows. For native
 *        apps this is typically a custom-scheme URI or an app-link URL.
 * @param useSystemCredentialManager When `true` (default), use the system Credential
 *        Manager picker for passkeys — this is required for roaming authenticator
 *        support (hybrid/phone-as-authenticator, USB/NFC/BLE security keys) and
 *        handles biometric/device-credential authorization itself. Set to `false`
 *        to use the SDK's built-in KeyStore-backed passkey manager instead (local
 *        platform authenticator only, no roaming support) — mainly useful as a
 *        fallback on emulators/environments without a working Credential Manager
 *        provider.
 * @param credentialStore Custom [CredentialStore] implementation. When `null`
 *        (default), the SDK uses an encrypted file-backed store. Pass your own
 *        implementation if you need custom storage (e.g. Room, SQLCipher).
 * @param httpClient Custom [OkHttpClient] for all HTTP/WS communication.
 *        Use this to configure timeouts, certificate pinning, proxy settings,
 *        or logging interceptors. When `null`, a default client is created.
 * @param urlRewriter Optional function to rewrite URLs before they are opened
 *        in the browser (e.g. to map Docker-internal hostnames to external addresses).
 *        Applied to authorization URLs in [WalletEventListener.onAuthorizationRequired].
 * @param nativeAttestationProvider Optional platform attestation provider (e.g.
 *        [org.siros.sdk.keystore.PlayIntegrityProvider]) used to attach real device
 *        attestation evidence to Wallet Instance Attestation requests, so the backend's
 *        Key Attestation trust gate can lift its software-key clamp for genuinely
 *        Tier-1-attested instances. `SirosWallet` has no `Context` of its own (this
 *        is a plain Kotlin class, not Android-aware), so - unlike [keystore] - this
 *        can't be lazily constructed internally from a bare config value: the host
 *        app must construct it (it has the `Context`/`Activity` a provider like
 *        `PlayIntegrityProvider` needs) and inject the ready instance here. `null`
 *        (default) omits `native_attestation` entirely, matching today's behavior.
 * @param availableKeystores Optional registry of every [KeystoreManager] the
 *        host app has ready to use, keyed by WSCD plugin ID (e.g.
 *        `"softkey"`, `"fido2"`, `"r2ps"` - see the sample app's plugin
 *        chooser). Each entry's instance must already have its own platform
 *        transport wired up (BLE/USB/etc.) - like [keystore], the SDK cannot
 *        construct these itself. When set, [SirosWallet] can pick among
 *        these (see [WscdSelectionPolicy]) to satisfy a credential type's
 *        declared key-storage assurance requirement
 *        (`Vctm.requiredKeyStorage` / `MddlSchema.requiredKeyStorage`)
 *        before generating that batch's issuance keys, instead of using
 *        [keystore] unconditionally. **Fully backward compatible**: `null`
 *        (default) or an empty map disables this selection logic entirely -
 *        [keystore] is used exactly as before, with no tier-checking or
 *        prompting.
 * @param defaultWscdMapping Optional pre-populated default plugin choice per
 *        credential type, keyed by `"issuer|credentialType"` (e.g.
 *        `"https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"` ->
 *        `"fido2"`), consulted before asking the user (see
 *        [WscdSelectionPolicy]'s resolution order) - lets an integrator that
 *        already knows the right plugin for a given (issuer, credentialType)
 *        pair skip the [requestWscdChoice] prompt entirely. Only consulted
 *        when [availableKeystores] is non-empty.
 * @param requestWscdChoice Optional suspending callback the SDK invokes when
 *        [availableKeystores] contains more than one plugin capable of a
 *        credential type's required tier and neither a persisted TOFU choice
 *        nor [defaultWscdMapping] resolves it unambiguously - mirrors
 *        `org.siros.sdk.keystore.mdoc.RequestProximityConsent`'s shape
 *        exactly. See [RequestWscdChoice]'s doc comment.
 * @param zkCircuitUrls Mirror base URLs for the go-zk-circuits catalog
 *        service (read-only REST API for discovering/downloading ZK-proof
 *        circuit artifacts used by the Longfellow-ZKP-pseudonym feature).
 *        Tried in order, first-success-wins (see [org.siros.sdk.credentials.ZkCircuitClient]'s
 *        doc comment for why this is ordered fallback across mirrors of the
 *        SAME catalog, not merging like [registryUrl]'s TS11 registry
 *        sources). Defaults to a single entry, the pre-DNS Fly.io deployment
 *        (`https://zk-circuits.fly.dev`) - add `https://api.circuits.siros.org`
 *        (or another mirror) once available, without removing the default.
 * @param registryUrl Base URL for go-wallet-backend's credential-type
 *        registry service (TS11-backed, ingests the external canonical
 *        credential-type registry; includes `attestation_los`/
 *        `Vctm.requiredKeyStorage`/`MddlSchema.requiredKeyStorage` data) -
 *        queried as `<registryUrl>/type-metadata?vct=<vct-or-doctype>`. This
 *        is the SAME service the reference wallet-frontend implementation
 *        always calls for VCT/mdoc type metadata lookups, via its own
 *        distinct, independently-settable `VCT_REGISTRY_URL` config value -
 *        set this explicitly if your registry is deployed separately from
 *        your main wallet backend (e.g. a different host/environment). When
 *        `null` (the common case), derived automatically as
 *        `<backendUrl>/registry`, which covers the common case (registry
 *        mounted on the same host as the rest of go-wallet-backend's public
 *        API) with zero extra configuration.
 */
data class WalletConfig(
    val backendUrl: String,
    val tenantId: String = "default",
    val redirectUri: String = "",
    val useSystemCredentialManager: Boolean = true,
    val credentialStore: CredentialStore? = null,
    val httpClient: OkHttpClient? = null,
    val urlRewriter: ((String) -> String)? = null,
    val requireUserAuth: Boolean = true,
    val keystore: KeystoreManager? = null,
    val nativeAttestationProvider: NativeAttestationProvider? = null,
    /** Engine WebSocket URL. Defaults to backendUrl with port replaced by 8082. */
    val engineUrl: String? = null,
    /**
     * Use the WMP (Wallet Messaging Protocol) JSON-RPC 2.0 transport instead
     * of the legacy engine protocol. Requires go-wallet-backend with WMP support.
     */
    val useWmpProtocol: Boolean = false,
    val availableKeystores: Map<String, KeystoreManager>? = null,
    val defaultWscdMapping: Map<String, String>? = null,
    val requestWscdChoice: RequestWscdChoice? = null,
    val registryUrl: String? = null,
    val zkCircuitUrls: List<String> = listOf(ZkCircuitClient.DEFAULT_ZK_CIRCUIT_URL),
    /**
     * The credential types (`vct` values) this wallet handles as blind BBS
     * credentials — empty by default, which leaves BBS entirely inactive.
     *
     * Unlike the circuit-based proof systems, BBS constrains no credential
     * type at all: anything issued this way can be proved. That makes the
     * set of types a deployment decision rather than something the SDK can
     * derive, and the wallet has to know it *before* the first credential
     * exists — the wallet must commit to messages during issuance, so a type
     * missing from this set is not a credential presented the ordinary way,
     * it is a credential that never gets issued.
     *
     * Non-empty also registers the presentation half, so a listed type is
     * both issuable and presentable.
     */
    val bbsCredentialTypes: Set<String> = emptySet(),
    /**
     * PEM-encoded RICAL (Reader Identity CA List, ISO/IEC 18013-5 second
     * edition Annex F) root certificate(s) for [SirosWallet.evaluateReaderTrust]'s
     * local fallback path - plain X.509 path validation against these
     * anchors, with none of the RICAL CBOR/COSE document parsing or
     * `trustConstraints` enforcement the remote go-trust `mdocrical`
     * registry does (see that registry for the full RICAL semantics). Empty
     * by default: until an operator configures at least one root here,
     * local reader-trust evaluation always reports untrusted rather than
     * silently no-oping.
     */
    val readerTrustRootCertificatesPem: List<String> = emptyList(),
    /**
     * Forces [SirosWallet.evaluateReaderTrust] to always use the local
     * X.509 fallback (see [readerTrustRootCertificatesPem]) instead of
     * attempting the remote AuthZEN call first.
     *
     * Superseded by [readerTrustEvaluationMode], which can also express
     * "remotely, and fail closed if go-trust is unreachable" - a choice a
     * boolean cannot make. Still honored: `true` means
     * [MdocTrustEvaluationMode.LOCAL_ONLY], but only while
     * [readerTrustEvaluationMode] is left at its default.
     */
    @Deprecated(
        "Use readerTrustEvaluationMode instead; true is equivalent to LOCAL_ONLY.",
        ReplaceWith("readerTrustEvaluationMode = MdocTrustEvaluationMode.LOCAL_ONLY"),
    )
    val preferLocalReaderTrustEvaluation: Boolean = false,
    /**
     * PEM-encoded VICAL (Verified Issuer CA List, ISO/IEC 18013-5 Annex C)
     * root certificate(s) for [SirosWallet.evaluateIssuerTrust]'s local
     * fallback path - plain X.509 path validation against these anchors,
     * with none of the VICAL CBOR/COSE document parsing or per-certificate
     * `docType` enforcement the remote go-trust `vical` registry does (see
     * that registry for the full VICAL semantics). Empty by default: until
     * an operator configures at least one root here, local issuer-trust
     * evaluation always reports untrusted rather than silently no-oping -
     * same convention as [readerTrustRootCertificatesPem].
     */
    val issuerTrustRootCertificatesPem: List<String> = emptyList(),
    /**
     * Forces [SirosWallet.evaluateIssuerTrust] to always use the local
     * X.509 fallback (see [issuerTrustRootCertificatesPem]) instead of
     * attempting the remote AuthZEN call first.
     *
     * Superseded by [issuerTrustEvaluationMode]. Same convention as
     * [preferLocalReaderTrustEvaluation].
     */
    @Deprecated(
        "Use issuerTrustEvaluationMode instead; true is equivalent to LOCAL_ONLY.",
        ReplaceWith("issuerTrustEvaluationMode = MdocTrustEvaluationMode.LOCAL_ONLY"),
    )
    val preferLocalIssuerTrustEvaluation: Boolean = false,
    /**
     * Called right before [SirosWallet] is about to invoke a WSCD signing
     * operation (`generateProof`/`generateKeyAttestation`/`generateKeypairs`)
     * on [resolveEffectiveKeystoreForIssuance]'s resolved plugin, with that
     * plugin's ID - lets a host app prefetch a PIN and/or show a "present
     * your key" guide up front, mirroring the sample app's existing
     * enroll/rotate dev-screen pattern (collect the PIN BEFORE any transport
     * work starts, since a hardware-backed key's physical presentation and
     * PIN entry both need the user's hands, and forcing a mid-ceremony PIN
     * prompt can drop a live NFC session). Found necessary via live hardware
     * testing: without this hook, real credential issuance's only PIN
     * surface was a blocking dialog popped lazily mid-CTAP2-ceremony, with
     * zero "you can present the key now" feedback for the transport-connect
     * wait that happens first - the user had no way to know when to actually
     * tap/plug in the authenticator. Always paired with [onWscdOperationEnd]
     * (success or failure). `null` (default) preserves today's lazy-PIN
     * behavior with no guide shown.
     */
    val onWscdOperationStart: (suspend (pluginId: String) -> Unit)? = null,
    /**
     * Called once the WSCD operation [onWscdOperationStart] announced has
     * concluded (success or failure) - lets a host app dismiss any "present
     * your key" guide and clear a prefetched PIN. Always called exactly
     * once for every [onWscdOperationStart] call.
     */
    val onWscdOperationEnd: (suspend () -> Unit)? = null,
    /**
     * How [SirosWallet.evaluateReaderTrust] answers a RICAL question:
     * remotely against go-trust, locally against
     * [readerTrustRootCertificatesPem], or remotely with local as a
     * fallback. Read [effectiveReaderTrustEvaluationMode] rather than this.
     *
     * `null` means "not configured", which resolves to
     * [MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK] - what every
     * previous release did - unless the deprecated
     * [preferLocalReaderTrustEvaluation] says otherwise. It is nullable
     * precisely so that "unset" and "explicitly REMOTE_WITH_LOCAL_FALLBACK"
     * are distinguishable: comparing against the default value cannot tell
     * them apart, and would silently downgrade a caller who asked for the
     * fallback mode by name while a legacy flag happened to be set.
     */
    val readerTrustEvaluationMode: MdocTrustEvaluationMode? = null,
    /**
     * How [SirosWallet.evaluateIssuerTrust] answers a VICAL question. Same
     * convention as [readerTrustEvaluationMode], and independent of it: a
     * wallet may reasonably insist on remote issuer trust at issuance time
     * while tolerating local reader trust at an offline checkpoint. Read
     * [effectiveIssuerTrustEvaluationMode] rather than this.
     */
    val issuerTrustEvaluationMode: MdocTrustEvaluationMode? = null,
    /**
     * Talk to [backendUrl] using the legacy `/user` webauthn + HMAC
     * `appToken` auth flow instead of the standalone Authorization Server's
     * session-mode passkey flow (the `/auth/passkey` endpoints with
     * `X-Token-Mode: session`). `false` (default): every wallet talks only
     * to the new AS.
     *
     * `SirosWallet` used to auto-detect this per-backend by probing the AS's
     * login-begin endpoint at connect time (a 404 meant "legacy backend").
     * That probe is gone - go-wallet-backend is retiring the legacy
     * endpoints (`as.legacy.enabled=false` answers HTTP 410
     * `legacy_tokens_disabled`), and every backend this SDK talks to already
     * runs the new AS, so auto-detection is no longer needed and the extra
     * round-trip on every connect was pure waste. Set `true` only to reach a
     * deliberately old/pinned backend still running with legacy enabled.
     */
    val useLegacyAuth: Boolean = false,
    /**
     * Initial value of [SirosWallet.transactionDataEnabled]: whether the
     * wallet handles OpenID4VP `transaction_data` requests (EC TS12 payment
     * SCA). `false` by default. This is a runtime setting, not a build flag:
     * it can be changed on the wallet at any time and applies to flows
     * started afterwards. It only takes effect once a
     * [SirosWallet.transactionConsentHandler] is registered, because the
     * wallet cannot show a transaction without one.
     */
    val transactionDataEnabled: Boolean = false,
) {
    /**
     * The reader-trust mode actually in force: [readerTrustEvaluationMode] if
     * one was chosen, otherwise whatever the deprecated
     * [preferLocalReaderTrustEvaluation] implies.
     *
     * An explicitly chosen mode always wins, including an explicit
     * [MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK].
     */
    @Suppress("DEPRECATION")
    val effectiveReaderTrustEvaluationMode: MdocTrustEvaluationMode
        get() = readerTrustEvaluationMode ?: if (preferLocalReaderTrustEvaluation) {
            MdocTrustEvaluationMode.LOCAL_ONLY
        } else {
            MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK
        }

    /** See [effectiveReaderTrustEvaluationMode]. */
    @Suppress("DEPRECATION")
    val effectiveIssuerTrustEvaluationMode: MdocTrustEvaluationMode
        get() = issuerTrustEvaluationMode ?: if (preferLocalIssuerTrustEvaluation) {
            MdocTrustEvaluationMode.LOCAL_ONLY
        } else {
            MdocTrustEvaluationMode.REMOTE_WITH_LOCAL_FALLBACK
        }

    companion object {
        private val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }

        /**
         * Discover the engine base URL from the backend's
         * `/.well-known/wallet-configuration` endpoint.
         *
         * Returns `null` if discovery fails — the caller should fall back
         * to [backendUrl] (single-port deployment).
         */
        suspend fun discoverEngineUrl(backendUrl: String): String? {
            val url = backendUrl.trimEnd('/') + "/.well-known/wallet-configuration"
            return try {
                val client = okhttp3.OkHttpClient.Builder()
                    .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .build()
                val request = okhttp3.Request.Builder().url(url).build()
                val response = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                    client.newCall(request).execute()
                }
                response.use { resp ->
                    if (!resp.isSuccessful) return@use null
                    val body = resp.body?.string() ?: return@use null
                    val parsed = json.parseToJsonElement(body).jsonObject
                    val engineUrl = parsed["engine_url"]?.jsonPrimitive?.contentOrNull
                    if (engineUrl.isNullOrBlank()) null else engineUrl
                }
            } catch (_: Exception) {
                null
            }
        }
    }
}

/** See [SirosWallet.capabilities]. */
data class WalletCapabilities(
    val nativeAttestation: Boolean,
    val wscd: Boolean,
)
