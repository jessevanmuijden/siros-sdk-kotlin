# Changelog

All notable changes to the SIROS SDK for Android will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **A request carrying OpenID4VP `transaction_data` is now refused instead of
  silently ignored.** The DC API path parsed the request and dropped
  `transaction_data`, and both engine transports ignored it on
  `sign_presentation`, so a payment-SCA request was answered with a
  presentation that bound no transaction and that the user never saw. All
  three paths now refuse with `TransactionDataError` before anything is
  signed (the DC API answers the verifier `invalid_transaction_data`). This
  is step 1 of the EC TS12 rollout; the handling itself follows.

### Removed
- **BREAKING:** `WscdKeystoreAdapter.signVpToken(..., transactionData:
  List<TransactionDataItem>, ...)` and `TransactionDataItem`. The overload was
  never called and hashed a re-serialisation of the entry instead of the
  verifier's original string; use `KeystoreManager.signVpToken(..., kid,
  transaction: TransactionBinding)`.

### Added
- Sample app: a settings toggle for payment confirmation (EC TS12) requests
  applied at runtime, a consent dialog rendering the SDK's model (level 1
  prominent, 2 and 3 below, 4 omitted, unsigned-request warning), a
  transaction log screen, and its own wording for refusal reasons.
- **`transaction_data` (EC TS12 payment SCA) is wired into the engine
  WebSocket, WMP and DC API presentation paths.** With
  `transactionDataEnabled` on and a `transactionConsentHandler` registered
  the wallet validates the request, shows it through the handler (labels,
  `visualisation` levels, UI elements from the type metadata; refusing when a
  required label is missing), establishes the authentication factors through
  `authenticationFactorsProvider`, signs the key binding JWT with the
  transaction bound, and records every attempt in `transactionLogStore`
  (`getTransactionLog()`). The default factors provider establishes none, so
  SCA presentations are refused (`insufficientAuthenticationFactors`) until a
  provider that can justify two categories for the operation is registered
  (the WSCD manager does not report them yet, siros-wscd-manager#101/#102).
  The user is not asked to confirm a request the provider says it cannot
  satisfy (`AuthenticationFactorsProvider.canEstablish`). The DC API shows the
  confirmation in its own activity. Values and labels with control, bidi or
  zero-width characters are refused; for the built-in types the amount,
  currency and payee name are always level 1 whatever the metadata says.
- **`transaction_data` core (EC TS12), not yet reachable from any transport.**
  Strict decoding of each entry from its own `raw` (duplicate member names,
  invalid UTF-8 and orchestrator-hint disagreement are refused), SD-JWT VC
  only, SCA `category` check, type support, JSON Schema validation against
  the spec's four built-in schemas (embedded verbatim) or the type metadata's,
  hash algorithm choice, and `transaction_data_hashes` over the verifier's
  `raw` string (golden vectors reproduced). `KeystoreManager.signVpToken`
  gains a `TransactionBinding` overload (`jti`, `response_mode`, string
  `transaction_data_hashes_alg`, two-category `amr`); the unused
  `WscdKeystoreAdapter.signVpToken(..., TransactionDataItem)` overload, which
  hashed a re-serialisation, is removed.
- `WalletConfig.transactionDataEnabled` / `SirosWallet.transactionDataEnabled`
  (runtime flag, default `false`), `SirosWallet.transactionConsentHandler`
  and `isTransactionDataEffectivelyEnabled`; `TransactionDataError` with the
  cross-SDK reason codes; the wire members `raw`, `payload`,
  `transaction_data_hashes_alg` (array or string), `response_mode`,
  `credentials_to_include` and `features: ["transaction_data.v1"]` /
  `capabilities_offered.transaction_data`. Nothing is declared to the
  orchestrator yet: this build contains no `transaction_data` pipeline.
- **Typed IDV errors for facetec-api v0.15/v0.16 refusals:
  `IDVException.ChipUntrusted` (`chip_untrusted`),
  `IDVException.DocumentExpired` (`document_expired`) and
  `IDVException.SessionExpired` (`session_expired`),** with `errorCode`s
  `idv_chip_untrusted`, `idv_document_expired` and `idv_session_expired`.
  Until now these reached the app as a generic `VerificationFailed` carrying
  a raw body (`RemoteIDVClient`) or as `ProviderError` (`FaceTecIDVProvider`).
  Adding subclasses breaks exhaustive `when`s over `IDVException`. The sample
  app has a message for each, in every language it ships.
- **`FaceTecIDVProvider` documents facetec-api v0.16.0's session rules:** one
  `externalDatabaseRefID` on every request of a session, a single-use liveness
  proof that expires after 15 minutes (an expired or used proof is
  `liveness_failed`; restart from the face scan with a new
  `startVerification`), and session affinity across facetec-api replicas.
- **`FaceTecIDVProvider`: identity verification with the FaceTec 10 SDK**
  (#246). FaceTec 10 replaced the FaceScan/IDScan processors the SDK's
  FaceTec support was written against with one opaque blob relay, so the
  existing `FaceTecCaptureDelegate` could not run a scan with any current
  FaceTec SDK: its availability check called a method FaceTec 10 removed,
  and so always reported FaceTec unavailable. The new provider runs FaceTec's
  liveness → document scan (with NFC chip read) → photo match session in an
  invisible host Activity. It relays each blob to facetec-api's
  `/v1/process-request` with a per-session `externalDatabaseRefID`, and
  returns the credential offer facetec-api issues. facetec-api's refusal
  codes and FaceTec's session statuses map to `IDVException`s. Configure it
  with `FaceTecIDVConfig(processRequestUrl, authToken, deviceKeyIdentifier)`.
  As before, the app supplies the FaceTec AAR; the SDK reaches it by
  reflection. The FaceTec code now has unit tests, including a check of every
  reflected class and method against a real FaceTec 10 AAR. That check runs
  where one is available (`FACETEC_SDK_AAR` or the Gradle cache) and is
  skipped elsewhere. The sample app uses the new provider
  (`-PfacetecDeviceKeyIdentifier=...`), and now shows its localized messages
  for IDV error codes.
- **`IDVException.DocumentChipNotVerified`: a refused issuance because the
  document's NFC chip was not read and authenticated.** facetec-api now
  issues nothing without an authenticated chip read
  (sirosfoundation/facetec-api#65) and refuses with an `nfc_*` code.
  `RemoteIDVClient` turns such a 422 into this exception, with `reason` set
  to the code and `errorCode` to `idv_<code>`, instead of a generic
  `VerificationFailed` carrying the raw body. Its `/v1/id-scan` endpoint
  only tells verified from not, so the reason there is always
  `nfc_skipped`; any other `nfc_*` code a backend sends maps the same way,
  and the sample app has a message for each.

### Changed
- **Legacy `/user/*` webauthn auth is now gated behind an explicit config
  flag instead of being auto-detected per backend.** `SirosWallet` used to
  probe the AS's login-begin endpoint on first connect and fall back to
  the legacy flow on a 404 - an extra network round-trip on every first
  login/register, and an implicit runtime guess for something this
  security-sensitive. go-wallet-backend is retiring the legacy HMAC
  session tokens (`as.legacy.enabled=false` now answers legacy endpoints
  with HTTP 410 `legacy_tokens_disabled`), and every backend this SDK
  talks to already runs the new AS, so the probe is gone. Added
  `WalletConfig.useLegacyAuth` (default `false`): every wallet talks only
  to the new AS unless a host app deliberately opts a pinned/old backend
  in (#235).
- **ZK (Vega) presentations were always declined, regardless of which
  credentials the wallet held.** `SharedDcqlMatcher` never told the
  shared DCQL matching engine what ZK proof systems this wallet can
  satisfy - the capability registration call (`addZkSystem`) was only
  ever made for DC API/OS-picker registration, not for the direct
  `openid4vp://` deep-link presentation path, so a `mso_mdoc_zk` request
  was declined outright even when a genuinely matching credential was
  present. Fixed by threading the wallet's registered ZK systems
  (`SirosWallet.zkSystemIds`) into `SharedDcqlMatcher.evaluate` too.

### Deprecated
- **`FaceTecCaptureDelegate`**: it targets the FaceTec 9 API and cannot run
  with FaceTec 10 (#246). Use `FaceTecIDVProvider`.

## [0.20.3] - 2026-09-29

### Fixed
- **CI: a GitHub Packages publish failure no longer blocks the Maven Central
  publish.** 0.20.2's Maven Central Portal publish never ran because a
  single module's GitHub Packages upload hit a transient 409 Conflict
  (most likely a network retry racing its own earlier success), which
  stopped the release job before it ever reached the Maven Central step.
  The two publish targets no longer gate each other; a genuine GitHub
  Packages failure still fails the job rather than being silently masked.
- **`did:`-scheme trust evaluation now fails closed on a denied `/v1/resolve`
  decision, and correctly resolves DID issuers.** `/v1/resolve` is itself
  an AuthZEN evaluation - a denied response (`decision: false`) could
  still carry a usable DID document, so a signature that happened to
  verify against it was being accepted regardless of the decision.
  Separately, `requires_resolution` for a `credential_issuer` never
  carries a `request_jwt` (OID4VCI issuance has no signed request object
  to verify one against, unlike OpenID4VP presentation), but both trust-
  evaluation paths required one unconditionally, failing every DID issuer
  resolution before `/v1/resolve` was ever called. Also closes a
  fragment-only verification-method matching gap: comparing only the
  fragment after `#` let a verification method belonging to a completely
  different DID match if it happened to share the same fragment as the
  request's `kid` - full, normalized identifiers are now compared instead.

## [0.20.2] - 2026-09-29

### Fixed
- **Presentation consent screen now shows a verified identity when there's
  no declared display name.** The backend no longer trusts/caches an
  unvalidated client-supplied `client_metadata.client_name` for the
  verifier consent screen, so a `null` verifier name is now common. The
  WMP credential-matching path never read back the `TrustResult` already
  cached for the flow, so the consent screen got neither a display name
  nor a fallback. Fixed by wiring the cached `TrustResult` through to
  `PresentationRequest`, with the consent screen falling back to the
  verified `client_id`/DID/certificate subject, labeled "Verified
  identity", when there's no declared name (#218).
- **`did:`-scheme verifiers can now be resolved when the engine defers to
  the frontend.** go-wallet-backend sets `requires_resolution: true` /
  `request_jwt` / `resolution_subject_id` on a trust evaluation when it
  cannot resolve a `did:`-scheme verifier's key material itself (no
  verifier PDP configured). This SDK previously ignored those fields
  entirely. Added `BackendApiClient.resolveKey` (`POST /v1/resolve`,
  `subject_type: "key"`) and `SirosWallet.resolveDidKeyMaterial`, which
  resolves the DID document and verifies `request_jwt` against each
  `verificationMethod`'s `publicKeyJwk` (EC/P-256, RSA, and Ed25519/EdDSA
  keys), failing closed if resolution fails, no usable verification
  method is found, or the signature doesn't verify (#219).

## [0.20.1] - 2026-09-28

### Fixed
- **DCQL matching now sees every nested claim path.** A verifier's query for
  a nested claim (e.g. `registered_address.full_address`) could fail to
  match a credential that genuinely has it, reported as "you do not have
  any credentials that match this request" against a real `eucc`
  credential. `SharedDcqlMatcher` (the shared Rust engine's input) built
  its claim list from `CredentialUtils.extractClaims`, a *display* function
  that only exposes a nested claim if the credential's issuer type
  metadata (VCTM) explicitly declares that exact sub-path, and even then
  collapsed it into one dotted display string that a naive re-split could
  not tell apart from a literal dot in a claim name. `flattenClaimPaths`
  now walks a credential's merged SD-JWT/JWT payload directly, independent
  of VCTM coverage, with real path arrays throughout. (#215)

- **The engine WebSocket no longer reconnects every few seconds in
  production.** Its ping interval was hardcoded to 30s on both client and
  server, on the assumption that any intermediate proxy/load balancer's
  idle timeout would be at least 60-120s; production Fly.io deployments
  actually close an idle connection after ~5-6s, so the connection was
  silently reconnecting continuously and could occasionally kill a flow
  mid-flight. The interval is now 3s by default and server-configurable -
  go-wallet-backend reports its own value to the client right after
  authentication, so the two sides never have to independently guess a
  number that happens to agree. (#213)

## [0.20.0] - 2026-09-21

### Fixed
- **A credential is matched on the vct it carries, not on its metadata.**
  DCQL matching read `credential.metadata?.vct`, which is a rendering
  artefact rather than the credential's identity: it is absent until an
  issuance flow has an offer to build it from, and the hydration pass that
  repopulates it skips any credential whose metadata is already real. A
  freshly issued credential could therefore be present, valid, correctly
  typed and presentable, and still match nothing. Seen live: an EBW-OID
  credential carrying `vct: uri:eu.ebw.oid.1` matched 0 candidates against a
  query naming exactly that, while the PID beside it matched.

  `CredentialUtils.vctOf` reads the credential first and the metadata copy
  second, and all four places that declare what a credential *is* now use it:
  `CredentialMatcher`, `SharedDcqlMatcher` (the shared Rust engine's input),
  and the two DC API registration paths `SirosCredentialRegistry` and
  `StockEntryBuilder` — the last two decide what the OS picker matches a
  request against, and previously passed a null vct and an empty string
  respectively. (#208)

## [0.19.0] - 2026-09-21

### Added
- **Local or remote mdoc trust evaluation is now a choice, per registry.**
  `MdocTrustEvaluationMode` — `REMOTE_WITH_LOCAL_FALLBACK` (the default, and
  what every previous release did), `REMOTE_ONLY`, `LOCAL_ONLY` — selectable
  independently for RICAL readers and VICAL issuers via
  `WalletConfig.readerTrustEvaluationMode` and `issuerTrustEvaluationMode`.
  The local path is deliberately the weaker of the two (plain X.509 path
  validation, no RICAL/VICAL CBOR parsing, no `trustConstraints`, no
  per-certificate `docType`), so which one runs is a security decision;
  `REMOTE_ONLY` is for a deployment that would rather deny a presentation than
  accept one on the weaker check.
  - `WalletConfig.preferLocalReaderTrustEvaluation` and
    `preferLocalIssuerTrustEvaluation` keep working and keep their meaning
    (`true` is `LOCAL_ONLY`), and are deprecated. An explicitly chosen mode
    always wins over them — read `effectiveReaderTrustEvaluationMode` /
    `effectiveIssuerTrustEvaluationMode` for the resolved value.

### Fixed
- **A trust evaluation that fails closed is no longer answered from the
  cache.** `evaluateTrustDirect` — the DC API and engine-relayed path — fell
  back to the local roots on *any* exception, so a backend that was reachable
  and refused the caller silently downgraded to the weaker check, and both of
  its callers would then answer from a positive `TrustCache` entry with no
  current remote evaluation at all. The refused-versus-unreachable rule now
  applies on that path too, and the two fail-closed cases raise
  `TrustEvaluationFailedClosedException`, which both callers honour ahead of
  the cache lookup. The cache keeps its degraded mode for the one failure it
  was meant for: an unreachable backend under `REMOTE_WITH_LOCAL_FALLBACK`.
- **An SD-JWT is no longer parsed as an mdoc.** `buildWith` called
  `parseMdocDocument` for every credential regardless of format; an SD-JWT's
  `.` separators hit the base64url decoder and threw, once per SD-JWT per
  registry refresh — and the registry refreshes on every credential change and
  every flow. The fallback was right, but the stack traces drowned out genuine
  issuance failures on a real device. The docType choice moves into
  `docTypeFor`, which parses only for `mso_mdoc`; a *genuine* mdoc that fails
  to parse still warns. (#204)
- **A credential offer URI with no authority is read correctly.** RFC 3986
  allows `openid-credential-offer:?credential_offer=…` with no `//`, and
  issuers emit it. `java.net.URI` calls that opaque and reports no query, so
  every parameter was invisible and the whole URI was handed to the engine as
  if it were the offer JSON. The query is now read from the scheme-specific
  part for an opaque URI.
- **A credential offer arriving on the wallet's own callback is recognised.**
  A same-device offer chooser delivers an offer through the registered
  redirect URI, where the classifier knew an authorization code and a
  presentation request but not an offer, so it returned `Unknown` and apps
  sent it down the presentation flow. It is now classified as an offer, after
  the authorization-code case, which still wins.

### Changed
- **A wallet lifecycle refusal now says whether it ends one device or the
  whole wallet.** SIROS adopts the EUDI wallet-unit lifecycle semantics
  exactly: revoking one instance ends that device and nothing else, and only
  deactivating the wallet is terminal. `WALLET_REVOKED` answered both and only
  the human-readable message differed, so the SDK took the one safe reading
  and kept the cached account on every refusal. go-wallet-backend#340 adds a
  machine-readable `scope` (`instance` / `wallet`), and this release consumes
  it as a third refusal, `DEACTIVATED`, alongside `SUSPENDED` and the now
  strictly per-instance `REVOKED`. Only `DEACTIVATED` forgets the cached
  account.

## [0.18.0] - 2026-09-17

### Fixed
- **The self-driven re-login no longer reuses a cut-off token.**
  `AuthServerClient` caches access tokens independently of `AuthTokens`, so
  clearing the latter left the pre-cut-off token to be served from that cache
  and refused with `401` on first use. The re-login now calls the new
  `AuthServerClient.clearTokenCache()`, which drops cached tokens without
  ending the session the way `logout()` would.

### Added
- **Wallet instance lifecycle: the SDK now speaks the whole protocol**
  (SID-AUTH-06, go-wallet-backend#319). The backend grew a token cut-off, an
  erasure retry and a passkey-ownership check on top of the instance API the
  SDK already called; the client side of each of those is here.
  - `WalletState.LifecycleBlocked(reason, message, cachedAccounts)` - a
    blocked wallet is a state, not an error. Entered from `login()`,
    `unlockKeystore()`, `resumeSession()` and from the SDK's own re-login
    whenever the authorization server answers `403` with `WALLET_SUSPENDED`
    or `WALLET_REVOKED`. Neither reason discards anything local - see the
    correction under **Changed** for why `WALLET_REVOKED` is not proof the
    wallet was erased - and the state carries the backend's own message so
    the app can tell the user which case it is.
  - **One self-driven re-login after a token cut-off.** Any lifecycle change
    refuses every token issued before it, so the reauthentication signal now
    drops the tokens, API client and engine session and attempts `login()`
    exactly once - never in a loop. A lifecycle `403` there goes straight to
    `LifecycleBlocked`, a success continues as a normal login, anything else
    is the existing error path. `WalletEventListener.onReauthenticationRequired`
    still fires first for hosts that drive their own prompt.
  - A successful `setWalletInstanceStatus` write re-logs in the same way, so
    suspending *this* device's own instance lands in
    `LifecycleBlocked(SUSPENDED)` rather than surfacing later as a stray 401.
  - `409 ERASURE_INCOMPLETE` is retried per the protocol: five attempts, 1 s →
    8 s, identical body. A `401` after such a `409` is the acting token being
    dropped with the erased key material and counts as complete.
  - `403 CREDENTIAL_NOT_OWNED` at WIA generation retries the request once
    without `credential_id` and clears the stale id, with a warning. The first
    link recorded for an instance wins, so the SDK never guesses another one.
  - `WalletInstance.isThisDevice` and `SirosWallet.thisInstanceId` - the
    instance-key JWK thumbprint the SDK already sends as `wallet_instance_id`
    - so a Devices screen can mark this installation and warn before
    suspending it.
  - Optional `WalletEventListener.onWalletLifecycleBlocked(reason, message)`,
    with a no-op default.
  - **Security: the instance key now survives a logout.**
    `SessionStore.clearAccount()` deleted `instanceKeyId`, so the next login
    minted a new key and registered a **new, active** backend wallet instance.
    A *suspended* installation could therefore walk away from its own
    suspension simply by logging out and back in. Only `clearAll()` (a factory
    reset) drops it now.
  - A session generation makes the self-driven re-login happen once per
    *session* rather than once per call (late 401s from requests issued before
    the cut-off can no longer each start another), refuses it when there is no
    session left to replace, and aborts it when the caller logged out or
    destroyed the wallet while the old session was being torn down.
  - A lifecycle block tears the session down locally instead of calling
    `logout()`: the unawaited `DELETE /auth/session` could otherwise land
    after the retry the app makes once a suspended instance is reactivated,
    invalidating the session that retry had just established.

- **Sample app: a Devices screen and a blocked-wallet login screen.**
  Settings → Devices lists this account's wallet instances (this-device badge,
  status, key storage, last attested, reason) with per-row Suspend /
  Reactivate / Remove and a footer that deactivates the wallet behind a typed
  confirmation, reporting whether the backend confirmed the erasure. The login
  screen renders `WalletState.LifecycleBlocked` as its own screen - suspended
  explains and offers a retry, revoked explains and offers a fresh enrollment -
  instead of a generic error. Strings in `res/values*/strings.xml` and the
  Transifex source `assets/i18n/en.json`.

### Changed
- **Correction: `WALLET_REVOKED` no longer forgets the cached account.** The
  design assumed that code meant the wallet had been deactivated and erased.
  It does not: the backend returns it for the login gate of a *single* revoked
  instance too, and only deactivates the wallet when the **last** non-revoked
  instance is revoked - the user's other devices keep logging in either way,
  and only the human-readable `message` distinguishes the two. Forgetting the
  account on a per-instance revocation destroyed the other passkeys that still
  worked. Both refusal reasons now end the session, keep the cached account,
  and show the backend's own message; re-enrollment is the user's call.
  `deactivateWallet` is the one place that still forgets the account, where
  the caller asked for it and the outcome is unambiguous.
- **Source-breaking: `WalletState` has a new subclass.**
  `WalletState.LifecycleBlocked` means an exhaustive `when` over `WalletState`
  no longer compiles without a branch for it (the sample app needed one). Add
  a branch, or an `else`, when upgrading.
- **`SirosWallet.deactivateWallet` and `BackendApiClient.revokeAllWalletInstances`
  return `DeactivationOutcome(revoked, complete)`** instead of a bare count.
  The revocations stand even when the backend's erasure cascade did not
  finish, so the local account is forgotten either way and `complete` is what
  the app tells the user (an incomplete erasure leaves residual server-side
  data for an administrator to clean up).
- **`setWalletInstanceStatus` takes a typed `WalletInstanceStatus`** on both
  `SirosWallet` and `BackendApiClient`. The `status: String` overload is
  deprecated and kept for one release; it rejects a value the backend would
  refuse instead of sending it.
- `AuthException` carries the server's user-facing `serverMessage` separately
  from its developer-facing `message` - it is what tells a suspended wallet
  from a revoked one for the user. (Binary-incompatible for direct
  constructor callers; source-compatible.)

## [0.17.0] - 2026-09-17

### Fixed
- **A presentation the wallet cannot satisfy now fails immediately instead of
  stalling** (go-wallet-backend#335). The WMP transport's match handler
  ignored the verifier's DCQL query and answered with every stored
  credential, so a wallet holding an mDL and no PID claimed a full match set
  for a PID request; it now runs the same `CredentialMatcher` as the other
  transports. When nothing matches, the wallet sends the engine's
  `credentials_matched` action with an empty match set and a reason, which
  ends the flow at once with `NO_MATCHING_CREDENTIAL` naming the credential
  types the verifier asked for - instead of sitting at credential selection
  until the five-minute user-interaction timeout, or reporting a decline the
  user never made. Needs go-wallet-backend#336 on the engine side; against
  an older engine the extra action is ignored and behaviour is unchanged.
- `no_match_reason` is carried on the wire by both transports
  (`WalletEngineSession.sendMatchResponse` gained the parameter; the WMP
  profile dropped the field entirely).
- An issuance parked on `authorization_required` because it required a
  presentation that then failed this way is reported to the app as failed
  too, rather than silently waiting out its own timeout.

### Added
- `CredentialMatcher.requestedCredentialTypes` - the credential types a DCQL
  query asks for (`vct_values`/`doctype_value`), for explaining what is
  missing.
- `WalletEngineSession.sendCredentialsMatched`.

## [0.16.0] - 2026-09-17

### Changed
- `siros-wscd-manager` 0.8.1 -> 0.9.1: key ids minted by the softkey and
  FIDO2 plugins are now RFC 7638 JWK thumbprints (existing ids keep
  resolving); FIDO2 plugin state restored via `registerFido2PluginWithState`
  now rebinds its keys to the plugin, so they no longer fall through to the
  default plugin after a restart.

## [0.15.0] - 2026-09-16

First release whose native crate dependencies are all on Maven Central, so
`mavenCentral()` alone resolves the SDK; and the first to ship the bridge
capability vocabulary (`bridge-capabilities-0.15.0.{json,ts}` attached).

### Added
- **Bridge capability vocabulary** (`spec/bridge-capabilities.json`): the
  capability descriptor a web-view wrapper app advertises to the page it
  hosts, shaped like WMP's capability map. Generated into
  `org.siros.sdk.transport.bridge` (`BridgeCapabilityId`, one parameters
  class per capability, `BridgeDescriptor`, `BridgeDescriptorBuilder`), into
  Swift for siros-sdk-swift, and into TypeScript attached to each release
  for the frontend's bridge contract package. CI fails if the generated
  files drift from the spec. See `spec/README.md`.
- README: consuming the SDK now needs only `mavenCentral()` - the five native
  crate AARs are on Central as of 2026-09-10 (backfilled; their release
  workflows publish there on every tag).
- `docs/TWO-APIS.md`: the SDK's two entry points - the orchestrated API
  (`SirosWallet`) and the low-level, flow-free composition of keystore, auth
  and credentials for hosts that run the OID4VCI/OID4VP flows themselves -
  with the composition a web-view wrapper uses for native ZK proving and
  proximity, and what the low-level API deliberately leaves out.
- `.github/actions/central-publish`: signs and uploads one AAR + POM to the
  Central Portal, completing the POM with Central's required metadata and
  attaching sources/javadoc jars. For the SDK's native crate dependencies
  (siros-wscd-manager, siros-dc-matcher, zk-cred-*), which publish a
  hand-rolled POM rather than through Gradle; `central-backfill-native.yml`
  republishes already-released versions from GitHub Packages, so a consumer
  of the SDK needs only `mavenCentral()`.

### Changed
- Maven Central deployments publish automatically once validated
  (`publishingType = AUTOMATIC`); 0.14.0 was published by hand from the portal.

## [0.14.0] - 2026-09-10

First release published to **Maven Central** as `org.siros:siros-sdk-*` with
`org.siros:siros-sdk-bom` - the first public SDK release. Otherwise identical
to 0.13.0.

### Added
- Publication to **Maven Central** on each release tag, via the Central Portal
  publisher API (Nmcp): all eight modules plus the BOM as one signed
  deployment. Artifacts are signed with the SIROS Foundation SDK signing key
  (`1877CD169960F999CB7B138AB3BA2844F54BCB99`, on keyserver.ubuntu.com and
  keys.openpgp.org). Each artifact gains a `-javadoc` jar (a pointer to the
  Dokka reference; Central requires the file). GitHub Packages publication
  continues unchanged.

## [0.13.0] - 2026-09-10

First release published to Maven (GitHub Packages) as `org.siros:siros-sdk-*`
with `org.siros:siros-sdk-bom`. The 0.12.0 tag (2026-09-07) never rolled this
section, so some entries below shipped in 0.12.0 already; everything since
0.11.0 is here.

### Fixed
- `startIssuance(offerUri)` unpacks `credential_offer` / `credential_offer_uri`
  from any scheme (`haip-vci://`, an upper-cased scheme from a QR code, an
  issuer's `https://` redirect page), not only from `https://` - the engine
  itself only unpacks lowercase `openid-credential-offer://`, so a `haip-vci`
  link previously reached it as the raw offer. The decision is the new
  `resolveIssuanceStart`, shared with the offer-display lookup.

### Added
- Circuit lifecycle for ZK proving. `ZkCircuitClient` takes a `cacheDir`
  and keeps fetched artifacts on disk under their catalog-published SHA-256
  (verified on every read as well as every download), and descriptors
  network-first with the cached copy serving when every source fails - so a
  circuit is fetched and verified once per device and a proof works with no
  network. `ZkProverResidency` bounds the process to one loaded prover
  (Longfellow circuit or Vega prover key, 100+ MB of native memory each):
  `LongfellowZkProofSystem` and `VegaProofSystem` take one, `ZkMdocPresentation.standard`
  shares one between them, and `ZkMdocPresentation.releaseProvers()` drops
  it. `SirosWallet` wires the cache under the app's `cacheDir` and releases
  the prover on `TRIM_MEMORY_UI_HIDDEN` / `onLowMemory`; a proof in flight
  finishes first. Replaces the two unbounded per-system prover maps.
- `org.siros.sdk.keystore.ZkMdocPresentation`: zero-knowledge presentation
  of a stored mdoc credential with no wallet and no Activity - resolve the
  verifier's `zk_system_type` list against the registered proof systems,
  run the prover, and assemble the `zkDocuments` DeviceResponse CBOR. Takes
  credential bytes, a session transcript, requested claims, an optional
  verifier identity and a `ZkWitnessSigner`; the device key never enters
  it. `SirosWallet.zkPresentation` exposes the wallet's instance, and both of
  the wallet's ZK paths (DC API and `sign_presentation`) now go through it.
  The assembly used to be a private method of `SirosWallet`.
- Public-API dumps (`sdk/<module>/api/<module>.api`, Kotlin
  binary-compatibility-validator) for every published module, checked by
  `apiCheck` in CI. An intended signature change is recorded with `apiDump`
  and reviewed as a diff.
- Maven publication. Every `:sdk:` module publishes `org.siros:siros-sdk-<module>`
  (AAR, sources, POM with BSD-2-Clause/scm metadata, Gradle module metadata)
  plus `org.siros:siros-sdk-bom`, to GitHub Packages on each release tag;
  `publishToMavenLocal` works for local consumers. The version is
  `sdkVersion` in `gradle.properties`, overridden from the tag in CI. The
  release workflow's publish step used to be a no-op (`|| echo skipping`)
  and now fails loudly instead.
- The platform components a host app needs for DC API and NFC engagement now
  ship in the SDK and are merged into the app manifest automatically:
  `org.siros.sdk.wallet.dcapi.DCAPIGetCredentialActivity` (the Digital
  Credentials API `GET_CREDENTIAL` entry point, translucent theme
  `Theme.SirosSdk.DcApiHost`, GPM privileged-app allowlist) and
  `org.siros.sdk.keystore.mdoc.MdocHostApduService` (ISO 18013-5 §9.2.1 NFC
  static handover, with its `host-apdu-service` descriptor). A host app
  keeps `WalletSessionHolder` pointed at its unlocked wallet and sets
  `ActiveEngagement.handoverSelectBytes` while an engagement is shown, and
  declares nothing else. Both were previously sample-app code every
  integrator would have had to copy.
- `org.siros.sdk.keystore.OkHttpR2psTransport`, the default
  `R2psTransportProvider`, moved into the SDK from the sample app (Swift
  counterpart: `URLSessionR2psTransport`).
- Wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319):
  `SirosWallet.listWalletInstances()`, `setWalletInstanceStatus()` and
  `deactivateWallet()` (revokes every instance server-side, then forgets the
  local account), backed by the new `WalletInstance` type and
  `BackendApiClient` methods. WIA generation now sends the logged-in passkey's
  `credential_id` so the backend can link the instance to the passkey.
  `AuthException.errorCode` now carries the AS's error code, so a 403
  `WALLET_SUSPENDED` / `WALLET_REVOKED` login refusal is distinguishable
  from a plain authentication failure.

- Answer the engine's `sign_client_auth` sign request (go-wallet-backend#317,
  wallet-frontend#282) on both the legacy engine transport and WMP: sign the
  RFC 9449 DPoP proof and a fresh OAuth client attestation PoP for each
  request with the instance key - the same key the Wallet Instance
  Attestation binds as `cnf` - and report it as `dpop_key_id`, so the
  DPoP-bound token is bound to the attested key and no PoP is ever replayed.
  `KeystoreManager.generateDPoPProof` is the new keystore primitive
  (`JweKeystore` and `WscdKeystoreAdapter` implement it). `dpop_key_id` from
  `flow_complete` is persisted with the refresh token
  (`CredentialRefreshTokenEntry.dpopKeyId`) and presented back on renewal.
  The WMP sign sub-flow also answers `request_attestation` now. Requires a
  backend with go-wallet-backend#318; older backends never send the action.

### Changed
- `WalletSessionHolder` moved from the sample app to
  `org.siros.sdk.wallet.dcapi`; `ActiveEngagement` to
  `org.siros.sdk.keystore.mdoc`. The SDK's own strings are prefixed `siros_`
  and can be overridden by a host app by name.

## [0.11.0]

Highlights since v0.10.0 (1 commit). Sample app: versionName 0.11.0, versionCode 11.

### Fixed
- NFC static handover: send the mandatory "Complete List of 128-bit Service
  UUIDs" AD (type `0x07`) in little-endian byte order, sending only the
  single UUID matching the LE-Role-preferred mode - a real reader rejected
  a 2-UUID AD outright and otherwise saw no UUIDs at all in our handover
  message (#147)
- BLE central-client mode: restart the scan window at the moment a real NFC
  tap actually completes handover, instead of trusting a window that
  started when the presentation screen mounted - the first scan attempt
  reliably timed out before a real tap completed (#147)
- BLE central-client/peripheral-server: distinguish a peer's own
  session-termination status from an unexpected data-carrying message once
  the session is already established, replying only in the latter case
  (#147)
- BLE central-client mode: add a grace delay before signaling end-of-transfer
  after the final response chunk - sending it immediately raced a real
  reader's background verification thread (#147)

## [0.10.0]

Highlights since v0.9.0 (1 commit). Sample app: versionName 0.10.0, versionCode 10.

### Fixed
- Register `mdoc-openid4vp://` (ISO 18013-7 Annex B's mdoc-specific OpenID4VP
  scheme) in the manifest's intent-filter and `DeepLinkClassifier` - a link
  using this scheme was silently dropped as `Unknown` before reaching the
  app at all, since Android has no intent-filter to route it through
  (#145)

## [0.9.0]

Highlights since v0.8.0 (16 commits). Sample app: versionName 0.9.0, versionCode 9.

### Added
- DC API/OpenID4VP: run the shared DCQL matching engine alongside the built-in
  matcher, then let it decide which credentials actually qualify (#138, #140)
- Delete button next to Renew on fully-exhausted ("shadow") credential cards -
  previously the only way to remove one was renewing it first
- Wired RICAL reader-trust controls into the in-session Settings tab (#129)

### Fixed
- BLE peripheral-server mode: fixed a permanent-hang bug where a stale session
  from a prior connection attempt silently swallowed every retry with no
  response and no completion callback, leaving the presentation screen stuck
  indefinitely - added a bounded overall timeout and an explicit session-
  termination status instead of silently dropping late messages (#143)
- BLE: both roles now report failure when their own connection attempt never
  completes, instead of hanging forever waiting for the other role (#135, #137)
- `eligibleInstances` (and the credential-list "shadow" display state) now
  also checks signing-key availability, not just consumption count, so a
  credential with a lost key can no longer masquerade as usable (#139)
- A `null` `kid` on a stored credential no longer silently masks a lost key
  binding (#142)
- The default ("softkey") WSCD plugin's private keys now correctly survive an
  app restart - a JSON-shape mismatch at the Rust/Kotlin FFI boundary
  (`UniFFISigner.exportPrivateKeypairs()`) was silently dropping every
  generated key before it ever reached persisted storage, making any
  softkey-issued credential look "shadow" (no available key) after the very
  next cold start
- A property-ordering bug (`fido2RegisteredTransport` read before its own
  declaration during `wallet`'s eager construction) silently degraded FIDO2
  plugin registration to a stateless instance every cold start
- `SessionStore.privateDataJwe` now persists with a blocking, durable write
  instead of `SharedPreferences.apply()`'s async flush, closing a window
  where a hard-kill shortly after credential issuance could lose the
  just-written encrypted key container
- Engine WebSocket: disconnect a prior session before reconnecting, instead of
  leaking a duplicate concurrent client (#141)
- DC API/OpenID4VP x5c trust checks now have a local-anchor fallback path
  (#132), and a decline now returns a real structured OpenID4VP error
  response instead of an opaque exception (#130)
- Fail closed on an explicit trust-evaluation denial rather than falling back
  to local validation (#127)
- CI: trigger the Play Store upload from the tag, not `release: published`
  (#128)

### Changed
- DC API registration now lives in the SDK, on our own matcher (Phase 6, #131)
- Target API 36 (Android 16) (#134)

## [0.8.0]

Highlights since v0.7.0 (12 commits). Sample app: versionName 0.8.0, versionCode 8.

### Added
- `VegaProofSystem`: real Vega ZK mdoc proving, end-to-end tested against a live
  verifier on device (#116)
- `BbsProofSystem`: the blind BBS presentation path (#117), plus the wallet's half
  of blind BBS issuance (#123)
- Our own DC API credential matcher, Phase 1, behind the `-PcustomDcMatcher` build
  flag (#118)
- VICAL-based issuer-trust evaluation for mdoc presentation (#114)
- Sample app: a "Computing proof…" indicator during Vega ZK proof generation, so the
  multi-second prove step is no longer a silent freeze (#124)
- `prepProve`/`prove` timing logs for ZK proof generation (#119)

### Changed
- `ZkProofSystem` generalized beyond mdoc-only, so non-mdoc credential formats can
  plug into the same proving interface (#115)
- `zk-cred-vega` bumped to 0.0.5 (r12 circuit revision) (#119, #125)
- Sample app requests `largeHeap`, which the Vega prover-key decompression needs (#120)

### Fixed
- Circuit decompression no longer double-buffers the decompressed artifact, roughly
  halving peak memory for both Vega and Longfellow (#122)
- AndroidSVG full-bleed `<image>` dark-band mis-render in credential logo previews (#121)
- BLE session-establishment callback race during proximity presentation (#114)
- Blank logo square for SVG credential logos (#114)

## [0.1.0]

### Added
- Initial SDK with 7 modules: transport, auth, keystore, flow, credentials, wallet, passkey-provider
- Sample app demonstrating registration, login, issuance, and presentation flows
- CI pipeline with build, test, and coverage gate (25%)
- CONTRIBUTING.md and ARCHITECTURE.md

### Fixed
- WmpSessionException and WmpTimeoutException now extend SirosException
- Redacted credential IDs and session UUIDs from log output

---

Releases v0.2.0 through v0.7.0 predate this changelog being kept up to date; their
notes are auto-generated on the corresponding
[GitHub release](https://github.com/sirosfoundation/siros-sdk-kotlin/releases).
