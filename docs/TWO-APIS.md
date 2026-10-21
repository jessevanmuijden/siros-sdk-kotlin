# The SDK's two APIs: orchestrated and low-level

The SIROS SDK for Android is one Gradle BOM but two ways in, and which one
you take is the first integration decision.

| | Orchestrated ("flow-full") | Low-level ("flow-free") |
|---|---|---|
| Entry point | `SirosWallet` (`org.siros:siros-sdk-wallet`) | `siros-sdk-keystore`, `siros-sdk-auth`, `siros-sdk-credentials` composed by you |
| Who runs OID4VCI / OID4VP | the SDK, through the engine backend over WMP | **you** - typically a web page in your WebView, or your own engine client |
| Who talks to go-wallet-backend | the SDK (`flow` + `transport` modules) | you |
| Who owns the private-data container | the SDK (login, sync, lock) | you import and export it around each operation |
| Consent / credential picker UI | your app, driven by SDK state | your app, driven by your own flow |
| Typical host | a native wallet app (the sample app) | a web-view wrapper app, or an app with its own protocol stack |
| Everything below the line | included | included |

Both APIs are the same code underneath: `SirosWallet` is a facade over the
lower modules, not a second implementation. Everything the facade can do
natively - device keys and WSCD plugins, passkeys with PRF, security keys
over CTAP2, mdoc/SD-JWT parsing and DCQL matching, ZK proving, ISO 18013-5
proximity, host card emulation, issuer and reader trust evaluation - is
reachable without it.

## Why the split exists

The module graph enforces it:

```
credentials  <-  keystore  <-  auth  <-  flow  <-  wallet
     ^             ^           ^         ^
  transport -------+-----------+---------+
```

Only `wallet` depends on `flow`, and `flow` is where the OID4VCI/OID4VP
orchestration and the engine conversation live. A host that already runs the
protocol - the SIROS web wallet inside a wrapper app is the canonical case -
does not want a second protocol stack in the process, but it does want the
native pieces underneath: hardware-bound keys, native ZK speed, a Bluetooth
stack that does reader authentication. Constructing `SirosWallet` would drag
the engine in; composing the three lower modules does not.

This is a supported way to use the SDK, not a loophole: the three modules'
public APIs are covered by the binary-compatibility dump in `sdk/*/api`, and
the [native capability bridge](../spec/README.md) is built on exactly this
composition.

## Choosing

Use the **orchestrated API** when your app *is* the wallet: it has no other
protocol stack, and you want issuance and presentation to work by handling
`WalletState` and calling `acceptIssuance()` / `acceptPresentation()`. Start
from the sample app.

Use the **low-level API** when:

- your app hosts the SIROS web wallet (or another page) that already runs the
  flows, and native is there for keys, proving and proximity;
- you have your own OID4VCI/OID4VP client and only want SIROS's credential
  handling and key management;
- you are building something that is not a wallet but needs one of the
  capabilities - a verifier reading mdocs over BLE, a service that evaluates
  issuer trust.

Do not mix the two for the *same* container in the *same* process: the facade
assumes it is the only writer of the private-data container it unlocked.

## The low-level composition

The pieces, and what each needs from the host:

| Module | Class | Needs | Gives |
|---|---|---|---|
| keystore | `JweKeystore` | nothing | the PRF-sealed container: `unlock(prfOutput, container, hkdfSalt, hkdfInfo)`, `exportEncryptedContainer()`, `generateKey`, `sign`, SD-JWT KB-JWT / mdoc device auth |
| keystore | `UniFFISigner` + `WscdKeystoreAdapter` | an `AuthProvider` for PIN prompts if a plugin needs one | the same `KeystoreManager` surface, keys held by a WSCD plugin (software, FIDO2 security key over CTAP2, R2PS remote HSM) |
| keystore | `ZkMdocPresentation.standard(ZkCircuitClient(cacheDir = ...))` | a cache dir; a `ZkWitnessSigner` that signs the witness with the device key | `systemIds()`, `present(request, signer)` -> a ZK mdoc device response |
| keystore | `MdocProximitySession` | a `Context` for the BLE transports; callbacks for credentials, consent, device signature, reader trust | a complete ISO 18013-5 session over BLE (central or peripheral), NFC static handover via `MdocHostApduService` |
| auth | `CredentialManagerAuthProvider(context)` | a `Context` | passkey registration/assertion with PRF; security keys over the SDK's CTAP2 transports |
| auth | `AuthServerClient(baseUrl, tenantId)` | nothing | the passkey challenge/response conversation with the auth server, if you use SIROS's |
| credentials | `CredentialMatcher`, `MdocCbor`, `SdJwtParts`, `VctmFetcher` | nothing | parsing, DCQL matching, display metadata |
| credentials | `ZkCircuitClient` | a cache dir | circuit catalog client with hash-verified disk cache |

A wrapper app that hosts the web wallet and takes ZK proving and proximity
natively (stage A of the bridge plan) composes:

```kotlin
// Once per process.
val circuits = ZkCircuitClient(cacheDir = File(context.cacheDir, "siros-zk-circuits"))
val zk = ZkMdocPresentation.standard(circuits)          // Longfellow + Vega, one resident prover

// Advertise what is native - the page picks native or in-page per capability.
val descriptor = BridgeDescriptorBuilder(platform = "android", host = BridgeHost(appId, appVersion, sdkVersion))
    .zk(ZkCapability(systems = zk.systemIds(), circuitCache = true))
    .proximitySession(ProximitySessionCapability(transports = listOf("ble_peripheral"), nfcStaticHandover = true))
    .encode()

// Per proof: the page supplies the credential bytes and transcript; the
// device key stays in the page's keystore, so the witness signature is a
// callback into it.
val response = zk.present(
    ZkMdocPresentation.Request(
        credentialBytes = mdocBytes,
        requestedSystems = requestedSystems,        // ZkSystemSpec list from the verifier's request
        sessionTranscript = sessionTranscript,
        requestedClaims = requestedClaims,
    ),
    signer = ZkWitnessSigner { algorithm, data -> bridge.signWitness(algorithm, data) },
)

// Per proximity presentation: the SDK runs engagement, transport, session
// encryption and reader authentication; the page stays the source of
// credentials, consent and signatures.
val session = MdocProximitySession(
    engagement = DeviceEngagement.create(supportsPeripheralServerMode = true),
    getCredentials = { bridge.listMdocs() },
    requestConsent = { req -> bridge.askConsent(req) },
    signPresentation = { id, claims, transcript -> bridge.signDeviceAuth(id, claims, transcript) },
    evaluateReaderTrust = { x5chain -> readerTrust.evaluate(x5chain) },
    // ...
)
```

A host that owns the keys itself (stage B) adds the keystore, importing and
exporting the container around each session so the page remains its writer:

```kotlin
val keystore: KeystoreManager = JweKeystore()          // or WscdKeystoreAdapter(UniFFISigner(config, pinProvider))
keystore.unlock(prfOutput, containerFromPage, hkdfSalt, hkdfInfo)
val keyId = keystore.generateKey("ES256")
val sig = keystore.sign(keyId, payload)
val updatedContainer = keystore.exportEncryptedContainer()  // hand back to the page
keystore.lock()
```

The PRF output that unlocks the container comes from a passkey assertion:
`CredentialManagerAuthProvider(context).authenticate(AuthenticateOptions(rpId, challenge, prfSaltsByCredential = ...))`
returns `AuthenticateResult.prfOutput`. The salt per credential is whatever the
container was sealed with - see the account registry pattern in
`SirosWallet.loginCandidates` if you need to mirror the facade's behaviour.

## What the low-level API deliberately does not include

- **The engine conversation and OID4VCI/OID4VP orchestration.** That is the
  `flow` module, and taking it means taking the facade. (The facade also holds the
  response-encryption keys of an issuance and builds the encrypted `direct_post.jwt` response itself, so the engine
  never sees a credential, a delivered seed or a `vp_token`; the primitives, `CredentialResponseKey` and
  `AuthorizationResponseEncryption` in `sdk:keystore`, are usable without it.) If a native WMP engine
  ever exists it will be advertised as one more bridge capability, not bolted
  onto the low-level API.
- **Private-data sync with go-wallet-backend.** `SirosWallet.fetchPrivateData`
  / the ETag-based writer are facade concerns. Low-level hosts move the
  container themselves (a web-view host: the page already syncs it).
- **Issuer identity for trust evaluation.** `MdocIssuerIdentity` (issuer URL
  from the IACA certificate's SAN, the subject id the PDP expects) currently
  lives in `sdk:wallet`; a low-level host evaluating issuer trust derives it
  itself until it moves down to `credentials`.
- **Account bookkeeping.** `AccountRegistry`, session stores and the
  login-after-logout salt handling are facade-level; the low-level API takes
  PRF output and container bytes as inputs and does not remember them.

## Stability

Both APIs are versioned together in the same release and the same BOM. The
low-level surface is what the binary-compatibility check guards
(`./gradlew apiCheck`); a signature change in `keystore`, `auth` or
`credentials` is a reviewed diff in `sdk/<module>/api/<module>.api`, exactly as
for `wallet`. Deprecations follow the same one-release grace as the facade.
