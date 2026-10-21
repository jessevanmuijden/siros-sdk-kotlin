# Changelog

All notable changes to the SIROS SDK for Android will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Private data: `S.schemaVersion` 4** (privatedata-spec 3.0,
  https://github.com/sirosfoundation/privatedata-spec/pull/9 at 8ca8860). `JweKeystore`
  now writes `S.schemaVersion` 4 (it wrote 3). A version 3 container it rewrites is
  migrated by that number alone; everything else is carried through unchanged, including
  unknown members of `S`, of credential entries and of `metadata` entries. `S.credentials[].metadata`
  and `S.extensions` are version 4 members, so they are only ever written into a version 4
  container (the SDK always rewrites at 4); containers written earlier that already carry them
  under version 3 are read as version 4. The SDK emits no events and does not fold or merge them,
  so event stamping and the ETag/`If-Match` handling are unchanged.
- **Breaking for clients still on version 3 only:** wallet-frontend (and older SDKs) that do not
  implement version 4 will refuse to rewrite a container this SDK has rewritten, until updated.
- The vendored privatedata-spec vectors are re-copied verbatim from 8ca8860 (with the fixtures
  they reference); `vectors.PROVENANCE.txt` records the commit and digests.

### Added
- **`UnsupportedSchemaVersionException`** (`errorCode` `unsupported_schema_version`; `kind`
  `STATE_VERSION`, `EVENT_VERSION` or `EVENT_TYPE`). `JweKeystore.exportEncryptedContainer()`
  throws it, before building or storing anything, when the unlocked container has an
  `S.schemaVersion` other than 3 or 4 (absent counts as 1; 1 and 2 are not migrated here), an event
  whose `schemaVersion` is not 1 to 4 or is missing, or an event type the implemented versions do
  not define (`set_extension` only from version 3 events on, as written by spec 2.1 to 2.8 clients).
  Reading is unaffected, so credentials stay usable. `SirosWallet` reports it as its own
  `onFlowError("sync", ...)` and neither stores nor uploads the container, so the backend copy is intact.
  Previously such a container was silently rewritten as version 3.

- **Holder-generated pseudonym commitment (`org.siros.psc`) in the OpenID4VCI
  proof JWT** (tracking issue https://github.com/SUNET/vc/issues/823). When the
  engine's `generate_proof` sign request (legacy engine and WMP sign sub-flow)
  carries `holder_commitments: ["psc"]` with `credential_type` and
  `credential_issuer`, the wallet adds the claim `org.siros.psc` =
  base64url-without-padding of the 32-byte `psc` to the `jwt` proof payload
  before signing. The issuer string is used verbatim (a trailing slash is a
  different commitment). Fail-closed: an unknown commitment name, a missing
  type/issuer, a keystore that is not a `HolderWitnessSource`, an
  attestation-type proof, or a value that is not 32 bytes fails the flow instead
  of sending a proof without the claim, and still runs `onWscdOperationEnd`. The
  commitment is `HolderWitnessSource.privateSeedCommitment(type, issuer)` (seed v2). The value is never logged. New:
  `KeystoreManager.generateProof(..., extraClaims)`
  (non-empty claims refused by a conformer that cannot place them),
  `SignRequestParams`/`SignSubFlowParams` members.
- Holder commitment consistency: the issuer string a commitment was derived for
  is stored with the issued credentials (also when issuer display metadata could
  not be fetched), and a fresh registration unlocks the other keystores from the
  exported container instead of independent empty ones, so every keystore derives
  the same `psc` before and after login.
- **`PSC_CONFLICT` as a typed error.** The issuer's refusal of a different
  pseudonym commitment (before anything is issued, so nothing to roll back) is
  delivered as `WalletEventListener.onPseudonymCommitmentConflict`
  (`PseudonymCommitmentConflictException`, `errorCode = "psc_conflict"`,
  `userMessageRes` = `siros_psc_conflict`, added in default/sv/fi/el/pt; the
  translations are unreviewed). The default implementation forwards the issuer's
  text to `onFlowError`.
- **User consent for `circuit_zk` presentations.** One `PresentationConsentHandler`
  (a sibling of `TransactionConsentHandler`, not coupled to `transactionDataEnabled`;
  wallet-level `SirosWallet.presentationConsentHandler`, per request through a new
  `presentationConsentHandler` parameter of `handleDCAPIRequest` and `handleDCAPIRequestWithPresentationConsent`)
  is asked once for ALL queries of a request, before anything is signed or proved and before
  the issuer-delivered secret seed is fetched. `handleCircuitZkDcApi` now runs in two phases:
  phase 1 (validation, trust, the user's pick, local age check, verifier id, consent items)
  touches no secret; phase 2 (seed, sign, prove) runs only after consent. A decline, a handler
  that throws, the SDK-side two-minute time limit and a cancelled activity are all a decline
  (`DCAPIRefusalReason.USER_DECLINED`) with zero seed, signer and prover calls; with no handler
  the request is refused (`DCAPIRefusalReason.CONSENT_UNAVAILABLE`, answered `access_denied`).
  The model (`PresentationConsentRequest`, `ConsentVerifier`, `CredentialRef`, `ConsentEntry`,
  `ConsentItem.{Claim,Predicate,Pseudonym,LegacyPseudonym}`, `AgeForm`, built by
  `ConsentRequests.build`) says what the verifier will receive and never carries a claim value,
  seed, proof or pseudonym value; the age range is precomputed (born between / at least / at most).
  `PresentationConsentText` is the SDK-owned wording (default, sv, fi, el, pt), parameterised per
  item; the trust framework and `verifier_id_type` are in the model but never in the text. The DC
  API activity shows it in a plain dialog after the OS picker. Cross-SDK vectors:
  `spec/circuit-zk-consent-vectors.json` (generator `tools/gen_circuit_zk_consent_vectors.py`).
  The sample app renders the same model in Compose (`PresentationConsentDialog`).
  Predicates are not about `birth_date` alone: the `circuit_zk` function set is open-ended, so the consent item
  is a generic `ConsentItem.Predicate` (function, claim with the credential's OWN display label, comparisons
  `eq ne lt le gt ge in`, operands; what the verifier learns, never the value) and functions are declared as data
  (`PredicateFunctions`, `WalletConfig.circuitZkPredicateFunctions`, default `age_check`, which keeps the approved
  "born between / at least / at most" wording). Generic wording per comparison (default, sv, fi, el, pt) says
  "{claim} is at least {value}" and that the actual value is not shared. A function that is not declared is refused
  before consent (the wallet cannot describe it). The local pre-check is driven by the same declarations (dates,
  numbers, strings, bools; a claim path or format the reader cannot judge is skipped, not guessed), and the
  cross-query rule is generalised: per credential and claim path, predicates are intersected across queries and a
  function's declared minimum selectivity is enforced (`age_check`: 365 days); functions that declare none have
  no merge rule. `intermediary_risk` is read from the PDP's `context.intermediary_risk` (boolean, optional) and is
  PROVISIONAL until go-trust defines it.
  A DATE-typed claim has its own operator sentences ("is on or after {date}", "is after", "is on or before",
  "is before", "is on", "is not on", "is one of the dates: ..."; `siros_consent_predicate_date_*`), numbers and strings
  keep the generic wording, and the age wording of `age_check` still wins. Vectors: `date_compare` cases.
  The consent wording (all five locales) was approved by leifj on 2026-10-20.
  Predicate functions are ONE declaration (`PredicateFunction`): it drives consent, the local pre-check, the
  cross-query merge rule AND the validator's per-function rules (`PredicateFunction.validatorRules()`, rule ids
  `<function-id-with-dashes>-count|no-bounds|bad-date|bad-operand|bad-claim|le-before-ge|span-short`; `age_check`
  keeps its rulebook ids). `RulebookCircuitZkValidator`/`CircuitZkRuleSet.rulebookV03(predicates=...)` and the
  wallet's default validator take the declared functions. The presenter's handler for a predicate is the generic
  `PredicateFunctionHandler(declaration)` (`holds` is `PredicateFunctions.holdsFor` over an mdoc claim reader);
  `AgeCheckFunctionHandler` and `DeclaredPredicateHandler` are gone, and the handler registry keeps only hook-style
  functions (`HOOK_CIRCUIT_ZK_HANDLERS`: the pseudonym, the legacy disclosure). `FakeCircuitZkProver.optIn(predicates)`.
  Known follow-up (not filed): the approved year strings use `%d` with words, so fi/el (and sv/pt as needed)
  need proper plural resources.
- **`CatalogCircuitZkProver`: the real `circuit_zk` prover, and the wallet's
  default.** `WalletConfig.circuitZkProver = null` now means the catalog prover
  (it was "refuse every request"); `FakeCircuitZkProver` stays an explicit
  opt-in (`WalletPolicyOptions.fakeProver`) for tests and development. The
  prover fetches the chosen circuit's catalog descriptor (it must be published,
  `active` and not deprecated) and dispatches to the `CircuitZkSystemAdapter`
  registered for its (`system`, `systemVersion`) in a `CircuitZkSystemRegistry`;
  a system or version nobody claims is refused, never routed to a default or to
  the fake. Two adapters ship. `NymAuthCircuitZkAdapter`: the `nymauth-*` mdoc
  circuits (`pseudonym-v1-sha256` with `known-offender-matching-ssc`, `age_check`);
  everything that can be done in Kotlin is real (descriptor checks, hash-verified
  and decompressed-hash-verified artifact, residency, device-key signing of the
  challenge through `ZkWitnessSigner`, issuer key, T/E/C, verifier input,
  pseudonym cross-check against `NymPseudonym`), and the witness construction
  and proof run behind one seam, `NymAuthNativeProver`
  (`WalletConfig.circuitZkNativeProver`): until a native binding implements it
  this adapter refuses. `LegacyZkCircuitZkAdapter`: Longfellow (`longfellow`
  6-8) and Vega-mc (`vega-mc` 12) through the existing `ZkMdocPresentation`, so
  the real proof systems, their shared `ZkProverResidency` and `VegaProofCache`.
- **Catalog refresh: a retired circuit is expunged as soon as the SDK sees it.**
  `ZkCircuitCatalogRefresher` (started by the wallet while `circuit_zk` is on: at
  start, every six hours and when a network becomes available; background,
  fail-soft, no UI) fetches the manifest and makes the cache match it. A circuit
  the manifest does not list as published, `active` and not deprecated, or no
  longer lists at all (a complete manifest, `next` absent), loses its cached
  descriptor and its cached artifact (unless an active circuit uses the same
  artifact hash) and its resident prover memory (`ZkProverResidency.releaseCircuit`,
  Vega's proof cache). A partial page (`next` set) retires only what it lists as
  not active. A cached descriptor of an active circuit is replaced by the
  manifest's. A proving-path fetch that sees a retired descriptor expunges it
  too. Offline (no manifest) nothing changes: cached circuits stay usable until a
  refresh reaches the catalog, with no age limit. Also: artifacts are fetched
  against the catalog's declared size (absent or over the ceiling is refused),
  catalog bodies and artifacts are read with a hard limit, the zstd frame's size
  must equal the catalog's `uncompressed.size`, and an `OutOfMemoryError` or a
  missing native library in a prover is a refusal, not a crash. The proof time is
  the device clock and is not bounded by the wallet (the verifier enforces its
  tolerance on `proof_time`); a sanity window or trusted time is deferred. An empty
  `verifier_id` is refused, and the derived `private_seed` is zeroed after a
  presentation.
- **The nymauth native seam's errors are typed.** `NymAuthNativeException`
  (`NymAuthNativeErrorKind`, a coarse `NymAuthRefusal`, no message of the binding) is a
  superset of the Vega (`InvalidInput`, `InvalidShapes`, `UnknownCircuit`, `Refused{code}`,
  `ProverFailed`, `ProofInvalid`, `Mismatch`, `Internal`) and Longfellow (`InvalidInput`,
  `Circuit`, `UnsupportedCircuit`, `Credential`, `Unsatisfied`, `Prover`, `Verification`)
  error types (`NymAuthNativeException.vega(..)` / `.longfellow(..)`). The adapter refuses on
  each, with an internal reason and a log line that names only the kind and the circuit id; the
  verifier still gets the bare `access_denied`. `UnknownCircuit` / `UnsupportedCircuit` mean "this
  app version does not support this circuit build": a distinct reason
  (`CIRCUIT_UNSUPPORTED_BY_APP`), the resident circuit is dropped, and
  `NymAuthCircuitZkAdapter.onUnsupportedCircuit` / `unsupportedCircuits` let a wallet say "update the app".
- **The nymauth native prover is real: `UniffiNymAuthNativeProver`.** It drives the UniFFI bindings of `zk-cred-vega`
  (`nymauthVegaLoadKeys` then `nymauthVegaProve`; system `vega-nymauth`) and `zk-cred-longfellow`
  (`nymauthInitializeProver` then `nymauthProve`; system `longfellow-nymauth`, params `block_enc_hash`, `block_enc_sig`,
  `hash_circuit_id`, `sig_circuit_id` from the catalog descriptor), keeps ONE built circuit resident (keyed by system,
  circuit id and artifact hash; dropped on memory pressure, on a retired circuit, or when another circuit is loaded), and
  cross-checks the binding's own challenge-digest derivation against the digest the device key signed. It is the default
  for `WalletConfig.circuitZkNativeProver = null`; a build whose libraries lack the nymauth entry points refuses instead of
  crashing. A `CatalogCircuitZkCircuitSource` keeps the `circuit_zk` circuit table in step with the catalog, and the sample
  app uses it (and the real prover) unless the request policy's fake-prover switch is on. The libraries are PR builds until
  released: pins, versions (`zk-cred-vega` 0.0.6, `zk-cred-longfellow` 0.1.2), the vendored bindings and the local
  override (`-PsirosNativeRepo=<dir>`, `tools/build-native-aars.sh`) are in docs/NATIVE_DEV.md.
- **`sign_client_auth`: a DPoP proof that was asked for and could not be made is no longer answered with a bare key id.**
  `buildClientAuth` named the key first and then logged and swallowed any exception from `generateDPoPProof`, so the engine
  saw a key id with no proof and failed the token exchange with the misleading "client returned no DPoP proof". Now, when
  `htm`/`htu` are set and no proof results, the reply carries no key id (the engine then falls back to its own key or
  reports a real reason) and a warn line names the reason (`keystore_locked`, or the exception class and a short message):
  `sign_client_auth for flow <id>: a DPoP proof was asked for ... (reason=...); answering WITHOUT a key id`. The DPoP key
  is, and stays, the instance key of the default keystore (the WIA's `cnf` key), not the keystore resolved for
  credential key proofs.
- **New permission: `android.permission.ACCESS_NETWORK_STATE`** (normal, install-time), declared in `sdk/wallet`'s manifest and merged
  into the host: the circuit catalog refresh also runs when a network becomes available.
- **The nymauth adapter runs the validator's rule set (CIRCUIT-6).** The adapter refuses every plan the wallet's
  `RulebookCircuitZkValidator` refuses (restricted to `known-offender-matching-ssc`: an age span under 365 days, `le`
  before `ge`, a `verifier_context`, the reserved meta members, ...) on top of its own shape checks; a vector-driven
  test over `spec/circuit-zk-validator-vectors.json` asserts both directions for every plan the circuit could prove.
  The validator and its vectors are unchanged.
- **`private_seed` is per issuer (privatedata-spec 2.7, label `org.siros.private_seed/v2`).**
  `private_seed = HKDF-SHA256(mainKey, salt = "", info = label || lp(credentialType) || lp(issuer))[:16]`,
  `psc = SHA-256(private_seed)`, `lp(x)` = 2-byte big-endian length then the UTF-8 bytes; an empty field or one over
  65535 bytes is refused (no seed). The issuer is the Credential Issuer Identifier exactly as the credential stores
  it (`credentialIssuerIdentifier`, no normalisation: a trailing slash is another psc), so different issuers see
  different psc values for one person. `HolderWitnessSource.privateSeedCommitment(credentialType, issuer)`,
  `CircuitZkWitnessProvider.witness/privateSeedMatches` and `CircuitZkFunctionHandler.commitmentCheck` take the
  issuer, `CircuitZkPresenter.Request.issuer` carries it (null refuses a function that needs the device seed) and
  `handleCircuitZkDcApi` passes the stored identifier. The spec's `derived-secrets.json` is vendored verbatim
  (privatedata-spec `1b796d2`): all 11 vectors, the 4 refused inputs and the 5 must-differ pairs reproduce. The
  v1 label was never released; `spec/private-seed-vectors.*` and its generator are removed.
- **PROPOSAL: `zk-claim-disclosure-v1`, a `circuit_zk` function for the legacy
  proof systems** (`CircuitZkLegacyDisclosure`; the id is one constant, the
  rulebook owners decide the name). Params `claims`, `systems` (the verifier's
  `zk_system_type` specs), optional `pseudonym` (+ `verifier_context`). Result:
  `true`, or the proof system's legacy 32-byte pseudonym (not the rulebook's;
  a system that returns none is refused). `proof` is the ZK `DeviceResponse`
  the `mso_mdoc_zk` path builds. `age_check` and `pseudonym-v1-sha256` stay
  nymauth-only. The default validator accepts it
  (`CircuitZkRuleSet.withFunction`); `SirosWallet.circuitZkCircuitsOf(manifest)`
  builds a circuit table in which legacy catalog entries are offered for it.
- **Issuance start is visible at once.** `startIssuance` and
  `startIssuanceByOffer` now publish `WalletState.FlowActive` synchronously,
  before any network work, with `flowType = "issuance"`, a placeholder
  `flowId` (`FlowActive.PENDING_FLOW_ID`, `FlowActive.isPending`) and a
  client-side `status` that steps through `initializing`, `connecting_engine`,
  `establishing_session`, `checking_entitlement`, `preparing_issuance` and
  `starting_flow` (`FlowActive.STEP_*`) until the engine's own progress events
  take over. Previously the wallet stayed `Ready` for about five seconds on a
  mobile network (engine reconnect, entitlement check, metadata fetches), so
  hosts showed no feedback after the user chose a credential type. A start that
  fails (engine unreachable, entitlement refusal) returns the wallet to
  `Ready` and throws, as before; `cancelCurrentFlow()` during the start resets
  at once, sends nothing to the engine and stops the suspended start from
  reaching it later. The flow type now stays `"issuance"` across the first
  engine progress event for flows begun this way.
- Sample app: label for the new `initializing` step (en, sv, fi, el, pt); a
  user-cancelled start is no longer reported as an error.

### Fixed
- **Consent builder parity with the Swift review.** (1) The age wording ("your exact birth date is not shared") is used
  only when every condition of an age-specialised function is a single `ge` or `le` bound; one that also declares `eq`
  (or another comparison) renders with the generic wording stating every comparison (`age_with_eq` in the shared
  vectors; an age-specialised function may now declare more than `ge`/`le`). (2) `ConsentRequests.build` takes a required
  `requestSigned` (no default; the wallet passes whether the request carried key material); an empty query list is
  refused (new vector); a numeric span whose bounds cannot be aligned exactly (`1e999999999`) is refused instead of
  building a billion-digit number (the 2^64 span vector already pins exact arithmetic).
- **SD-JWT `ssc` reader (`SecretSeedCommitment.sscOfSdJwt`) fails closed on a non-`sha-256` `_sd_alg`
  and ignores a nested same-named claim.** Only an `ssc` disclosure whose digest is in the payload's
  top-level `_sd` counts; a disclosure of a same-named claim of a nested object no longer makes the
  top-level one ambiguous.
- **mdoc issuer trust evaluation no longer 502s and silently downgrades to
  local VICAL validation.** The `mdoc-issuer-auth` AuthZEN request named the
  issuer URL as `subject.id` but the certificate hash as `resource.id`; go-trust
  requires `resource.id == subject.id` on every full evaluation and answered
  400, which go-wallet-backend's authzen proxy turns into a 502 on
  `POST /v1/evaluate`, so every mdoc issuance fell back to local root validation
  and was stored `trusted=false`. `resource.id` now always equals `subject.id`
  (the key material stays in `resource.key`). The fallback to local validation
  is also stricter: only a network failure, or a 502/503/504 carrying no
  upstream JSON error body, counts as "backend unreachable"; a 4xx, a 500, or a
  502/503/504 whose body is a PDP error now fails closed instead of silently
  downgrading.

### Changed
- **`circuit_zk` never presents a credential the user did not pick.** An empty
  `selectedCredentialIds` no longer means "the first eligible credential": it is refused
  (`SELECTED_CREDENTIAL_UNAVAILABLE`). Plain OpenID4VP is unchanged. An `age_check` is checked
  locally against the credential's `birth_date` before the user is asked; an unsatisfiable one is
  refused without consent. Only per-verifier pseudonym configs (`known-offender-matching-ssc`,
  `-psc`) have consent wording; any other config is refused (`UNSUPPORTED_REQUEST`) for now.
- **Consent review follow-ups.** The numeric merge rule compares the span as a `BigDecimal` (it
  was narrowed to `Long`; vector added); generic predicate text no longer says "the value is not
  shared" (a proof of `== SE` reveals it); the presenter is given a `DeclaredPredicateHandler` for every
  function the wallet declared in `circuitZkPredicateFunctions`, so a function the user was asked about
  can also be presented. `context.intermediary_risk` is optional and provisional until go-trust defines it.
- **`VerifierIdRegistry.resolve` returns `ResolvedVerifierId(type, id)`** instead of the bare id
  string. Removed the unused precursor `CircuitZkConsentSummary` / `circuitZkConsentSummary()`.
- **BREAKING (unreleased `circuit_zk`): the response is the JSON shape of siros-dc-matcher `docs/circuit_zk_response.md`.**
  `vp_token[queryId]` is an ARRAY of presentation objects `{circuit_id, proof_system, proof, x5chain, results}`
  (`CircuitZkResponsePresentation`; `CircuitZkPresenter.Result.presentation` / `.json`; `base64Url` is gone). `proof` is
  base64url without padding. `x5chain` is REQUIRED: the credential's own `issuerAuth` `x5chain`, leaf (Document Signer)
  first, at most 8 certificates of at most 4096 bytes each, standard base64 with padding (the verifier validates it
  through go-trust and takes the issuer key from the leaf; the wallet never sends a bare key). `results` is
  `{handle: {pseudonym}}` or `{handle: {satisfied: true}}`, one per `return` handle, none skipped. `circuit_id` and
  `proof_system` are values the request OFFERED (`circuit_id_values`, `circuit_proof_system_values`): a request that
  offered none cannot be answered and is refused before anything is proved (an offered alias is stated as the id). The old
  CBOR presentation and its `proof_time` are no longer produced. `CircuitZkResponseValidator` (a mirror of the matcher's
  `validate_response`, strict: `null` is a type error, repeated members refused, an item type with no result shape refuses
  the response) checks every response before it is sent; the 79 shared vectors are vendored in
  `spec/circuit-zk-response-vectors` (siros-dc-matcher 932b07af, set digest 5c7fd1d3...). Only `multiple: true` queries may
  carry more than one presentation. A legacy `zk-claim-disclosure-v1` plan has no result shape yet and so cannot be
  answered over this shape. The verification time T is NOT decided and not implemented.
- **Redirect (OpenID4VP QR) handover for `circuit_zk`:** `MdocDeviceResponseBuilder.buildCircuitZkRedirectSessionTranscript`
- **BREAKING (unreleased): rulebook v0.4, `circuit_zk` is `zkp_req`.** Names (the matcher's, siros-dc-matcher pull request 50,
  head `69e6be1`, `spec/zkp-req-vectors`): format `zkp_req`, `req` is `_req`, item `id` is `fn_id`, `pseudonym-v1-sha256` is
  `pseudonym` with `config`, `ver` (1) and `prf` (`sha-256`; `hashdh-bls12381g1` for the held `bbs_cd`), `circuit_id` is
  `system_id`, `circuit_id_values` / `circuit_proof_system_values` are `system_id_values` / `proof_system_values`
  (`proof_system_values` is optional, `system_id_values` is not: a request that offered no `system_id` cannot be answered and
  is refused before anything is proved), the plan's `circuit_filter` is `system_filter`, `meta.source_format` is required
  (`mso_mdoc`; a request for another source format is not answered with an mdoc), `verifier_id_type` is gone. The planner is
  `zkp_req_plan`, the registration `addZkpReqSystem` with the circuit's `system_id`; a blob built by an older matcher declines
  `zkp_req`, so the bundled matcher and the registered blob move together (`org.siros:siros-dc-matcher:0.11.0`). The wallet's satisfiability
  rules (`CircuitZkRuleSet.rulebookV04`) use the matcher's codes as rule ids and pass all 43 `zkp_req_unsat` vectors.
- **BREAKING (unreleased): the response is the rulebook's base64url CBOR `ZkpPresentation`.** `vp_token[queryId]` is an array of
  strings, each the unpadded base64url of `{system_id, proof, issuer_key_set, ? proof_time, results}`
  (`CircuitZkResponsePresentation`; `CircuitZkPresenter.Result.presentation` / `.json`; `base64Url` is gone, and the earlier
  CBOR/JSON presentation classes with `circuit_id`/`x5chain` are removed). `issuer_key_set` is the credential's own
  `issuerAuth` `x5chain` (DER, leaf first, at most 8 certificates of at most 4096 bytes each, checked before any proof is
  made; the verifier validates them through go-trust and takes the issuer key from the leaf). `proof_time` (tag 0) is the
  EXACT 20-byte form `YYYY-MM-DDThh:mm:ssZ` and required for `mso_mdoc`: the prover's own time input when it has one, else the
  device clock, rendered by the one function `ProofTime.render`. A pseudonym is 32 bytes for `sha-256`, a predicate result is
  `true`; no item type is skipped. `CircuitZkResponseValidator` (strict CBOR: definite lengths, no duplicate keys, no trailing
  bytes, depth 16) mirrors the matcher's `validate_response` and checks every response before it is sent; the 143 response
  vectors, the `proof_time` vectors and the 54 planner vectors (device test) are vendored verbatim with their set digest checked.
  A legacy `zk-claim-disclosure-v1` plan has no result shape and cannot be answered over this shape.
- **Prefixed `verifier_id`:** `verifier_input = SHA-256(verifier_id)` with the PREFIXED string (`x509_san_dns:<dns name>`,
  `semantic_id:...`). The bare DNS name is not a `verifier_id`. The pseudonym vectors now carry the prefixed forms and the
  circuit developers' reference pseudonyms (`155f4337...aad1` for `x509_san_dns:verifier.example`).
- **`birth_date` of a nym_auth attestation is never disclosed:** the default non-disclosure policy protects `ssc`, `psc`,
  `secret_seed` and `birth_date` of `eu.europa.ec.eudi.nym_auth.1` and `.bbs.1`; a query with no `claims` (the whole
  attestation) does not match them. `birth_date` of any other credential is an ordinary claim. `age_check` still reads it locally.
- **Redirect (OpenID4VP QR) handover for `zkp_req`:** `MdocDeviceResponseBuilder.buildCircuitZkRedirectSessionTranscript`
  (OpenID4VPHandover over `[prefixed client_id, nonce, JWK thumbprint (32 bytes, required), response_uri]`; the response
  is always encrypted, so a null thumbprint is not representable). Pinned by the spec's own example from the shared
  nymauth challenge vectors. The DC API path keeps `OpenID4VPDCAPIHandover`.
- **A `circuit_zk` circuit that declares no `functions` and no `capabilities`
  now fits no plan** (`CircuitZkCircuit.supports`; it used to fit every plan).
  `CircuitZkCircuitSource.fromManifest` takes an optional `declare` for entries a
  registered prover adapter claims, and `CircuitZkCircuit` gains `systemVersion`.
  `CircuitZkProver` gains `admits(circuit, plan)`, which the presenter applies
  when picking the circuit. The validator's `function-not-declared` rule (shared
  test vectors) is unchanged.
- **BEHAVIOUR-BREAKING for hosts relying on storing untrusted credentials:
  issuance is fail-closed on issuer trust.** A credential is stored only if its
  issuer's trust is established: an mdoc needs a verifiable `issuerAuth` and a
  positive `evaluateIssuerTrust` (remote `decision=true`, or - only when the
  backend was genuinely unreachable - a positive local validation against
  configured roots); a negative decision, a 4xx/validation rejection,
  unreachable with no (or negative) local roots, or a missing/unverifiable
  `issuerAuth` refuses the issuance. Other formats are refused when the engine's
  server-side issuer trust (`trust_evaluated`) was negative. A refusal stores
  nothing, captures no refresh token, syncs nothing, leaves a renewal's
  superseded batch in place, sends the OID4VCI `credential_failure`
  notification (best effort, no detail) and ends the flow with the new
  `WalletEventListener.onIssuerNotTrusted` plus `onFlowError` carrying the
  default wording (string resource `siros_issuer_not_trusted`, localised
  en/sv/fi/el/pt). There is no host switch to turn this off. The engine's
  issuer-trust report now travels on `FlowCompleteMessage.issuerTrust`
  (attached by `WalletEngineSession` in message order, so it cannot race the
  completion), and a completion whose flow was cancelled while its trust check
  was pending is dropped without touching state.
- **One trust-decision cache replaces `TrustCache`** (removed). Every
  `/v1/evaluate` call (mdoc issuer/reader, DC API, engine-relayed and WMP trust
  evaluation) goes through `TrustDecisionCache`: successful decisions (allow
  and deny) only, keyed by a hash of the whole request (action, subject, full
  certificate chain / key material, context), `WalletConfig.trustDecisionCacheTtl`
  (default 5 minutes, `Duration.ZERO` disables), in memory, 256 entries LRU,
  single-flight for identical concurrent requests, cleared when the backend
  connection is dropped or replaced (logout, account deletion, reconnect).
  Errors and timeouts are never cached and an expired entry is never served,
  not even while the backend is unreachable; the old "cached positive while the
  backend is unreachable" fallback is gone. Trade-off: a trust revocation can
  take up to the TTL to take effect.
- **BREAKING (unreleased TS12 API): payment SCA takes its authentication
  factors from the signing operation, not from a provider.**
  `siros-wscd-manager` 0.9.1 -> 0.10.0 (UniFFI bindings regenerated:
  `signWithFactors`, `authenticationCapability`, fresh user authentication).
  `AuthenticationFactorsProvider`, `ConservativeAuthenticationFactorsProvider`
  and `SirosWallet.authenticationFactorsProvider` are removed. Before the user
  is shown a transaction the wallet asks the key's signer whether two
  authentication categories are reachable (`KeystoreManager.scaAuthenticationCapability`,
  never prompts) and refuses (`insufficientAuthenticationFactors`) if not or if
  that cannot be determined. After consent the SCA sign is a fresh user
  authentication (`requireFreshUserAuthentication`; a cached OPAQUE session or
  token is never reused) and the KB-JWT `amr` is exactly the factors that sign
  applied, with the PIN class measured from the PIN typed for it. Because the
  `amr` is inside the signed bytes it is stated before the signature; the sign's
  own report must then equal it (as a set) or the presentation is discarded and
  refused. `TransactionBinding` no longer takes factors. `Signer` gains
  `scaAuthenticationCapability` and `beginScaSign` (defaults refuse), implemented
  by `UniFFISigner` for R2PS (`key_in_remote_wscd`) and FIDO2
  (`key_in_local_external_wscd`). `JweKeystore` (software keys, no user
  authentication of its own) now refuses an SCA sign. Non-SCA signing is
  unchanged.
- A signer that reaches possession alone and would need the host to vouch for
  a second factor (R2PS WebAuthn, a UV-performing FIDO2 transport) is reported
  as not possible and refused BEFORE consent: the manager refuses a
  fresh-authentication sign for exactly those, so offering them would let the
  user consent and verify before a certain refusal. There is no host-verified
  factor hook. Cancelling the PIN prompt (or a prompt that fails) declines the
  transaction (`declined`, `access_denied`) rather than reporting insufficient
  factors.
- **The wallet, not the request, picks the pseudonym's `verifier_id_type`
  (ordered list; AuthZEN is the default source).** The type is agreed in the
  trust framework, so `WalletConfig.circuitZkVerifierIdTypes` /
  `WalletPolicyOptions.verifierIdTypes` is an ORDERED list of supported types
  (default `["semantic", "x509_san_dns"]`, helpers in `VerifierIdTypeOrder`:
  entries non-blank, trimmed, comma-free, unique; invalid lists throw at
  construction). `VerifierIdRegistry.resolve` walks it in order and uses the
  first type for which the policy decision point's `context.verifier_ids` holds
  an identifier (AuthZEN first for every supported type, then any optional
  `circuitZkVerifierIdSources` for hosts that want their own; the default
  is empty and the PDP is the single default source). Conflicting DISTINCT values for a type decline that type and the
  next is tried; empty ids are ignored; `basis` is ignored. An EMPTY list means no
  type is supported and a pseudonym request is refused (fail closed); so is a
  request where no type resolves (bare `access_denied`, reason
  `VERIFIER_ID_UNAVAILABLE`). The `verifier_id_type` a request names is still
  accepted structurally by the planner but is IGNORED for selection and is
  not refused on mismatch (the default validator accepts any named type).
  The trust request no longer carries `context.verifier_id_type`, so the PDP
  returns everything and the wallet picks. Sample app: an ordered, editable
  list (add, remove, up/down, reset), stored as the comma-separated
  `verifier_id_types` (unparseable falls back to the default; the empty string
  is the deliberate empty list); applies at next wallet creation.
  VALUE FORMS are defined by the rulebook / trust framework (nym_auth rulebook
  "Verifier identity") and produced by the PDP (go-trust `pkg/authzen`):
  `x509_san_dns` = the dNSName SAN, ASCII lower case, no trailing dot, NO
  `x509_san_dns:` prefix; `x509_san_uri` = the URI SAN as bound;
  `decentralized_identifier` = the DID without fragment; `openid_federation` =
  the entity id as in the chain; `semantic` = `semantic_id:` + the ETSI id. The
  wallet hashes the value byte-for-byte: it never lower-cases, trims or strips
  anything (pinned by a test with a mixed-case value). The request no longer
  carries `verifier_id_type`, so the rulebook validator's
  `verifier-id-type-required` rule is removed (absent is satisfiable;
  `-forbidden` and `-unregistered` were later removed too, see the validator
  cleanup entry below).
  The shared vectors `spec/nym-pseudonym-vectors.json` (generated by the
  independent `tools/gen_nym_pseudonym_vectors.py`; for reuse by the Swift
  port) and `spec/circuit-zk-validator-vectors.json` were regenerated to
  match; the matcher's `circuit_zk` planner vectors were re-copied from
  siros-dc-matcher tag `v0.10.0` (`ba1323c`; byte-identical to the earlier
  `9237638` and `v0.9.1` copies; no
  `verifier_id_type` in the requests, a new vector shows a legacy one is still
  accepted and passed through opaquely). The planner behaviour is unchanged. The sample app's nym demo drops the request parameter and uses the
  bare DNS form.
  Type strings are opaque: the names in the wallet's list must match what the
  PDP returns; go-trust is aligning to the trust framework (the `x509_san_dns`
  value is the bare DNS name, derived by the PDP), and nothing is mapped or
  aliased here. The local `X509SanDnsSource` (which parsed the request's
  client id and `x5c` leaf) is DROPPED: the PDP is the single source of
  verifier ids and the SDK no longer parses the request for this. It was new
  in this PR, so removing it is not a binary-compatibility break against any
  release; the pluggable `VerifierIdSource` interface and
  `circuitZkVerifierIdSources` remain. Replaces `VerifierIdSourceKind` / `WalletPolicyOptions.verifierIdSources`
  (stored key `verifier_id_sources` is no longer read) and the type-keyed
  `VerifierIdRegistry`/`VerifierIdTypes` role (all new in this PR). The Swift
  port needs the same change; not done here.
- **Ordinary queries beside a `circuit_zk` query are validated by the engine
  too.** `matchDcql` used to skip engine validation for the whole request when
  any `circuit_zk` query was present (the engine did not know the format when
  that was written), so a credential missing a claim an ordinary query asked for
  became a candidate again. The ordinary queries are now given to the shared
  engine as a request of their own (circuit queries and `credential_sets`
  removed) and only its per-query candidates are used; the planner still decides
  the `circuit_zk` queries. If the engine cannot answer, the ordinary queries
  offer nothing (the built-in fallback never checked claims). (#266)
- **The raw credential view redacts protected claims.** The sample app's Raw tab
  decoded the SD-JWT payload and disclosures unchanged, so a protected claim
  stayed readable and copyable. `CredentialDisclosureGuard.rawViewOf` (SDK) now
  decides what a debug view may show: protected, descendant and ancestor claims
  are dropped from the cleartext payload and the disclosures (nested ones placed
  by digest); a protected mdoc shows no raw text. (#266)
- **The public ZK response builder refuses a protected element.**
  `MdocDeviceResponseBuilder.buildZkDeviceResponse` (and so
  `ZkMdocPresentation.buildDeviceResponse`) serialised `disclosedClaims`
  verbatim, so a host using the custom-prover/replay API could emit `ssc`/`psc`
  under the default policy. It now throws `DisclosureRefusedException`. (#266)
- **An absent or unreadable DC API picker selection is refused.** The activity
  returned an empty selection, which the wallet reads as "present the first
  eligible credential". The decision is now `DCAPISelection.resolve` (JVM
  testable), which yields an id no credential has; the no-selection fallback
  remains only for callers that pass no `selectedCredentialIds`. A selection with ANY
  unreadable id resolves to that id alone (a readable subset never authorises a
  response), and `handleCircuitZkDcApi` refuses a selection in which any id is
  unknown or a candidate of none of the queries, or that lists an id twice. (#266)
- **The SD-JWT non-disclosure guard also covers the issuer payload.**
  `CredentialDisclosureGuard.requireNoneProtectedSdJwt` checked only the
  selected disclosures, but every presentation carries the issuer JWT
  unchanged, so a protected claim stored there in cleartext (or any presentation
  with no disclosure) was transmitted by `JweKeystore` and `WscdKeystoreAdapter`.
  It now refuses a protected cleartext claim, by original path segments and
  ancestor-aware. Display and matching already hid such claims. (#266)
- **A `circuit_zk` query the matcher cannot read still makes the request a
  `circuit_zk` request, and the whole request is refused.** `DcqlMatchOutput`
  gains `hasCircuitZkQuery` (from the original queries, whether or not
  `WalletConfig.circuitZk` is on) and `unparsedQueryCount`. A `circuit_zk` query
  with a missing or non-string `id` was dropped from the results, so with the
  flag off, or with the native matcher unavailable, an ordinary sibling query
  could be answered alone. `handleDCAPIRequest`, the circuit branch and the
  engine-relayed match path now refuse on the flag, not on returned results.
  (#266)
- **The `circuit_zk` circuit list is kept as the verifier's two lists, never
  expanded into their product.** `CircuitZkPlan.circuitFilter` is now a
  `CircuitZkCircuitFilter(proofSystems, circuitIds)` (it replaces
  `List<CircuitZkCircuitRef>`; `CircuitZkCircuitRef` is removed). Planning runs
  before the trust decision, and 10,000 proof systems x 10,000 circuit ids
  expanded to 100 million pairs, a heap exhaustion from an untrusted signed
  request. Admission is the same (system in the first list and id or alias in
  the second); the planner, matcher and rulebook validator all use `admits`.
  (#266)
- **`circuit_zk` / `nym_auth` fails closed unless the credential's only
  namespace is its doctype namespace.** `CircuitZkPresenter` now refuses
  (step `NAMESPACE`, the verifier still gets a bare `access_denied`) a credential
  whose `nameSpaces` is not exactly `{docType}`: a decoy namespace listed first,
  an extra namespace, or a missing doctype namespace. The nym_auth circuits read
  `birth_date` and `ssc` from the doctype-named namespace and do not check that
  no other namespace holds an attribute of the same name, so the wallet checks
  it. This changes behaviour: credentials with extra namespaces were previously
  proved. The legacy `mso_mdoc_zk` path (`ZkMdocPresentation`,
  `LongfellowZkProofSystem`) is unchanged and still takes any namespace. (#266)
- **The wallet's DC API trust path no longer logs the verifier id or a
  throwable.** `handleDCAPIRequest` and the trust call it shares with the
  `circuit_zk` branch (`evaluateTrustDirect`) logged the verifier's subject id
  and passed the exception to Timber, whose message can carry the verifier id
  or the backend's refusal text. They now log the exception class only. This
  changes existing log output; a test scans the wallet's DC API path so it
  cannot return. (#266)

### Added
- **siros-dc-matcher 0.10.0: capabilities use `credential.issuance_profile`.**
  The pinned matcher AAR moves from 0.9.0 to 0.10.0 (no FFI or plan-JSON
  change: the vendored `uniffi.siros_dc_matcher_ffi` bindings are
  byte-identical to the matcher tag's, nothing regenerated). The matcher's
  capabilities parser follows the circuit catalog's rename of
  `credential.profile` to `credential.issuance_profile` (an optional, non-empty
  opaque string constraining the input credential; validated, never a filter).
  The old `profile` key is now an unknown member, so such capabilities are
  rejected and the circuit is not offered (fail closed); nothing here set it,
  the SDK passes `capabilities` through verbatim. `spec/circuit-capabilities-vectors`
  is re-copied from the `v0.10.0` tag (`match.json` changed: `profile-*` cases
  use `issuance_profile`, three cases added, two carry `expectRejected`);
  `spec/circuit-zk-planner-vectors` is unchanged (byte-identical). The host and
  device capability-vector harnesses treat `expectRejected` cases as "nothing
  served" and check registering them does not throw.
- **`SharedCircuitZkPlanner`: the default `circuit_zk` planner, backed by
  siros-dc-matcher 0.8.0.** Used when `WalletConfig.circuitZk` is on and no
  `circuitZkPlanner` is given. The wallet's circuits are registered with the
  matcher (`SirosCredentialRegistry.refresh(circuitZkCircuits = wallet.circuitZkCircuits)`,
  one `add_circuit_zk_system` per circuit id and alias, `functions` only when
  the catalog declares them), so the OS picker offers `circuit_zk` rows. The
  matcher's planner conformance vectors are in `spec/circuit-zk-planner-vectors`.
  Behaviour changes: `CircuitZkPlan.circuitFilter` is a `CircuitZkCircuitFilter` of the
  verifier's two lists, and an empty list in it admits no circuit (null still means "any");
  a request repeating a DCQL credential-query or claim `id` offers nothing.
  The matcher AAR is 0.9.0 (0.7.0: `zk_required` absent means optional,
  duplicate ids rejected, holder binding and `multiple` honoured). (#271)
- **siros-dc-matcher 0.9.0: the planner is read directly, and circuits can
  declare a credential type or `capabilities`.** `SharedCircuitZkPlanner` calls
  the matcher's new `circuit_zk_plan` export instead of matching a throwaway
  probe blob, so the limits that existed only because of the probe are gone:
  a request whose circuit lists are present but empty, with `vct_values: []`,
  or without an `id` is planned as the matcher plans it (the plan JSON is
  unchanged, and a rejected request is still `InvalidRequest`). The planner's
  conformance vectors are now checked to the error code.
  `CircuitZkCircuit` gains two optional opaque strings, `credentialType` and
  `capabilities`, which `SirosCredentialRegistry` registers as the matcher's
  `credential_type` and `capabilities` params, verbatim (the SDK never reads
  them). `credentialType` restricts the circuit to a request naming that
  doctype or vct; `capabilities` (the catalog's capabilities object as JSON)
  makes the matcher apply its capability rule and replaces `functions` and
  `credentialType`; a value it cannot parse leaves the circuit not offered.
  `ZkCircuitDescriptor.capabilities` carries the catalog's object and
  `CircuitZkCircuitSource.fromManifest` passes it through. The matcher's
  capability vectors are in `spec/circuit-capabilities-vectors`. API note:
  `CircuitZkCircuit` and `ZkCircuitDescriptor` gain a trailing constructor
  parameter (source compatible, not binary compatible). The sample app's demo
  circuit declares its credential type. (#271)
- **`NymPseudonym.derive`: the nym_auth rulebook pseudonym function
  (`pseudonym-v1-sha256`), pure and driven by one config table.** Computes
  `SHA256(DST || seed || prover_input || verifier_input)` for the four
  rulebook v0.3 configs; `verifier_id` is an opaque caller-supplied string.
  Misuse (unknown config, missing or unused input, wrong seed length) throws
  `NymPseudonymError`. Shared vectors in `spec/nym-pseudonym-vectors.json`
  (self-generated, not yet cross-checked with the circuit developers). Unrelated
  to the legacy `DefaultZkPseudonymDeriver`. (#261)
- **`CircuitZkPresentationCodec`: encoder and strict decoder for the generic
  `circuit_zk` presentation (`CircuitZkPresentation`).** Follows the rulebook
  CDDL; `circuit_id` is opaque (the caller validates it against the catalog).
  Fails closed with `CircuitZkPresentationError`, preserves unknown top-level
  keys (optional strict mode), has a pluggable `issuer_key_set` decoder hook
  and an opt-in `requireResultHandles` check. Shared vectors in
  `spec/circuit-zk-presentation-vectors.json`. (#262)
- **`PrivateSeed`: a stable per-credential-type holder `private_seed`, derived
  from the container `mainKey`.** `HKDF-SHA256(mainKey, info =
  "org.siros.private_seed/v1" || credentialType)[:16]`, with `psc` and a
  fail-closed `matchesCommitment`. `PrivateSeed` and the generic `RootSecret`
  derivation are internal: `JweKeystore` and `WscdKeystoreAdapter` implement
  only the purpose-bound `HolderWitnessSource` (the issuer commitment, and a
  `CircuitZkPresenter` that feeds the seed to its prover), so no public member
  of a keystore derives a secret. The key is never exported and a locked
  keystore throws `KeystoreException`. `mainKey` must never be rotated. The seed
  still reaches the prover the host configures, by design: the host app is
  inside the wallet's trust boundary. `FixedRootHolderWitnessSource` serves
  demos and tests over a caller-supplied key. Vectors in
  `spec/private-seed-vectors.json`. (#263)
- **DC API: `expected_origins` and wallet-chosen request entry.** The parser
  reads `expected_origins` from a signed payload and, given a policy, answers
  the first `requests[]` entry the policy accepts (the default still takes the
  first). A `circuit_zk` request must use `openid4vp-v1-signed` and name the
  calling origin in `expected_origins` (exact match); otherwise it is refused
  with `access_denied` and no description, before trust evaluation.
  `WalletConfig.dcApiExpectedOrigins` (`OFF` default, `IF_PRESENT`,
  `REQUIRED`) gates the other formats. (#264)
- **`circuit_zk` matching and format plumbing, behind `WalletConfig.circuitZk`
  (default off).** `CircuitZkPlanner`, `CircuitZkRequestValidator` (permissive
  by default) and `CircuitZkCircuitSource` (from the catalog manifest) decide a
  `circuit_zk` query, failing closed (no candidates, no fallback). One
  `CredentialUtils.isCircuitZkFormat`; a `circuit_zk` query never enters the
  legacy `mso_mdoc_zk` path, and a matched request is answered with
  access-denied until the presentation branch exists. Credential types served
  through `circuit_zk` register no claims in the OS picker blob
  (`SirosCredentialRegistry.refresh(claimlessDoctypes = wallet.circuitZkDocTypes)`).
  With the flag off nothing changes. (#265)
- **`RulebookCircuitZkValidator`: the wallet-side rulebook satisfiability rules
  for a planned `circuit_zk` request**, as a named data-driven `CircuitZkRuleSet`
  (function rules registered per function id) behind `CircuitZkRequestValidator`.
  Returns `Ok` or `AccessDenied(ruleId)`; the rule id is for local logs only.
  (The `VerifierIdTypes` registry that was part of it is gone again, see below.)
  Shared vectors in `spec/circuit-zk-validator-vectors.json`. A `circuit_zk`
  request that matches nothing is now answered with `access_denied` and no
  description, never the "no credential matches" text. (#267)
- **`CircuitZkPresenter`: assembles and encodes a `circuit_zk` presentation
  from a validated request.** Fail-closed steps (validator re-run,
  doctype, witness, `psc` check, data-dependent predicates, circuit selection,
  prover, assembly; the `ssc` check for the issuer-delivered `secret_seed` was
  added later, see the secret-seed entry below) with function handlers registered per function id
  (`pseudonym-v1-sha256`, `age_check`), a `CircuitZkProver` interface and the
  same `ZkWitnessSigner` / residency handling as `ZkMdocPresentation`. Refusals
  are `CircuitZkError` with no description. `FakeCircuitZkProver.optIn()` is a
  fake that reports itself as such and is never registered by default. (#268)
- **`handleDCAPIRequest` answers a `circuit_zk` request (behind
  `WalletConfig.circuitZk`, default off).** Request hardening, then trust from
  the policy decision point alone (no local certificate check, no trust cache:
  an outage is a refusal), plan and validate, resolve the verifier id through
  the new `VerifierIdSource` registry (`WalletConfig.circuitZkVerifierIdSources`;
  shipped: `AuthZENSource`), present, and return the token
  in `vp_token`. `TrustResult` gains an optional read-only `context`. Every
  failure is `access_denied` with no description; the history record has
  `zkProof = true` and no claim names. `WalletConfig.circuitZkValidator` now
  defaults to the rulebook validator. (#269)
- **A non-disclosure guard: `ssc` and `psc` are never matched, registered,
  presented or displayed.** `NonDisclosurePolicy` is a data table of protected
  claim paths by credential type (default: the nym_auth doctype's `ssc` and
  `psc`; override with `WalletConfig.nonDisclosurePolicy`); one
  `CredentialDisclosureGuard` serves the matcher, the OS picker claims, the
  display claims and every presentation builder, which refuses (never strips)
  a presentation that would disclose a protected claim
  (`DisclosureRefusedException`). A type with no entry is unaffected.
  `circuitZkConsentSummary` gives hosts a summary with no credential values. (#270)
- **The wallet now holds the issuer-delivered `secret_seed`; the ssc pseudonym
  configs are provable when a seed is available (presenter side only).**
  Earlier entries (#263, #268, #270) and the `holderPrivateSeed` /
  `NOT_HELD_BY_WALLET` KDocs said the wallet never holds the `secret_seed` and
  refuses `known-offender-matching-ssc`, `account-recovery-ssc` and
  `user-managed-pseudonym-xsite-ssc` by design; that is superseded. The issuer
  delivers the seed (16 bytes, lowercase hex of 32 chars on the wire) in the
  OID4VCI credential response `credential_metadata`, to be stored per credential
  in privatedata. `CircuitZkPresenter.Request.secretSeed` carries it; the
  presenter never trusts it: the seed must be exactly 16 bytes (else refused at
  the witness step), and `SHA256(seed)` must equal the credential's `ssc` (one
  32-byte bstr in the doctype namespace; absent, non-bstr, wrong length or
  duplicated refuses), compared in constant time in a new step before the
  predicates and the prover. Any failure is `access_denied` with no description
  and the prover is never called. The presenter works on its own copy of the
  seed and zeroes it on every exit path; the seed is in no log, exception
  message, history record or response. `CircuitZkWitnessKind.SECRET_SEED` and
  `CircuitZkFunctionWitness.secretSeed` (redacted `toString`, identity
  `equals`) are new; witness providers are never asked for the seed (it is not
  derivable from `mainKey`, so the keystore providers return null for it).
  `NymConfigInfo.seedKind` (`NymSeedKind.PRIVATE` / `SECRET`, now public)
  replaces `holderPrivateSeed`. `FakeCircuitZkProver` derives the ssc configs
  from the witness's `secretSeed`. `NOT_HELD_BY_WALLET` remains only for configs
  this SDK does not know. Receipt, storage and the wallet-side lookup are
  implemented, see the next entry.
  Shared vectors `spec/secret-seed-commitment-vectors.json` (generator
  `tools/gen_secret_seed_commitment_vectors.py`, hashlib only) cover
  `ssc = SHA256(secret_seed)` and the rejections. The nym demo issuer now issues
  `ssc = SHA256(random 16-byte seed)` and the sample has an ssc scenario plus a
  "wrong seed must refuse" button.

- **The issuer-delivered `secret_seed` arrives in the response-level
  `credential_metadata` (OpenID4VCI 1.1, openid/OpenID4VCI#721; privatedata-spec
  2.6 section 5A, vectors vendored verbatim from privatedata-spec `8c4c865`); the ssc
  pseudonym configs are provable from the stored seed.**
  Wire: ONE object per Credential (and Deferred) Response, applying to every
  credential in it: `"credential_metadata": {"org.siros.secret_seed":
  {"<namespace>": "<32 lowercase hex>"}}` (`SecretSeedDelivery.MEMBER`, one constant).
  Transport: `FlowCompleteMessage` (engine) and the WMP `FlowCompleteResult` carry
  `credentialMetadata` (`ResponseCredentialMetadata`: every member verbatim and in
  order, unknown members preserved; a value that is not an object decodes as a
  `malformed` placeholder so the frame and each `notification_id` stay readable) and
  `credentialMetadataEncryptedResponse` (default false; set by the engine only for a
  JWE-decrypted response; a non-boolean reads as false). The credential DTOs print
  no credential and the response object prints no member.
  Receipt (`flow_complete`), once for the whole response and before anything is
  stored or a renewed batch replaced: the `org.siros.secret_seed` member must come
  from an encrypted response, the response must carry a `notification_id`, the
  member must be well formed (1-8 namespaces of at most 64 UTF-8 bytes, none the
  reserved `namespaces`, each seed exactly 32 lowercase hex characters), and the seed
  of `WalletConfig.secretSeedNamespace` (default `org.siros.nym_auth`) must open the
  `ssc` of EVERY credential (`SHA256(seed) == ssc`, constant time; mdoc: the one 32-byte
  bstr of the doctype namespace, SD-JWT VC: the one top-level `ssc` disclosure bound
  to the signed `_sd`). Any refusal fails the whole issuance: nothing is stored, the old
  batch of a renewal stays, `credential_failure` is sent once per `notification_id`, and
  the error names no value. Storage is unchanged: every credential of the response
  gets one `S.credentials[].metadata` entry per response member,
  `{type: <member>, value: <member verbatim>}`, in order (a keystore side map, never
  part of the stored credential JSON). `WalletConfig.secretSeedMetadataType` is replaced
  by `secretSeedNamespace`.
  Safeguards: the seed is STRIPPED from the response object before any merge into
  display metadata (`SecretSeedDelivery.stripped` / `mergeDisplay`: the issuer's
  public advertisement stays, the seed cannot enter), and a static test keeps every
  other reader of the object out. Issuer metadata advertises a seed by namespace names
  only (`credential_metadata["org.siros.secret_seed"] = {"namespaces": [...]}`,
  `CredentialDisplayMetadata.secretSeed`, `SecretSeedDelivery.classifyAdvertisement`):
  a configuration whose public metadata carries anything else there (a seed value, say)
  is malformed and not offered, and a completion for an advertising configuration that
  was not encrypted is refused. The wallet cannot itself ask for response encryption:
  the engine decides `credential_response_encryption` from the issuer's
  `credential_response_encryption` metadata; for an advertising configuration the engine
  must treat encryption as required (see the engine note in the PR).
  Replays and the WMP client: a REPLAYED `wmp.flow.complete` lists what it withheld in
  `redacted_members` (from `credential_metadata`, `credential_metadata_encrypted_response`,
  `refresh_token`, `dpop_jwk`, `dpop_key_id`; the credentials are kept, a live completion has no
  marker; both flow-complete DTOs decode it, an unreadable marker reads as everything withheld).
  A listed member is not recoverable: nothing is invented, reused from an earlier flow or
  substituted. A credential that needs a seed (it carries an `ssc`, or its configuration advertised
  one) in a completion whose metadata was withheld, or an advertised seed that did not arrive, fails the
  issuance with nothing stored; credentials of a replay that needs no seed are stored normally;
  renewal material is captured only when none of it is withheld, so a replayed batch is not
  renewable (re-issue). A seed over a deferred response is refused
  (`DeliveredResponseMetadata.deferredResponse`, false until the engine relays one). The SSE
  transport (`WmpHttpSseTransport`) now returns from `connect()` only once the stream is open (so it is
  connected before `wmp.flow.start` is sent), drops a replayed event id, sends `Last-Event-ID` on a
  reconnect, and no event data or decode error is ever logged (`WmpSession`, `WmpPeer` log the
  exception class only).
  Use: the internal `CredentialSecretSeedSource` seam is suspend and keystore-backed
  (`KeystoreSecretSeedSource`, reads the `org.siros.secret_seed` entry's
  designated-namespace seed); `handleCircuitZkDcApi` fetches the picked credential's
  seed for the ssc configs, the presenter re-verifies the commitment, and the wallet
  zeroes its copy. Guard tests keep the metadata out of logs, history, presentations
  and stored credentials. The keystores preserve every member of a credential entry
  they do not own, every unknown `S` and `settings` member and unknown container
  members.
- **Validator cleanup: a legacy `verifier_id_type` is accepted and ignored.**
  Rulebook v0.3 removed it from the request and implementations must not reject
  it. `verifier-id-type-forbidden` and `verifier-id-type-unregistered`, the
  `VerifierIdTypes` registry, the `RulebookCircuitZkValidator` constructor
  parameter and the vectors' `default_registered_verifier_id_types` /
  `options.registered_verifier_id_types` are removed (all new in this PR); the
  vectors now expect `ok`, with one proving a legacy parameter passes. The
  Swift port shares `spec/circuit-zk-validator-vectors.json` and needs the same
  change.

### Binary compatibility (this PR, against 0.x main)
The SDK is 0.x and `apiCheck` tracks every signature (`api/*.api` are dumped in
this PR); as with earlier 0.x releases (see the `ZkCircuitDescriptor` note
above), appended defaulted constructor and function parameters are source
compatible but change the JVM descriptors, so an already compiled consumer
must be rebuilt. Not binary compatible, by type (all source compatible unless
noted):
- `WalletConfig`: new trailing properties (circuit_zk, DC API, policy
  options, ordered `circuitZkVerifierIdTypes`, `secretSeedMetadataType`); `VerifierIdRegistry`,
  `VerifierIdSourceKind` and `WalletPolicyOptions.verifierIdSources` are new in
  this PR and were reworked (no released descriptor changes); the constructor, `copy` and `copy$default` descriptors change.
- `engine.CredentialResult` and `wmp.openid4x.CredentialResult` (released):
  trailing `credentialMetadata` and `credentialMetadataEncryptedResponse`, and
  they now implement `CredentialResultMetadata`; the constructor, `copy` and
  `copy$default` descriptors change (source compatible).
- Binary compatible, additive: `JweKeystore` / `WscdKeystoreAdapter`
  `getCredentialMetadata` and `setCredentialMetadata`;
  `CredentialResponseMetadataEntry`, `CredentialResultMetadata`,
  `FlowCompleteResult`, `SecretSeedCommitment` and
  `WalletConfig.DEFAULT_SECRET_SEED_METADATA_TYPE`.
- `RulebookCircuitZkValidator` / `CircuitZkRuleEnv` lose their `VerifierIdTypes`
  parameter: new in this PR, so no released descriptor changes.
- `TrustResult`: trailing `context`; constructor and `copy` change.
- `DCAPIRequest`: trailing `extensions` and related fields; constructor and
  `copy` change.
- `CredentialMatcher.MatchResult`: trailing `circuitZkPlan`; constructor and
  `copy` change. `CredentialMatcher.matchDcql` gains a trailing `circuitZk`
  (and client metadata) parameter; the old descriptor and `$default` go.
- `SirosWallet.handleDCAPIRequest` (both overloads): trailing
  `selectedCredentialIds`; the two-argument and consent-handler descriptors go.
- `SirosCredentialRegistry.refresh`: trailing `claimlessDoctypes` and
  `circuitZkCircuits`.
- `ZkCircuitDescriptor`: trailing `capabilities`.
- `CircuitZkCircuit`, `CircuitZkSupport`, `CircuitZkPresenter` (including
  `Request.secretSeed`, `CircuitZkFunctionWitness.secretSeed`,
  `CircuitZkWitnessKind.SECRET_SEED` and `NymConfigInfo.seedKind` /
  `NymSeedKind`, which replace `holderPrivateSeed`) and
  `HolderWitnessSource.circuitZkPresenter`: new in this PR, so no released
  descriptor changes.
- The generated matcher bindings (`uniffi.siros_dc_matcher_ffi.FfiCombination`,
  `FfiMatchOutcome`, `FfiMatchedCredential`) follow the 0.9.0 matcher AAR;
  they are not SDK API to build against.
- Binary compatible: `WalletException` is now `open`; `JweKeystore` and
  `WscdKeystoreAdapter` additionally implement `HolderWitnessSource`;
  `CredentialDisclosureGuard.register/unregister/requestsProtected(type, ...)`
  are additions.
No type was reworked to preserve the old descriptors; consumers rebuild against
this version.

### Changed (review follow-up)
- **`CredentialDisclosureGuard` is no longer last-writer-wins.** `SirosWallet`
  registers its `nonDisclosurePolicy` with the new `register(owner, policy)`
  (dropped by `unregister`, called from `destroy()`); the policy in force is the
  union of every live registration, so a second wallet with
  `NonDisclosurePolicy.NONE` cannot weaken a running one. `policy` still reads
  the policy in force; assigning it replaces all registrations (apps/tests).
  Binary compatibility: additive (`register`, `unregister`,
  `NonDisclosurePolicy.union`).
- **`WalletException` is now `open`** (binary compatible) so the DC API can
  raise `DCAPIPresentationDeclined(message, reason)`, a `WalletException`
  carrying a coarse `DCAPIRefusalReason`. The existing-format decline paths
  (untrusted verifier, no matching credential, no eligible copy, missing
  encryption key, no ZK proof system) now show the user the refusal dialog. The
  verifier response is unchanged (`access_denied` with the same description).
- `DCAPIRequestRules`: the `requiresSignedRequest` hook can only ADD
  requirements; a `circuit_zk` query is always signed and origin-bound.
- `circuit_zk` with a picker selection: a query the user's pick is not a
  candidate of is refused; the first-eligible fallback applies only when no
  selection was supplied.
- `AuthZENSource` reads go-trust #203's `context.verifier_ids` list of
  `{verifier_id_type, verifier_id, basis?}`. One distinct value of the type
  is used; several distinct values decline (the trust request carries no
  `verifier_id_type` hint; the wallet's ordered type list picks).
  (Trust is now evaluated after matching; the verifier still only sees
  `access_denied`.)

### Fixed (review follow-up 5)
- **`circuit_zk` over the DC API refuses a request carrying `transaction_data`.**
  The circuit branch has no transaction pipeline (validation, consent, hash
  binding), so it used to answer such a request with a proof the user never
  saw the transaction for. It is now refused before trust evaluation or any
  credential access (reason `UNSUPPORTED_REQUEST`; the verifier gets the bare
  `access_denied`). Known limitation until the circuit path implements the
  transaction pipeline.
- A copy used for a `circuit_zk` proof is no longer treated as consumed under
  `CredentialConsumptionPolicy.CONSUME_NON_ZKP` (the circuit path now passes
  the per-presentation ZK resolver to `eligibleInstances`).
- `WalletPolicyOptions.fromStored`: a stored verifier-ID source list with an
  unrecognised name (a source renamed or removed by an upgrade) falls back to
  the default instead of disabling every source; an empty string still means
  none.
- Finnish settings label: `KAMALA` (terrible) corrected to `VÄÄRÄ` (fake).

### Fixed (review follow-up)
- **The non-disclosure policy is ancestor-aware.** A policy protecting a nested
  path such as `address.secret` now also hides the `address` object from display
  and matching (`extractClaims`, `flattenClaimPaths`, `extractMdocClaims`), and
  a presentation refuses a disclosure whose claim path is protected, below a
  protected path, or an ancestor of one (the SD-JWT path is resolved from where
  the disclosure's digest sits in the credential; an unplaceable disclosure is
  refused if any protected path mentions its name). The mdoc element check is
  ancestor-aware too.
- **`circuit_zk` circuit selection no longer treats a circuit with
  `capabilities` or a `credential_type` as unrestricted.** Such a circuit is
  selected only when the shared matcher serves it (`CircuitZkServing`,
  `SharedCircuitZkServing`: the circuit and a claimless credential of the
  doctype are registered in a throwaway blob and the request matched; no
  capability rule is reimplemented), in `CredentialMatcher`, in
  `handleDCAPIRequest` and in `CircuitZkPresenter`. Without a matcher answer
  the circuit is not selected. Circuits without either keep the legacy
  `functions` filter.
- The DC API activity no longer logs request, response or error payloads
  (only sizes and status).
- Coroutine cancellation is no longer converted to a refusal or swallowed in
  `CircuitZkPresenter.present`, the circuit_zk trust call and
  `VerifierIdRegistry.resolve`.

## [0.20.5] - 2026-10-12

### Fixed
- **A wallet installation's OAuth Client Attestation instance key could be
  lost forever, silently failing every `sign_client_auth` after.**
  `ensureInstanceKeyId` persisted only the key's id, never the key itself
  for the software WSCD plugin - after a process restart the id it recalled
  named a key that plugin's in-memory state had already lost, and every
  later DPoP/PoP request for it failed `Key not found` for the rest of the
  account's life. It now verifies the recorded id is actually live in the
  keystore before trusting it, self-healing by regenerating (and this time
  persisting) the key whenever it finds a stale or missing one.
- **A login on a device whose local passkey cache doesn't carry the
  signing-in credential (reinstall, cleared app data, device migration) now
  recovers instead of failing outright with "PRF not supported by
  authenticator."** The credential itself can be perfectly healthy in the
  platform authenticator; the account's server-synced `privateData`
  container already carries the exact PRF salt/HKDF parameters it was
  registered with. A successful recovery heals the local account cache so
  the next login is a normal one-tap match again. `AuthProvider.getPrfOutput`
  gained a required `rpId` parameter (an empty one crashes Google Play
  Services' FIDO2 UI) and `KeystoreManager.unlock` a `prfSalt` parameter,
  threaded through to the newly-created container on first-time setup
  instead of a disconnected random salt.

### Added
- **VEGA (ZK) proof generation is noticeably faster on repeat
  presentations of the same credential+disclosure set.** `prep_prove`'s
  witness-setup output is now cached and reused (`VegaProofCache`), and
  speculatively prewarmed as soon as a verifier's request names its claims
  - well before the user approves anything - so that cost lands during the
  consent screen's dead time instead of the live proving path.

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
