# Provenance

`match.json` and `README.md` here are a verbatim copy of the circuit capability
match vectors of the shared matcher,
`crates/siros-dc-matcher-core/tests/vectors/circuit_capabilities/` in
[sirosfoundation/siros-dc-matcher](https://github.com/sirosfoundation/siros-dc-matcher),
at tag `v0.10.0` (commit `ba1323c0ddd1a1e0587303b8eaefcaaee2813ec9`). `match.json` CHANGED
relative to `v0.9.1` / `v0.9.0` (earlier sha256 `9bee1868fd957fd4ad56a91dbca93b922ede04bfa57bb0f8b3a3c9bd5f383866`):
the `profile-preferred`, `profile-conformant` and `profile-before-status` cases now use `credential.issuance_profile`
(membership expectations unchanged), and three cases were added: `issuance-profile-served`,
`legacy-profile-key-fails-closed` and `issuance-profile-empty-fails-closed`. The last two carry `expectRejected: true`:
their capabilities must not parse (the old `credential.profile` key is now an unknown member; an empty
`issuance_profile` is invalid), so no circuit may be served for them. `README.md` changed accordingly.

| file | sha256 |
| --- | --- |
| `match.json` | `ab2e4f07ca6399e56cef486831ce1447fb772e13f3420af3a8d36d732153e8e9` |
| `README.md` | `6407690ed30d0463735d53498c30b06b4394512b72c605d017748e681579056c` |

Not authored here, and not to be edited here: the matcher owns these vectors.
Change them there and copy them again when the SDK takes a new matcher release
(the version in `sdk/credentials/build.gradle.kts`). Copy with:

```sh
M=siros-dc-matcher; V=crates/siros-dc-matcher-core/tests/vectors/circuit_capabilities
git -C $M show <tag>:$V/match.json > spec/circuit-capabilities-vectors/match.json
git -C $M show <tag>:$V/README.md  > spec/circuit-capabilities-vectors/README.md
```

The SDK does not implement the capability rule: the matcher does, and the
wallet only hands it each circuit's `capabilities` as an opaque JSON string at
registration (`CircuitZkCircuit.capabilities`). So these vectors are not run
through any SDK code of its own. `SirosCredentialRegistryCapabilityVectorsTest`
(a device test, because the matcher is native) registers each case's circuits
through `SirosCredentialRegistry` and checks that the matcher offers exactly
the circuits the case expects, which proves the registration reaches the rule
unaltered. Ranking and the `expectError` cases are the catalog's, not the
matcher's; `expectRejected` cases are checked to serve nothing (and registering them must not throw); see the README
for what is and is not checked.
