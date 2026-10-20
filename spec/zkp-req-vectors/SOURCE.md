# Provenance

Verbatim copy of the `zkp_req` conformance vectors of the shared matcher,
`crates/siros-dc-matcher-core/tests/vectors/{zkp_req,zkp_req_response,zkp_req_unsat,proof_time}/` in
[sirosfoundation/siros-dc-matcher](https://github.com/sirosfoundation/siros-dc-matcher) at tag `v0.11.0`
(commit `09ac62fbdd02af47cf1b143dfc2613e509445395`; rulebook v0.4, matcher pull request 50 merged as `93047bc7`). Counts:
54 / 143 / 43 / 1 json files (plus each directory's README). The vectors are unchanged since `93047bc7`.

Vector set digest (`scripts/vectors_digest.sh` of the matcher: the sha256 of the sorted `sha256sum` manifest of the json
files, paths relative to `tests/vectors`, README.md excluded):

    9f482d7a3fb87cb1381d0dfb7a2fc396b6cd3c1eba07c5d76f44e47142b751ac

The SDK test `ZkpReqVectorsTest` recomputes it. Not authored here and not to be edited here: the matcher owns them.

The normative text is `docs/zkp_req_request.md` and `docs/zkp_req_response.md` of the matcher at that tag.

The matcher binary bundled through `org.siros:siros-dc-matcher:0.11.0` (`assets/matcher.wasm` of the released AAR) has sha256
`459369181e36f13385571c3ca2dc7aeb34c34a647483ec82f73e5b9bd5d0721a`; the vendored Kotlin bindings are byte-identical to
`bindings/kotlin` of the tag.
