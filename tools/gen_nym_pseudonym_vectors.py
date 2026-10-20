#!/usr/bin/env python3
"""Generate spec/nym-pseudonym-vectors.json with INDEPENDENT code (hashlib only).

Does not call or import the Kotlin implementation. Formula, from the nym_auth
rulebook v0.4 ("Pseudonym generation function", "Configurations", "Verifier identity"):

  pseudonym = SHA256(DST || seed || prover_input || verifier_input)
  DST       = "nym_auth/v1/<config>" (UTF-8), no separators
  null input = 32 zero bytes

Usage: python3 tools/gen_nym_pseudonym_vectors.py [--check]
"""
import hashlib
import json
import pathlib
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "spec" / "nym-pseudonym-vectors.json"


def h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


Z = bytes(32)
SEED_A = bytes(range(0x00, 0x10))
SEED_B = bytes(range(0xF0, 0x100))
SEED_ARCHIVE = bytes.fromhex("4a8f9c1d2e3f4a5b6c7d8e9f0a1b2c3d")


def pseudonym(config, seed, user_value=None, vid=None, vctx=None):
    if config.startswith("known-offender-matching"):
        prover, verifier = Z, h(vid.encode())
    elif config == "account-recovery-ssc":
        prover, verifier = Z, h(h(vid.encode()), h(vctx.encode()))
    elif config == "user-managed-pseudonym-xsite-ssc":
        prover, verifier = h(user_value), Z
    else:
        raise ValueError(config)
    return h(("nym_auth/v1/" + config).encode(), seed, prover, verifier)


# Verifier id VALUE FORMS are defined by the nym_auth rulebook ("Verifier identity") and
# produced by the PDP; the derivation hashes the string verbatim. Types (informational,
# not an input): semantic or an OpenID4VP client_id_type name.
#   x509_san_dns            the Client Identifier INCLUDING its prefix: "x509_san_dns:<dns name>" (the bare DNS name is not a verifier_id)
#   x509_san_uri            URI SAN as bound
#   decentralized_identifier DID without fragment
#   openid_federation       entity id as in the chain
#   semantic                "semantic_id:" + ETSI id
DNS = "x509_san_dns:verifier.example.com"
SEM = "semantic_id:VATSE-556000000101"
SEM_LEI = "semantic_id:LEIXG-529900T8BM49AURSDO55"
URI = "https://verifier.example.com/rp"
DID = "did:web:verifier.example.com"
FED = "https://verifier.example.com/federation/entity"

# (name, config, seed, inputs); "type" is informational and kept out of the derivation.
CASES = [
    ("known-offender ssc, x509_san_dns (prefixed Client Identifier)", "known-offender-matching-ssc", SEED_A, {"verifier_id_type": "x509_san_dns", "verifier_id": DNS}),
    ("known-offender ssc, semantic (VAT)", "known-offender-matching-ssc", SEED_A, {"verifier_id_type": "semantic", "verifier_id": SEM}),
    ("known-offender ssc, semantic (LEI)", "known-offender-matching-ssc", SEED_A, {"verifier_id_type": "semantic", "verifier_id": SEM_LEI}),
    ("known-offender ssc, x509_san_uri", "known-offender-matching-ssc", SEED_A, {"verifier_id_type": "x509_san_uri", "verifier_id": URI}),
    ("known-offender ssc, decentralized_identifier", "known-offender-matching-ssc", SEED_A, {"verifier_id_type": "decentralized_identifier", "verifier_id": DID}),
    ("known-offender ssc, openid_federation", "known-offender-matching-ssc", SEED_A, {"verifier_id_type": "openid_federation", "verifier_id": FED}),
    ("known-offender ssc, other seed", "known-offender-matching-ssc", SEED_B, {"verifier_id_type": "x509_san_dns", "verifier_id": DNS}),
    ("known-offender ssc, verbatim hashing: a mixed-case value is NOT lower-cased by the derivation", "known-offender-matching-ssc", SEED_A, {"verifier_id_type": "x509_san_dns", "verifier_id": "x509_san_dns:Verifier.Example.COM"}),
    ("known-offender psc, x509_san_dns", "known-offender-matching-psc", SEED_A, {"verifier_id_type": "x509_san_dns", "verifier_id": DNS}),
    ("known-offender psc, semantic, other seed", "known-offender-matching-psc", SEED_B, {"verifier_id_type": "semantic", "verifier_id": SEM}),
    ("known-offender psc vs ssc, same seed and id differ by DST", "known-offender-matching-psc", SEED_A, {"verifier_id_type": "semantic", "verifier_id": SEM_LEI}),
    ("account-recovery, ascii context", "account-recovery-ssc", SEED_A, {"verifier_id_type": "x509_san_dns", "verifier_id": DNS, "verifier_context": "account-1234"}),
    ("account-recovery, semantic id", "account-recovery-ssc", SEED_B, {"verifier_id_type": "semantic", "verifier_id": SEM, "verifier_context": "account-1234"}),
    ("account-recovery, multi-byte UTF-8 context", "account-recovery-ssc", SEED_A, {"verifier_id_type": "x509_san_dns", "verifier_id": DNS, "verifier_context": "könto-€-日本-\U0001F512"}),
    ("account-recovery, 64-byte context (boundary)", "account-recovery-ssc", SEED_A, {"verifier_id_type": "x509_san_dns", "verifier_id": DNS, "verifier_context": "c" * 64}),
    ("account-recovery, 65-byte context (derivation accepts any length)", "account-recovery-ssc", SEED_A, {"verifier_id_type": "x509_san_dns", "verifier_id": DNS, "verifier_context": "c" * 65}),
    ("account-recovery, 64-byte multi-byte context (16 x 4-byte chars)", "account-recovery-ssc", SEED_A, {"verifier_id_type": "x509_san_dns", "verifier_id": DNS, "verifier_context": "\U0001F512" * 16}),
    ("account-recovery, empty context (derivation accepts any length)", "account-recovery-ssc", SEED_A, {"verifier_id_type": "x509_san_dns", "verifier_id": DNS, "verifier_context": ""}),
    # The nym_auth circuit developers' reference pseudonyms (zk-cred-vega test-vectors/nymauth/pseudonym.json): the check values.
    ("archive reference: ssc, x509_san_dns:verifier.example", "known-offender-matching-ssc", SEED_ARCHIVE, {"verifier_id_type": "x509_san_dns", "verifier_id": "x509_san_dns:verifier.example"}),
    ("archive reference: ssc, x509_san_dns:other-verifier.example", "known-offender-matching-ssc", SEED_ARCHIVE, {"verifier_id_type": "x509_san_dns", "verifier_id": "x509_san_dns:other-verifier.example"}),
    ("xsite, 16-byte user value", "user-managed-pseudonym-xsite-ssc", SEED_A, {"prover_input_hex": "000102030405060708090a0b0c0d0e0f"}),
    ("xsite, UTF-8 user value", "user-managed-pseudonym-xsite-ssc", SEED_B, {"prover_input_hex": "my shared värde".encode().hex()}),
    ("xsite, 100-byte user value", "user-managed-pseudonym-xsite-ssc", SEED_A, {"prover_input_hex": ("ab" * 100)}),
]

REJECT = [
    ("unknown config", "known-offender-matching-xyz", SEED_A, {"verifier_id": "v"}, "UNKNOWN_CONFIG"),
    ("unknown config, bare name", "pseudonym-v1-sha256", SEED_A, {"verifier_id": "v"}, "UNKNOWN_CONFIG"),
    ("known-offender ssc, missing verifier_id", "known-offender-matching-ssc", SEED_A, {}, "MISSING_INPUT"),
    ("known-offender psc, missing verifier_id", "known-offender-matching-psc", SEED_A, {}, "MISSING_INPUT"),
    ("account-recovery, missing verifier_id", "account-recovery-ssc", SEED_A, {"verifier_context": "c"}, "MISSING_INPUT"),
    ("account-recovery, missing verifier_context", "account-recovery-ssc", SEED_A, {"verifier_id": "v"}, "MISSING_INPUT"),
    ("xsite, missing prover_input", "user-managed-pseudonym-xsite-ssc", SEED_A, {}, "MISSING_INPUT"),
    ("known-offender ssc, verifier_context supplied", "known-offender-matching-ssc", SEED_A, {"verifier_id": "v", "verifier_context": "c"}, "UNUSED_INPUT"),
    ("known-offender ssc, prover_input supplied", "known-offender-matching-ssc", SEED_A, {"verifier_id": "v", "prover_input_hex": "00"}, "UNUSED_INPUT"),
    ("account-recovery, prover_input supplied", "account-recovery-ssc", SEED_A, {"verifier_id": "v", "verifier_context": "c", "prover_input_hex": "00"}, "UNUSED_INPUT"),
    ("xsite, verifier_id supplied", "user-managed-pseudonym-xsite-ssc", SEED_A, {"prover_input_hex": "00", "verifier_id": "v"}, "UNUSED_INPUT"),
    ("xsite, verifier_context supplied", "user-managed-pseudonym-xsite-ssc", SEED_A, {"prover_input_hex": "00", "verifier_context": "c"}, "UNUSED_INPUT"),
    ("seed too short (15)", "known-offender-matching-ssc", SEED_A[:15], {"verifier_id": "v"}, "WRONG_SEED_LENGTH"),
    ("seed too long (17)", "known-offender-matching-psc", SEED_A + b"\x00", {"verifier_id": "v"}, "WRONG_SEED_LENGTH"),
    ("seed empty", "account-recovery-ssc", b"", {"verifier_id": "v", "verifier_context": "c"}, "WRONG_SEED_LENGTH"),
    ("seed 32 bytes", "user-managed-pseudonym-xsite-ssc", bytes(32), {"prover_input_hex": "00"}, "WRONG_SEED_LENGTH"),
]


ARCHIVE = {
    "x509_san_dns:verifier.example": "155f433796d1f282268a87100cd08510893f97f6e5607bc5e4c66afadb71aad1",
    "x509_san_dns:other-verifier.example": "eefc129a09b735ea4ea6a5bc8278dc664c9849499f354d80aa37614fe8caec6b",
}


def build():
    for vid, want in ARCHIVE.items():
        got = pseudonym("known-offender-matching-ssc", SEED_ARCHIVE, None, vid, None).hex()
        assert got == want, (vid, got)
    vectors = []
    for name, config, seed, inp in CASES:
        uv = bytes.fromhex(inp["prover_input_hex"]) if "prover_input_hex" in inp else None
        exp = pseudonym(config, seed, uv, inp.get("verifier_id"), inp.get("verifier_context"))  # verifier_id_type is not an input
        vectors.append({"name": name, "config": config, "seed_hex": seed.hex(), **inp, "expected_hex": exp.hex()})
    rejects = [
        {"name": n, "config": c, "seed_hex": s.hex(), **i, "error": e} for n, c, s, i, e in REJECT
    ]
    return {
        "status": "self-generated, not yet cross-checked with the circuit developers",
        "rulebook": "nym_auth v0.4, pseudonym",
        "generator": "tools/gen_nym_pseudonym_vectors.py",
        "vectors": vectors,
        "rejections": rejects,
    }


if __name__ == "__main__":
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        sys.exit(0 if OUT.read_text() == text else "vectors out of date")
    OUT.write_text(text)
