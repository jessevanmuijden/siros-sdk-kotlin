#!/usr/bin/env python3
"""Generate spec/secret-seed-commitment-vectors.json with INDEPENDENT code (hashlib only).

Does not call or import the Kotlin implementation. The relation, from the nym_auth
rulebook v0.3 (the `ssc` data element is the issuer's commitment to the `secret_seed`):

  ssc = SHA256(secret_seed)        secret_seed: exactly 16 bytes; ssc: exactly 32 bytes

A wallet that was DELIVERED a secret_seed must check this against the credential's `ssc`
before it proves anything from the seed. Rejections carry the presenter step that refuses:
  WITNESS            the seed is absent or not 16 bytes
  SECRET_COMMITMENT  the ssc is not 32 bytes, or SHA256(seed) != ssc

Usage: python3 tools/gen_secret_seed_commitment_vectors.py [--check]
"""
import hashlib
import json
import pathlib
import sys

OUT = pathlib.Path(__file__).resolve().parent.parent / "spec" / "secret-seed-commitment-vectors.json"


def h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


SEED_A = bytes(range(0x00, 0x10))
SEED_B = bytes(range(0xF0, 0x100))
ZERO16 = bytes(16)
FF16 = b"\xff" * 16

VALID = [
    ("SEED_A (00..0f)", SEED_A),
    ("SEED_B (f0..ff)", SEED_B),
    ("all-zero seed", ZERO16),
    ("all-0xff seed", FF16),
]


def flip(b: bytes) -> bytes:
    return b[:-1] + bytes([b[-1] ^ 0x01])


REJECT = [
    # (name, seed, ssc, step)
    ("seed 15 bytes", SEED_A[:15], h(SEED_A), "WITNESS"),
    ("seed 15 bytes, ssc of the 15 bytes", SEED_A[:15], h(SEED_A[:15]), "WITNESS"),
    ("seed 17 bytes", SEED_A + b"\x00", h(SEED_A), "WITNESS"),
    ("seed 17 bytes, ssc of the 17 bytes", SEED_A + b"\x00", h(SEED_A + b"\x00"), "WITNESS"),
    ("seed 32 bytes (a hash, not a seed)", h(SEED_A), h(h(SEED_A)), "WITNESS"),
    ("seed empty", b"", h(b""), "WITNESS"),
    ("seed of another credential", SEED_B, h(SEED_A), "SECRET_COMMITMENT"),
    ("ssc differs in one bit", SEED_A, flip(h(SEED_A)), "SECRET_COMMITMENT"),
    ("ssc all zero", SEED_A, bytes(32), "SECRET_COMMITMENT"),
    ("ssc is the seed padded to 32 bytes", SEED_A, SEED_A + bytes(16), "SECRET_COMMITMENT"),
    ("ssc is the double hash", SEED_A, h(h(SEED_A)), "SECRET_COMMITMENT"),
    ("ssc 31 bytes (truncated)", SEED_A, h(SEED_A)[:31], "SECRET_COMMITMENT"),
    ("ssc 33 bytes (extended)", SEED_A, h(SEED_A) + b"\x00", "SECRET_COMMITMENT"),
    ("ssc empty", SEED_A, b"", "SECRET_COMMITMENT"),
]


def build():
    return {
        "status": "self-generated, not yet cross-checked with the circuit developers",
        "rulebook": "nym_auth v0.3, ssc = SHA256(secret_seed)",
        "generator": "tools/gen_secret_seed_commitment_vectors.py",
        "vectors": [{"name": n, "seed_hex": s.hex(), "ssc_hex": h(s).hex()} for n, s in VALID],
        "rejections": [
            {"name": n, "seed_hex": s.hex(), "ssc_hex": c.hex(), "step": step} for n, s, c, step in REJECT
        ],
    }


if __name__ == "__main__":
    text = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        sys.exit(0 if OUT.read_text() == text else "vectors out of date")
    OUT.write_text(text)
