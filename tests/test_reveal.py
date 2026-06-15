"""Salted commitment + commit-and-reveal verification.

Covers Build B of the "cheap builds": the oracle can produce a *salted*
input_hash so a low-entropy input can't be recovered by guessing the
published hash, and `verify_reveal` confirms a revealed (content, salt)
reproduces the committed fingerprint.
"""

import pytest

from veritas.crypto import OracleKey
from veritas.models import normalize_input
from veritas.oracle import Oracle, OracleConfig
from veritas.verifier import verify_full, verify_reveal


GENESIS_TEXT = (
    "VERITAS mainnet genesis: verifiable AI attestation anchored to "
    "Bitcoin (2026-06-13)"
)
GENESIS_HASH = "f16e4f7f799732b01c2f19d87309c1d87bff140491818cb3ecb2aacef2c74f1d"


# ── normalize_input ─────────────────────────────────────────────────────────

def test_unsalted_reproduces_on_chain_genesis():
    """salt="" must be byte-for-byte the original bare commitment, so the
    real on-chain genesis attestation still verifies."""
    _, h = normalize_input(GENESIS_TEXT)
    assert h == GENESIS_HASH
    # explicit empty salt is identical to the default
    assert normalize_input(GENESIS_TEXT, salt="") == normalize_input(GENESIS_TEXT)


def test_normalization_is_case_and_whitespace_insensitive():
    a = normalize_input("  VERITAS   Mainnet\tGenesis ")[1]
    b = normalize_input("veritas mainnet genesis")[1]
    assert a == b


def test_salt_changes_the_commitment():
    bare = normalize_input("approved")[1]
    salted = normalize_input("approved", salt="9f8e7d6c5b4a39281706f5e4d3c2b1a0")[1]
    assert bare != salted


def test_salt_matches_cross_language_vector():
    """This exact triple is asserted in the JS verifier's self-test too, so
    the Python signer and the browser verifier provably agree."""
    _, h = normalize_input("approved", salt="9f8e7d6c5b4a39281706f5e4d3c2b1a0")
    assert h == "5089006b47fda34d47aedbb75b7cc4cc2ac93b722912557c38ead4422d6bc7d5"


# ── the guessing gap the salt closes ────────────────────────────────────────

def test_bare_commitment_is_guessable_but_salted_is_not():
    """A bare hash of a low-entropy decision is recoverable by brute force;
    the salted commitment is not, without the secret salt."""
    decisions = ["approved", "denied", "escalated", "refunded"]
    secret_decision = "denied"

    # Bare: an adversary who only has the published input_hash recovers the
    # decision by hashing the small candidate set.
    bare = normalize_input(secret_decision)[1]
    recovered = [d for d in decisions if normalize_input(d)[1] == bare]
    assert recovered == [secret_decision]  # gap demonstrated

    # Salted: the same brute force over candidate decisions fails, because the
    # adversary lacks the 128-bit secret salt.
    salt = Oracle.gen_salt()
    salted = normalize_input(secret_decision, salt=salt)[1]
    recovered_salted = [d for d in decisions if normalize_input(d)[1] == salted]
    assert recovered_salted == []  # gap closed


def test_gen_salt_is_random_and_128_bit():
    s1, s2 = Oracle.gen_salt(), Oracle.gen_salt()
    assert s1 != s2
    assert len(s1) == 32 and bytes.fromhex(s1)  # 16 bytes of hex


# ── verify_reveal ───────────────────────────────────────────────────────────

def test_verify_reveal_unsalted_roundtrip():
    _, h = normalize_input(GENESIS_TEXT)
    assert verify_reveal(GENESIS_TEXT, h) is True
    assert verify_reveal("a different record", h) is False


def test_verify_reveal_salted_roundtrip():
    salt = Oracle.gen_salt()
    _, h = normalize_input("approved", salt=salt)
    # correct content + correct salt
    assert verify_reveal("approved", h, salt=salt) is True
    # right content, wrong salt
    assert verify_reveal("approved", h, salt=Oracle.gen_salt()) is False
    # right content, missing salt
    assert verify_reveal("approved", h) is False
    # wrong content, right salt
    assert verify_reveal("denied", h, salt=salt) is False


def test_verify_reveal_tolerates_input_hash_formatting():
    _, h = normalize_input(GENESIS_TEXT)
    assert verify_reveal(GENESIS_TEXT, f"  {h.upper()}  ") is True


# ── end-to-end through the oracle ───────────────────────────────────────────

def test_salted_attestation_still_verifies_and_reveals(tmp_path):
    """A salted attestation signs, verifies (Schnorr + Merkle), and the
    original content reveals against its committed input_hash — while the
    salt never appears in the published attestation or event."""
    key = OracleKey.generate()
    oracle = Oracle(key, OracleConfig(data_dir=tmp_path / "data"))

    salt = Oracle.gen_salt()
    content = "approved"
    signed, evt = oracle.attest("veritas.sentiment.keyword.v1", content, salt=salt)

    # Attestation is internally valid and bears the salted commitment.
    assert signed.verify() is True
    _, expected = normalize_input(content, salt=salt)
    assert signed.attestation.input_hash == expected

    # Merkle inclusion still works after closing the epoch.
    epoch = oracle.close_epoch()
    proof = oracle.inclusion_proof(epoch.number, 0)
    result = verify_full(signed=signed, proof=proof)
    assert result.schnorr_ok and result.merkle_ok

    # The secret salt is NOT leaked into anything published.
    assert salt not in signed.to_json()
    assert salt not in str(evt.to_dict())

    # Reveal verifies; a wrong salt does not.
    assert verify_reveal(content, signed.attestation.input_hash, salt=salt) is True
    assert verify_reveal(content, signed.attestation.input_hash,
                         salt=Oracle.gen_salt()) is False


def test_unsalted_attest_is_unchanged(tmp_path):
    """Default attest() (no salt) is byte-identical to the pre-salt behaviour,
    so existing callers and the on-chain genesis are unaffected."""
    key = OracleKey.generate()
    oracle = Oracle(key, OracleConfig(data_dir=tmp_path / "data"))
    signed, _ = oracle.attest("veritas.sentiment.keyword.v1", GENESIS_TEXT)
    _, bare = normalize_input(GENESIS_TEXT)
    assert signed.attestation.input_hash == bare
