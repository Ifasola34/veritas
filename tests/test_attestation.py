"""Attestation creation, signing, and verification."""

import pytest

from veritas.attestation import (
    Attestation,
    SignedAttestation,
    attestation_digest,
    canonical_json,
    make_attestation,
    sign_attestation,
)
from veritas.crypto import OracleKey


def test_canonical_json_is_stable():
    a = {"b": 2, "a": 1, "c": [3, {"y": 4, "x": 5}]}
    b = {"c": [3, {"x": 5, "y": 4}], "a": 1, "b": 2}
    assert canonical_json(a) == canonical_json(b)


def test_sign_and_verify():
    key = OracleKey.generate()
    att = make_attestation(
        model="veritas.test.v1",
        input_hash="ab" * 32,
        output={"label": "bullish", "score": 0.42},
        epoch=7,
        oracle_pubkey_hex=key.xonly_pubkey_hex,
    )
    signed = sign_attestation(att, key)
    assert signed.verify()


def test_sign_rejects_mismatched_oracle():
    key = OracleKey.generate()
    other = OracleKey.generate()
    att = make_attestation(
        model="m", input_hash="00"*32, output=None, epoch=0,
        oracle_pubkey_hex=other.xonly_pubkey_hex,
    )
    with pytest.raises(ValueError):
        sign_attestation(att, key)


def test_tampered_output_fails_verification():
    key = OracleKey.generate()
    att = make_attestation(
        model="m", input_hash="00"*32, output={"x": 1}, epoch=0,
        oracle_pubkey_hex=key.xonly_pubkey_hex,
    )
    signed = sign_attestation(att, key)
    # Mutate output post-sign.
    signed.attestation.output = {"x": 2}
    assert signed.verify() is False


def test_json_roundtrip():
    key = OracleKey.generate()
    att = make_attestation(
        model="m", input_hash="ff"*32, output=[1, 2, 3], epoch=99,
        oracle_pubkey_hex=key.xonly_pubkey_hex,
    )
    signed = sign_attestation(att, key)
    raw = signed.to_json()
    again = SignedAttestation.from_json(raw)
    assert again.verify()
    assert attestation_digest(again.attestation) == attestation_digest(signed.attestation)


# ---------- mutation-test-driven: canonical_json exact bytes ----------


def test_canonical_json_exact_bytes():
    obj = {"b": 2, "a": 1}
    result = canonical_json(obj)
    assert result == b'{"a":1,"b":2}'


def test_canonical_json_preserves_non_ascii():
    obj = {"key": "é"}
    result = canonical_json(obj)
    assert b"\\u00e9" not in result
    assert "é".encode("utf-8") in result


# ---------- mutation-test-driven: make_attestation field binding ------


def test_make_attestation_binds_all_fields():
    key = OracleKey.generate()
    att = make_attestation(
        model="test.v1",
        input_hash="ab" * 32,
        output={"x": 1},
        epoch=42,
        oracle_pubkey_hex=key.xonly_pubkey_hex,
        ts=1700000000,
        nonce="custom_nonce",
    )
    assert att.model == "test.v1"
    assert att.input_hash == "ab" * 32
    assert att.output == {"x": 1}
    assert att.epoch == 42
    assert att.oracle == key.xonly_pubkey_hex
    assert att.ts == 1700000000
    assert att.nonce == "custom_nonce"


def test_make_attestation_default_nonce_is_empty():
    key = OracleKey.generate()
    att = make_attestation(
        model="m", input_hash="00" * 32, output=None, epoch=0,
        oracle_pubkey_hex=key.xonly_pubkey_hex, ts=1,
    )
    assert att.nonce == ""
