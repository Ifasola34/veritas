"""Cryptographic primitives — Schnorr/tagged hash sanity."""

import os
import pytest

from veritas.crypto import (
    OracleKey,
    derive_anchor_key,
    schnorr_sign,
    schnorr_verify,
    tagged_hash,
    sha256d,
)


def test_oraclekey_generate_roundtrip():
    k = OracleKey.generate()
    assert len(k.privkey) == 32
    assert len(k.xonly_pubkey) == 32
    assert k.xonly_pubkey_hex == OracleKey.from_hex(k.privkey.hex()).xonly_pubkey_hex


def test_oraclekey_rejects_bad_inputs():
    with pytest.raises(ValueError):
        OracleKey(b"\x00" * 32)  # scalar 0 invalid
    with pytest.raises(ValueError):
        OracleKey(b"x" * 31)


def test_schnorr_sign_verify():
    k = OracleKey.generate()
    msg = os.urandom(32)
    sig = schnorr_sign(msg, k)
    assert len(sig) == 64
    assert schnorr_verify(msg, sig, k.xonly_pubkey) is True


def test_schnorr_rejects_tampered():
    k = OracleKey.generate()
    msg = os.urandom(32)
    sig = schnorr_sign(msg, k)
    # Tamper the message.
    bad_msg = bytes([msg[0] ^ 0x01]) + msg[1:]
    assert schnorr_verify(bad_msg, sig, k.xonly_pubkey) is False
    # Tamper the signature.
    bad_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
    assert schnorr_verify(msg, bad_sig, k.xonly_pubkey) is False
    # Wrong key.
    other = OracleKey.generate()
    assert schnorr_verify(msg, sig, other.xonly_pubkey) is False


def test_tagged_hash_is_deterministic_and_domain_separated():
    h1 = tagged_hash("VRT1/x", b"hello")
    h2 = tagged_hash("VRT1/x", b"hello")
    h3 = tagged_hash("VRT1/y", b"hello")  # different tag
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 32


def test_sha256d_matches_known_value():
    # SHA-256("") == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    # SHA-256d("") = SHA-256(SHA-256(""))
    expected = bytes.fromhex(
        "5df6e0e2761359d30a8275058e299fcc"
        "0381534545f55cf43e41983f5d4c9456"
    )
    assert sha256d(b"") == expected


# ---------- mutation-test-driven: derive_anchor_key test vector -------


def test_derive_anchor_key_exact_vector():
    key = OracleKey.from_hex("0" * 63 + "1")
    expected = bytes.fromhex(
        "451557d06d3ef788937b7b2f9241db3c038bb1b395442fab8cb96b69b2ec843e"
    )
    assert derive_anchor_key(key) == expected


# ---------- mutation-test-driven: schnorr_verify guards ---------------


def test_schnorr_verify_rejects_wrong_length_pubkey_only():
    k = OracleKey.generate()
    msg = os.urandom(32)
    sig = schnorr_sign(msg, k)
    assert schnorr_verify(msg, sig, k.xonly_pubkey[:31]) is False


def test_schnorr_verify_rejects_wrong_length_sig_only():
    k = OracleKey.generate()
    msg = os.urandom(32)
    sig = schnorr_sign(msg, k)
    assert schnorr_verify(msg, sig[:63], k.xonly_pubkey) is False


def test_schnorr_verify_rejects_wrong_length_msg_only():
    k = OracleKey.generate()
    msg = os.urandom(32)
    sig = schnorr_sign(msg, k)
    assert schnorr_verify(msg[:31], sig, k.xonly_pubkey) is False


def test_schnorr_verify_rejects_all_wrong_lengths():
    assert schnorr_verify(b"x", b"y", b"z") is False
