"""Nostr event construction & verification."""

from veritas.attestation import make_attestation, sign_attestation
from veritas.crypto import OracleKey
from veritas.nostr import (
    build_attestation_event,
    build_checkpoint_event,
    decode_attestation_event,
    KIND_VERITAS_ATTESTATION,
    KIND_VERITAS_CHECKPOINT,
)


def test_attestation_event_verifies():
    key = OracleKey.generate()
    att = make_attestation(model="m", input_hash="ab"*32, output={"x": 1},
                           epoch=1, oracle_pubkey_hex=key.xonly_pubkey_hex)
    signed = sign_attestation(att, key)
    evt = build_attestation_event(signed, key, index_in_epoch=0)
    assert evt.verify()
    assert evt.kind == KIND_VERITAS_ATTESTATION
    assert evt.pubkey == key.xonly_pubkey_hex


def test_decode_roundtrip():
    key = OracleKey.generate()
    att = make_attestation(model="m", input_hash="cd"*32, output=[1, 2],
                           epoch=2, oracle_pubkey_hex=key.xonly_pubkey_hex)
    signed = sign_attestation(att, key)
    evt = build_attestation_event(signed, key, index_in_epoch=4)
    sa = decode_attestation_event(evt)
    assert sa.verify()
    assert sa.attestation.epoch == 2
    assert sa.attestation.output == [1, 2]


def test_checkpoint_event_verifies():
    key = OracleKey.generate()
    evt = build_checkpoint_event(
        key=key, epoch=42, merkle_root_hex="ff"*32, leaf_count=10,
        anchor_txid="aa"*32,
    )
    assert evt.verify()
    assert evt.kind == KIND_VERITAS_CHECKPOINT
    assert any(t == ["d", "checkpoint:42"] for t in evt.tags)


def test_tampered_event_rejected():
    key = OracleKey.generate()
    att = make_attestation(model="m", input_hash="01"*32, output={"x": 1},
                           epoch=1, oracle_pubkey_hex=key.xonly_pubkey_hex)
    signed = sign_attestation(att, key)
    evt = build_attestation_event(signed, key, 0)
    # Mutate content; id should no longer match.
    evt.content = evt.content + "x"
    assert evt.verify() is False
