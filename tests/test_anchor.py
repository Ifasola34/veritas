"""Bitcoin anchor transaction construction."""

import pytest
from coincurve import PrivateKey

from veritas.anchor import (
    OP_RETURN_VERSION,
    Utxo,
    build_anchor_tx,
    build_op_return_payload,
    derive_anchor_pubkey,
    extract_op_return_from_raw_tx,
    parse_op_return_payload,
)
from veritas.crypto import OracleKey, derive_anchor_key


def _anchor_pk(okey):
    priv = derive_anchor_key(okey)
    return priv, derive_anchor_pubkey(priv)


def test_op_return_layout():
    payload = build_op_return_payload(b"\x01" * 32, epoch=7, leaf_count=42)
    assert payload[:4] == b"VRT1"
    assert payload[4] == OP_RETURN_VERSION
    assert int.from_bytes(payload[5:13], "big") == 7
    assert int.from_bytes(payload[13:17], "big") == 42
    assert payload[17:49] == b"\x01" * 32
    assert len(payload) == 49


def test_op_return_roundtrip():
    payload = build_op_return_payload(b"\xab" * 32, epoch=99, leaf_count=128)
    parsed = parse_op_return_payload(payload)
    assert parsed["tag"] == "VRT1"
    assert parsed["version"] == OP_RETURN_VERSION
    assert parsed["epoch"] == 99
    assert parsed["leaf_count"] == 128
    assert parsed["merkle_root"] == b"\xab" * 32


def test_anchor_tx_builds_and_contains_root():
    okey = OracleKey.generate()
    priv, pk = _anchor_pk(okey)
    utxo = Utxo(txid="ab"*32, vout=1, value_sats=50_000, pubkey_compressed=pk)
    root = b"\x42" * 32
    tx = build_anchor_tx(
        utxo=utxo, privkey=priv, merkle_root=root, epoch=11,
        leaf_count=3, fee_sats=300,
    )
    assert len(tx.txid) == 64
    assert root.hex() in tx.raw_hex
    assert b"VRT1".hex() in tx.raw_hex
    assert tx.fee_sats == 300


def test_anchor_tx_extract_op_return_roundtrip():
    okey = OracleKey.generate()
    priv, pk = _anchor_pk(okey)
    utxo = Utxo(txid="ab"*32, vout=0, value_sats=10_000, pubkey_compressed=pk)
    root = b"\xcc" * 32
    tx = build_anchor_tx(
        utxo=utxo, privkey=priv, merkle_root=root, epoch=5,
        leaf_count=17, fee_sats=400,
    )
    payload = extract_op_return_from_raw_tx(tx.raw_hex)
    assert payload is not None
    parsed = parse_op_return_payload(payload)
    assert parsed["epoch"] == 5
    assert parsed["leaf_count"] == 17
    assert parsed["merkle_root"] == root


def test_anchor_tx_rejects_overpay_fee():
    okey = OracleKey.generate()
    priv, pk = _anchor_pk(okey)
    utxo = Utxo(txid="cd"*32, vout=0, value_sats=200, pubkey_compressed=pk)
    with pytest.raises(ValueError):
        build_anchor_tx(
            utxo=utxo, privkey=priv, merkle_root=b"\x00"*32, epoch=0,
            leaf_count=1, fee_sats=500,
        )


def test_anchor_tx_rejects_mismatched_utxo_pubkey():
    okey = OracleKey.generate()
    priv, _ = _anchor_pk(okey)
    other = OracleKey.generate()
    _, wrong_pk = _anchor_pk(other)
    utxo = Utxo(txid="ef"*32, vout=0, value_sats=10_000, pubkey_compressed=wrong_pk)
    with pytest.raises(ValueError, match="does not match"):
        build_anchor_tx(
            utxo=utxo, privkey=priv, merkle_root=b"\x00"*32, epoch=0,
            leaf_count=1, fee_sats=300,
        )


def test_derive_anchor_key_is_distinct_and_deterministic():
    okey = OracleKey.generate()
    a = derive_anchor_key(okey)
    b = derive_anchor_key(okey)
    assert a == b
    assert a != okey.privkey
