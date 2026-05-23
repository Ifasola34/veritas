"""Bitcoin anchor transaction construction."""

import pytest
from coincurve import PrivateKey

from veritas.anchor import Utxo, build_anchor_tx, build_op_return_payload
from veritas.crypto import OracleKey, derive_anchor_key


def _anchor_pk(okey):
    priv = derive_anchor_key(okey)
    pk = PrivateKey(priv).public_key.format(compressed=True)
    return priv, pk


def test_op_return_layout():
    payload = build_op_return_payload(b"\x01" * 32, epoch=7)
    assert payload[:4] == b"VRT1"
    assert payload[4:36] == b"\x01" * 32
    assert int.from_bytes(payload[36:44], "big") == 7
    assert len(payload) == 44


def test_anchor_tx_builds_and_contains_root():
    okey = OracleKey.generate()
    priv, pk = _anchor_pk(okey)
    utxo = Utxo(txid="ab"*32, vout=1, value_sats=50_000, pubkey_compressed=pk)
    root = b"\x42" * 32
    tx = build_anchor_tx(
        utxo=utxo, privkey=priv, merkle_root=root, epoch=11, fee_sats=300,
    )
    assert len(tx.txid) == 64
    assert root.hex() in tx.raw_hex
    assert b"VRT1".hex() in tx.raw_hex
    assert tx.fee_sats == 300


def test_anchor_tx_rejects_overpay_fee():
    okey = OracleKey.generate()
    priv, pk = _anchor_pk(okey)
    utxo = Utxo(txid="cd"*32, vout=0, value_sats=200, pubkey_compressed=pk)
    with pytest.raises(ValueError):
        build_anchor_tx(
            utxo=utxo, privkey=priv, merkle_root=b"\x00"*32, epoch=0,
            fee_sats=500,
        )


def test_derive_anchor_key_is_distinct_and_deterministic():
    okey = OracleKey.generate()
    a = derive_anchor_key(okey)
    b = derive_anchor_key(okey)
    assert a == b
    assert a != okey.privkey
