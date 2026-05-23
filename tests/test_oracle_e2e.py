"""End-to-end oracle lifecycle: attest → close epoch → verify full chain."""

from pathlib import Path

from coincurve import PrivateKey

from veritas.anchor import Utxo
from veritas.attestation import attestation_digest
from veritas.crypto import OracleKey, derive_anchor_key
from veritas.merkle import verify_merkle_proof
from veritas.nostr import decode_attestation_event
from veritas.oracle import Oracle, OracleConfig
from veritas.verifier import verify_full


def _funded_utxo(okey):
    priv = derive_anchor_key(okey)
    pk = PrivateKey(priv).public_key.format(compressed=True)
    return Utxo(txid="ab"*32, vout=0, value_sats=100_000, pubkey_compressed=pk)


def test_attest_close_verify(tmp_path: Path):
    okey = OracleKey.generate()
    oracle = Oracle(okey, OracleConfig(
        data_dir=tmp_path / "data",
        anchor_utxo=_funded_utxo(okey),
        fee_sats=400,
    ))
    inputs = [
        "bullish breakout, strong rally up",
        "bearish dump and capitulation",
        "neutral chop, no edge",
        "long support, accumulate",
    ]
    signed_list = []
    events = []
    for x in inputs:
        s, e = oracle.attest("veritas.sentiment.keyword.v1", x)
        signed_list.append(s)
        events.append(e)
        assert s.verify()
        assert e.verify()

    epoch = oracle.close_epoch()
    assert epoch.closed
    assert epoch.root_hex is not None
    assert epoch.checkpoint_event is not None
    assert epoch.anchor_tx is not None
    assert epoch.anchor_tx.txid

    # Every attestation must verify under full pipeline.
    for i, signed in enumerate(signed_list):
        proof = oracle.inclusion_proof(epoch.number, i)
        assert proof is not None
        assert verify_merkle_proof(proof)
        r = verify_full(
            signed=signed,
            nostr_event=events[i],
            proof=proof,
            checkpoint_event=epoch.checkpoint_event,
            checkpoint_root_hex=epoch.root_hex,
        )
        assert r.ok, r.notes


def test_decoded_event_matches_attestation(tmp_path: Path):
    okey = OracleKey.generate()
    oracle = Oracle(okey, OracleConfig(data_dir=tmp_path))
    signed, evt = oracle.attest("veritas.sentiment.keyword.v1", "bullish")
    decoded = decode_attestation_event(evt)
    assert decoded.verify()
    assert attestation_digest(decoded.attestation) == attestation_digest(signed.attestation)


def test_persistence_files_written(tmp_path: Path):
    okey = OracleKey.generate()
    oracle = Oracle(okey, OracleConfig(data_dir=tmp_path))
    oracle.attest("veritas.sentiment.keyword.v1", "test input one")
    oracle.attest("veritas.sentiment.keyword.v1", "test input two")
    oracle.close_epoch()
    epoch_dir = tmp_path / "epoch_00000000"
    assert (epoch_dir / "checkpoint.json").exists()
    assert (epoch_dir / "atts" / "00000000.json").exists()
    assert (epoch_dir / "atts" / "00000001.json").exists()
