"""Adversarial verifier tests.

Each test constructs a SCENARIO an attacker would attempt, then asserts
that verify_full returns ok=False. The point is regression safety: if
anyone weakens a binding check later, these tests catch it before the
grant reviewer or an actual attacker does.

We use a real Oracle + close_epoch to produce honest artifacts, then
mutate one specific field at a time so each test isolates exactly one
broken invariant.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from coincurve import PrivateKey

from veritas.anchor import (
    Utxo,
    build_anchor_tx,
    build_op_return_payload,
    extract_op_return_from_raw_tx,
    derive_anchor_pubkey,
)
from veritas.attestation import (
    Attestation,
    SignedAttestation,
    attestation_digest,
    make_attestation,
    sign_attestation,
)
from veritas.crypto import OracleKey, derive_anchor_key
from veritas.merkle import MerkleProof, MerkleTree, verify_merkle_proof
from veritas.nostr import (
    NostrEvent,
    build_attestation_event,
    build_checkpoint_event,
)
from veritas.oracle import Oracle, OracleConfig
from veritas.verifier import verify_full


# ---------- helpers ------------------------------------------------


def _funded_utxo(okey: OracleKey) -> Utxo:
    priv = derive_anchor_key(okey)
    return Utxo(
        txid="ab" * 32, vout=0, value_sats=100_000,
        pubkey_compressed=derive_anchor_pubkey(priv),
    )


@pytest.fixture
def honest_epoch(tmp_path: Path):
    """A real, honest closed epoch: oracle, attestations, proofs,
    checkpoint, anchor tx. Tests then mutate one piece to attack.
    """
    okey = OracleKey.generate()
    oracle = Oracle(okey, OracleConfig(
        data_dir=tmp_path / "data",
        anchor_utxo=_funded_utxo(okey),
        fee_sats=400,
    ))
    inputs = [f"input number {i}" for i in range(4)]
    signed_list, events = [], []
    for x in inputs:
        s, e = oracle.attest("veritas.sentiment.keyword.v1", x)
        signed_list.append(s)
        events.append(e)
    epoch = oracle.close_epoch()
    proofs = [oracle.inclusion_proof(epoch.number, i) for i in range(len(signed_list))]
    return {
        "oracle": oracle,
        "okey": okey,
        "epoch": epoch,
        "signed": signed_list,
        "events": events,
        "proofs": proofs,
    }


# ---------- baseline: honest verify must pass ----------------------


def test_baseline_honest_full_chain_verifies(honest_epoch):
    h = honest_epoch
    r = verify_full(
        signed=h["signed"][0],
        nostr_event=h["events"][0],
        proof=h["proofs"][0],
        checkpoint_event=h["epoch"].checkpoint_event,
        anchor_raw_tx_hex=h["epoch"].anchor_tx.raw_hex,
    )
    assert r.ok, r.notes
    assert r.schnorr_ok and r.nostr_event_ok and r.merkle_ok
    assert r.checkpoint_ok and r.anchor_ok


# ---------- attestation tampering ----------------------------------


def test_rejects_attestation_with_swapped_output(honest_epoch):
    h = honest_epoch
    bad = copy.deepcopy(h["signed"][0])
    bad.attestation.output = {"label": "tampered"}
    r = verify_full(signed=bad)
    assert r.ok is False
    assert r.schnorr_ok is False


def test_rejects_signed_attestation_with_other_oracle_pubkey(honest_epoch):
    h = honest_epoch
    bad = copy.deepcopy(h["signed"][0])
    bad.attestation.oracle = "ff" * 32
    r = verify_full(signed=bad)
    assert r.ok is False


# ---------- nostr event tampering ----------------------------------


def test_rejects_nostr_event_with_different_pubkey(honest_epoch):
    h = honest_epoch
    other = OracleKey.generate()
    bad_evt = copy.deepcopy(h["events"][0])
    bad_evt.pubkey = other.xonly_pubkey_hex
    bad_evt.sign(other)  # make the sig verify so we isolate the pubkey-bind check
    r = verify_full(signed=h["signed"][0], nostr_event=bad_evt)
    assert r.ok is False
    assert r.nostr_event_ok is False
    assert any("pubkey" in n.lower() for n in r.notes)


# ---------- merkle proof tampering ---------------------------------


def test_rejects_proof_with_wrong_leaf(honest_epoch):
    h = honest_epoch
    p = h["proofs"][0]
    bad = MerkleProof(
        leaf=b"\x00" * 32, siblings=p.siblings, directions=p.directions,
        root=p.root, size=p.size, index=p.index,
    )
    r = verify_full(signed=h["signed"][0], proof=bad)
    assert r.ok is False
    assert r.merkle_ok is False


def test_rejects_proof_with_inflated_size(honest_epoch):
    h = honest_epoch
    p = h["proofs"][0]
    bad = MerkleProof(
        leaf=p.leaf, siblings=p.siblings, directions=p.directions,
        root=p.root, size=p.size * 1000, index=p.index,
    )
    r = verify_full(signed=h["signed"][0], proof=bad)
    assert r.ok is False
    assert r.merkle_ok is False


def test_rejects_proof_with_swapped_indices(honest_epoch):
    """Proof for attestation 0 served as if for attestation 2."""
    h = honest_epoch
    p_for_0 = h["proofs"][0]
    # Try to verify attestation 2 against attestation 0's proof.
    r = verify_full(signed=h["signed"][2], proof=p_for_0)
    assert r.ok is False
    assert r.merkle_ok is False


# ---------- checkpoint binding -------------------------------------


def test_rejects_checkpoint_for_different_epoch(honest_epoch):
    """Checkpoint validly signed by the same oracle but for a different epoch."""
    h = honest_epoch
    forged_cp = build_checkpoint_event(
        key=h["okey"], epoch=h["epoch"].number + 99,
        merkle_root_hex=h["epoch"].root_hex,
        leaf_count=len(h["signed"]),
        anchor_txid=h["epoch"].anchor_tx.txid,
    )
    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        checkpoint_event=forged_cp,
    )
    assert r.ok is False
    assert r.checkpoint_ok is False
    assert any("epoch" in n.lower() for n in r.notes)


def test_rejects_checkpoint_signed_by_different_oracle(honest_epoch):
    h = honest_epoch
    attacker = OracleKey.generate()
    forged_cp = build_checkpoint_event(
        key=attacker, epoch=h["epoch"].number,
        merkle_root_hex=h["epoch"].root_hex,
        leaf_count=len(h["signed"]),
        anchor_txid=h["epoch"].anchor_tx.txid,
    )
    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        checkpoint_event=forged_cp,
    )
    assert r.ok is False
    assert r.checkpoint_ok is False


def test_rejects_checkpoint_committing_to_different_root(honest_epoch):
    h = honest_epoch
    forged_cp = build_checkpoint_event(
        key=h["okey"], epoch=h["epoch"].number,
        merkle_root_hex="ee" * 32,  # wrong root
        leaf_count=len(h["signed"]),
        anchor_txid=h["epoch"].anchor_tx.txid,
    )
    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        checkpoint_event=forged_cp,
    )
    assert r.ok is False
    assert r.checkpoint_ok is False


def test_rejects_checkpoint_with_wrong_leaf_count(honest_epoch):
    h = honest_epoch
    forged_cp = build_checkpoint_event(
        key=h["okey"], epoch=h["epoch"].number,
        merkle_root_hex=h["epoch"].root_hex,
        leaf_count=len(h["signed"]) + 5,
        anchor_txid=h["epoch"].anchor_tx.txid,
    )
    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        checkpoint_event=forged_cp,
    )
    assert r.ok is False
    assert r.checkpoint_ok is False


def test_rejects_checkpoint_supplied_without_proof(honest_epoch):
    """Round-2 finding: digest is never bound to the checkpoint root
    without a proof, so verify_full must fail closed."""
    h = honest_epoch
    r = verify_full(
        signed=h["signed"][0],
        checkpoint_event=h["epoch"].checkpoint_event,
    )
    assert r.ok is False
    assert r.checkpoint_ok is False
    assert any("without inclusion proof" in n for n in r.notes)


# ---------- anchor binding -----------------------------------------


def test_rejects_anchor_supplied_without_proof(honest_epoch):
    """Round-2 finding: digest is never bound to the on-chain root
    without a proof, so verify_full must fail closed."""
    h = honest_epoch
    r = verify_full(
        signed=h["signed"][0],
        anchor_raw_tx_hex=h["epoch"].anchor_tx.raw_hex,
    )
    assert r.ok is False
    assert r.anchor_ok is False


def test_rejects_anchor_with_mismatched_op_return_root(honest_epoch):
    """Build a parallel anchor tx whose OP_RETURN commits to a different
    Merkle root than the checkpoint signed."""
    h = honest_epoch
    priv = derive_anchor_key(h["okey"])
    rogue_tx = build_anchor_tx(
        utxo=_funded_utxo(h["okey"]),
        privkey=priv,
        merkle_root=b"\xee" * 32,    # different root
        epoch=h["epoch"].number,
        leaf_count=len(h["signed"]),
        fee_sats=400,
    )
    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        checkpoint_event=h["epoch"].checkpoint_event,
        anchor_raw_tx_hex=rogue_tx.raw_hex,
    )
    assert r.ok is False
    assert r.anchor_ok is False


def test_rejects_anchor_with_mismatched_epoch(honest_epoch):
    h = honest_epoch
    priv = derive_anchor_key(h["okey"])
    rogue_tx = build_anchor_tx(
        utxo=_funded_utxo(h["okey"]),
        privkey=priv,
        merkle_root=bytes.fromhex(h["epoch"].root_hex),
        epoch=h["epoch"].number + 1,  # wrong epoch
        leaf_count=len(h["signed"]),
        fee_sats=400,
    )
    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        checkpoint_event=h["epoch"].checkpoint_event,
        anchor_raw_tx_hex=rogue_tx.raw_hex,
    )
    assert r.ok is False
    assert r.anchor_ok is False


def test_rejects_anchor_with_no_op_return(honest_epoch):
    h = honest_epoch
    # P2WPKH tx with no OP_RETURN — build a fake hex skeleton.
    # Use a real legitimately-built tx and strip its OP_RETURN output.
    # Easiest: construct a synthetic minimal tx by hand.
    # version=2, no-segwit-flag, 1 in, 1 out (no OP_RETURN), locktime=0.
    fake_tx = (
        b"\x02\x00\x00\x00"                                 # version
        + b"\x01"                                            # 1 input
        + (b"\x00" * 32) + (0).to_bytes(4, "little")         # outpoint
        + b"\x00"                                            # empty scriptSig
        + b"\xff\xff\xff\xff"                                # sequence
        + b"\x01"                                            # 1 output
        + (1000).to_bytes(8, "little")                       # value
        + b"\x16\x00\x14" + b"\x00" * 20                     # P2WPKH script (22 bytes)
        + b"\x00\x00\x00\x00"                                # locktime
    )
    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        anchor_raw_tx_hex=fake_tx.hex(),
    )
    assert r.ok is False
    assert r.anchor_ok is False


def test_rejects_truncated_anchor_hex(honest_epoch):
    h = honest_epoch
    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        anchor_raw_tx_hex="0100",  # 2 bytes
    )
    assert r.ok is False
    assert r.anchor_ok is False


def test_rejects_adversarial_varint_anchor_hex(honest_epoch):
    h = honest_epoch
    # Build a tx whose n_in varint claims 0xFFFFFFFF inputs.
    fake = bytes.fromhex("01000000" + "0001" + "fe" + "ff" * 4)
    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        anchor_raw_tx_hex=fake.hex(),
    )
    assert r.ok is False
    assert r.anchor_ok is False


# ---------- cross-artifact swaps -----------------------------------


def test_rejects_proof_from_different_epoch(honest_epoch, tmp_path: Path):
    """Build a second oracle/epoch, then try to use its proof against
    artifacts from the honest epoch — the leaf-vs-digest check should
    catch it even if root happens to look plausible."""
    h = honest_epoch
    other_okey = OracleKey.generate()
    other_oracle = Oracle(other_okey, OracleConfig(data_dir=tmp_path / "other"))
    other_signed, _ = other_oracle.attest("veritas.sentiment.keyword.v1", "x")
    other_epoch = other_oracle.close_epoch()
    other_proof = other_oracle.inclusion_proof(other_epoch.number, 0)

    r = verify_full(
        signed=h["signed"][0],          # honest attestation
        proof=other_proof,              # foreign proof
        checkpoint_event=h["epoch"].checkpoint_event,
    )
    assert r.ok is False
    # Should fail because foreign proof's leaf != honest attestation's digest.
    assert r.merkle_ok is False


def test_baseline_idempotent(honest_epoch):
    """Repeated verification of the same honest artifacts is stable."""
    h = honest_epoch
    r1 = verify_full(
        signed=h["signed"][1],
        nostr_event=h["events"][1],
        proof=h["proofs"][1],
        checkpoint_event=h["epoch"].checkpoint_event,
        anchor_raw_tx_hex=h["epoch"].anchor_tx.raw_hex,
    )
    r2 = verify_full(
        signed=h["signed"][1],
        nostr_event=h["events"][1],
        proof=h["proofs"][1],
        checkpoint_event=h["epoch"].checkpoint_event,
        anchor_raw_tx_hex=h["epoch"].anchor_tx.raw_hex,
    )
    assert r1.ok and r2.ok
    assert r1.notes == r2.notes
