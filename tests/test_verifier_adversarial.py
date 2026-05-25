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


# ============================================================================
# Round-3 regression tests — fixes added in commit after the original
# 20-case suite. Each test names exactly one round-3 attack class.
# ============================================================================


# ---------- verifier.py: TypeError-not-caught -----------------------


def test_rejects_checkpoint_with_null_epoch(honest_epoch):
    """Round-3 fix: int(checkpoint_payload['epoch']) used to raise
    TypeError on null/list/dict, crashing the verifier instead of
    returning ok=False with a note."""
    h = honest_epoch
    # Forge a checkpoint with epoch=null in the signed content.
    forged_cp = build_checkpoint_event(
        key=h["okey"], epoch=h["epoch"].number,
        merkle_root_hex=h["epoch"].root_hex,
        leaf_count=len(h["signed"]),
        anchor_txid=h["epoch"].anchor_tx.txid,
    )
    # Tamper the signed content directly (re-sign to keep outer sig valid).
    import json
    content_dict = json.loads(forged_cp.content)
    content_dict["epoch"] = None
    forged_cp.content = json.dumps(content_dict)
    forged_cp.sign(h["okey"])

    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        checkpoint_event=forged_cp,
    )
    assert r.ok is False
    assert r.checkpoint_ok is False
    assert any("epoch" in n.lower() and "invalid" in n.lower() for n in r.notes)


def test_rejects_checkpoint_with_null_count(honest_epoch):
    """Round-3 fix: int(checkpoint_payload['count']) used to raise
    TypeError on null."""
    h = honest_epoch
    forged_cp = build_checkpoint_event(
        key=h["okey"], epoch=h["epoch"].number,
        merkle_root_hex=h["epoch"].root_hex,
        leaf_count=len(h["signed"]),
        anchor_txid=h["epoch"].anchor_tx.txid,
    )
    import json
    content_dict = json.loads(forged_cp.content)
    content_dict["count"] = None
    forged_cp.content = json.dumps(content_dict)
    forged_cp.sign(h["okey"])

    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        checkpoint_event=forged_cp,
    )
    assert r.ok is False
    assert r.checkpoint_ok is False


# ---------- adversarial coverage gaps from round-3 ------------------


def test_rejects_op_return_with_wrong_protocol_tag(honest_epoch):
    """parse_op_return_payload raises on a payload whose 4-byte tag
    isn't 'VRT1'. End-to-end test through verify_full was missing."""
    h = honest_epoch
    # Build a tx with a forged OP_RETURN: same length, wrong tag.
    # Easier: take a real anchor tx and verify a bogus raw_hex fails.
    from veritas.anchor import build_op_return_payload
    from veritas.anchor import _op_return_script  # private but small
    # Construct a malformed payload directly:
    bad_payload = b"WRNG" + b"\x01" + (h["epoch"].number).to_bytes(8, "big") \
        + (4).to_bytes(4, "big") + b"\xcc" * 32   # 49 bytes, wrong tag
    # We can't easily inject this into a tx without rebuilding the whole
    # thing, so use the real anchor tx but pass an extracted-and-mutated
    # form via the optional anchor_raw_tx_hex. Cheaper path: verify
    # parse_op_return_payload rejects directly.
    from veritas.anchor import parse_op_return_payload
    with pytest.raises(ValueError, match="unknown protocol tag"):
        parse_op_return_payload(bad_payload)


def test_rejects_op_return_with_wrong_version_byte():
    """parse_op_return_payload should reject a payload whose version
    byte isn't the supported value."""
    from veritas.anchor import parse_op_return_payload
    bad = b"VRT1" + b"\xff" + (5).to_bytes(8, "big") + (3).to_bytes(4, "big") + b"\xcc" * 32
    with pytest.raises(ValueError, match="unsupported OP_RETURN version"):
        parse_op_return_payload(bad)


def test_rejects_op_return_with_wrong_length():
    """A payload shorter or longer than 49 bytes must be rejected."""
    from veritas.anchor import parse_op_return_payload
    with pytest.raises(ValueError, match="wrong length"):
        parse_op_return_payload(b"VRT1\x01\x00" * 5)   # 30 bytes


def test_rejects_nostr_event_with_tampered_sig_bytes(honest_epoch):
    """Existing tests cover pubkey mismatch — this covers a flipped
    sig byte where the pubkey still matches."""
    h = honest_epoch
    forged_evt = copy.deepcopy(h["events"][0])
    # Flip one bit of the sig (after the first char, to stay valid hex).
    old_sig = forged_evt.sig
    forged_evt.sig = ("0" if old_sig[0] != "0" else "1") + old_sig[1:]
    r = verify_full(signed=h["signed"][0], nostr_event=forged_evt)
    assert r.ok is False
    assert r.nostr_event_ok is False


def test_rejects_checkpoint_vs_anchor_leaf_count_mismatch(honest_epoch):
    """Checkpoint says count=N, on-chain OP_RETURN says count=N+1.
    Round-3 noted current adversarial suite only covers epoch + root
    mismatches between checkpoint and anchor."""
    from veritas.anchor import build_anchor_tx
    from veritas.crypto import derive_anchor_key
    h = honest_epoch
    # Build a parallel anchor tx with a LIE about leaf_count.
    priv = derive_anchor_key(h["okey"])
    real_root = bytes.fromhex(h["epoch"].root_hex)
    real_count = len(h["signed"])
    lying_anchor = build_anchor_tx(
        utxo=_funded_utxo(h["okey"]),
        privkey=priv,
        merkle_root=real_root,
        epoch=h["epoch"].number,
        leaf_count=real_count + 99,   # LIE
        fee_sats=400,
    )
    r = verify_full(
        signed=h["signed"][0],
        proof=h["proofs"][0],
        checkpoint_event=h["epoch"].checkpoint_event,
        anchor_raw_tx_hex=lying_anchor.raw_hex,
    )
    assert r.ok is False
    assert r.anchor_ok is False


# ---------- CLI exit code (round-3 fix) -----------------------------


def test_cli_verify_exits_1_on_rejected(honest_epoch, tmp_path):
    """Round-3 fix: `veritas verify` used to print REJECTED but exit 0,
    so `veritas verify bad.json && deploy.sh` would proceed."""
    import json as _json
    from click.testing import CliRunner
    from veritas.cli import cli

    h = honest_epoch
    # Write a TAMPERED attestation (sig won't verify).
    att_path = tmp_path / "bad.json"
    body = _json.loads(h["signed"][0].to_json())
    body["attestation"]["output"] = {"label": "tampered"}
    att_path.write_text(_json.dumps(body))

    runner = CliRunner()
    result = runner.invoke(cli, ["verify", str(att_path)])
    assert result.exit_code == 1
    assert "REJECTED" in result.output


def test_cli_verify_exits_0_on_verified(honest_epoch, tmp_path):
    """Honest attestation path — verify should exit 0."""
    from click.testing import CliRunner
    from veritas.cli import cli

    h = honest_epoch
    att_path = tmp_path / "good.json"
    att_path.write_text(h["signed"][0].to_json())

    runner = CliRunner()
    result = runner.invoke(cli, ["verify", str(att_path)])
    assert result.exit_code == 0
    assert "VERIFIED" in result.output


# ---------- broadcaster + LN backend validation (round-3 fixes) -----


def test_lnd_backend_rejects_file_url_scheme():
    """Round-3 fix: env-pollution attack with file:// URL used to
    cause urlopen to read local files."""
    from veritas.lightning import LndRestBackend
    with pytest.raises(ValueError, match="http:// or https://"):
        LndRestBackend(url="file:///etc/passwd", macaroon_hex="aa" * 16)


def test_phoenixd_backend_rejects_file_url_scheme():
    from veritas.lightning import PhoenixdBackend
    with pytest.raises(ValueError, match="http:// or https://"):
        PhoenixdBackend(url="file:///etc/passwd", password="x" * 8)


def test_bitcoind_broadcaster_rejects_file_url_scheme():
    from veritas.broadcast import BitcoindRpcBroadcaster
    with pytest.raises(ValueError, match="http:// or https://"):
        BitcoindRpcBroadcaster(rpc_url="file:///etc/passwd")


def test_lnd_check_paid_rejects_non_hex_payment_hash():
    """Round-3 fix: a malicious payment_hash like 'aaaa/../macaroons'
    used to be interpolated into the URL path with no validation."""
    from veritas.lightning import LndRestBackend
    b = LndRestBackend(url="https://node:8080", macaroon_hex="aa" * 64)
    with pytest.raises(ValueError, match="hex"):
        b.check_paid("aaaa/../macaroons")


def test_mempool_broadcaster_returns_failure_on_non_ascii_raw_hex():
    """Round-3 fix: raw_hex with non-ASCII chars used to raise
    UnicodeEncodeError outside the Broadcaster contract."""
    from veritas.broadcast import MempoolSpaceBroadcaster
    b = MempoolSpaceBroadcaster(network="signet")
    r = b.broadcast("deadbeefÿ")
    assert r.ok is False
    assert "hex" in r.error.lower()


def test_make_broadcaster_refuses_partial_credentials(monkeypatch):
    """Round-3 fix: setting USER without PASS used to silently build
    a no-auth broadcaster."""
    from veritas.broadcast import make_broadcaster
    monkeypatch.setenv("VERITAS_ANCHOR_BROADCAST", "1")
    monkeypatch.setenv("VERITAS_BROADCASTER", "bitcoind")
    monkeypatch.setenv("VERITAS_BTC_RPC_URL", "http://127.0.0.1:18443")
    monkeypatch.setenv("VERITAS_BTC_RPC_USER", "alice")
    monkeypatch.delenv("VERITAS_BTC_RPC_PASS", raising=False)
    with pytest.raises(RuntimeError, match="must be set together"):
        make_broadcaster()


# ---------- server env-var validation (round-3 fix) -----------------


def test_make_ln_backend_rejects_short_lnd_macaroon(monkeypatch):
    """Round-3 fix: a 1-char macaroon used to boot the server and
    then 401 every Lightning request in production."""
    from veritas.server import _make_ln_backend
    monkeypatch.setenv("VERITAS_LN_BACKEND", "lnd")
    monkeypatch.setenv("VERITAS_LND_URL", "https://node:8080")
    monkeypatch.setenv("VERITAS_LND_MACAROON", "x")
    with pytest.raises(RuntimeError, match="at least 32 hex chars"):
        _make_ln_backend()


def test_make_ln_backend_rejects_non_hex_lnd_macaroon(monkeypatch):
    """Macaroon must be hex, not arbitrary text."""
    from veritas.server import _make_ln_backend
    monkeypatch.setenv("VERITAS_LN_BACKEND", "lnd")
    monkeypatch.setenv("VERITAS_LND_URL", "https://node:8080")
    monkeypatch.setenv(
        "VERITAS_LND_MACAROON", "not-hex-but-long-enough-to-pass-length",
    )
    with pytest.raises(RuntimeError, match="hex chars"):
        _make_ln_backend()


# ---------- oracle.py recovery hardening (round-3 fix) --------------


def test_load_from_disk_skips_attestation_with_list_root(tmp_path):
    """Round-3 fix: a tampered atts/*.json whose root is a JSON list
    used to crash _load_from_disk with TypeError on body['signed']."""
    from veritas.crypto import OracleKey
    from veritas.oracle import Oracle, OracleConfig
    import json as _json
    okey = OracleKey.generate()
    # Build the data dir manually.
    data = tmp_path / "data"
    (data / "epoch_00000000" / "atts").mkdir(parents=True)
    # Drop a list-rooted JSON file alongside no real attestations.
    (data / "epoch_00000000" / "atts" / "00000000.json").write_text(
        _json.dumps(["this", "is", "a", "list"])
    )
    # Oracle init must succeed (skipping the bad file), not panic.
    oracle = Oracle(okey, OracleConfig(data_dir=data))
    # Past epochs reconstructed; the open epoch should be epoch 0 with
    # no loaded attestations.
    assert oracle.current.number == 0
    assert oracle.current.attestations == []
