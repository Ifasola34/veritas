"""End-to-end verifier.

Given a SignedAttestation and (optionally) a checkpoint Nostr event,
an inclusion proof, and the raw on-chain anchor tx hex, run every
check independently and report which passed.

This module deliberately has no network logic — fetching the artifacts
is the client's job. Pure verification only.

The verifier binds artifacts together at every boundary:
  - attestation Schnorr signature
  - Nostr event id + signature + pubkey == attestation.oracle
  - Merkle proof leaf == attestation digest, proof verifies under
    its own root + leaf count
  - checkpoint event Schnorr signature, pubkey, and SIGNED CONTENT
    epoch + root + leaf_count (we parse the signed JSON, never trust
    a caller-supplied "checkpoint_root_hex" in isolation)
  - if the raw anchor tx hex is supplied, the on-chain OP_RETURN's
    epoch + leaf_count + root must match the signed checkpoint
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .anchor import extract_op_return_from_raw_tx, parse_op_return_payload
from .attestation import SignedAttestation, attestation_digest
from .merkle import MerkleProof, verify_merkle_proof
from .nostr import NostrEvent


@dataclass
class VerificationResult:
    ok: bool
    schnorr_ok: bool
    nostr_event_ok: bool | None       # None if no event provided
    merkle_ok: bool | None            # None if no proof provided
    checkpoint_ok: bool | None        # None if no checkpoint provided
    anchor_ok: bool | None            # None if no anchor tx provided
    notes: list[str]


def _parse_checkpoint_content(evt: NostrEvent) -> dict | None:
    """Pull {epoch, root, count, anchor_txid} out of a signed checkpoint
    event's content. Returns None if the content isn't a recognized
    checkpoint payload.
    """
    try:
        d = json.loads(evt.content)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(d, dict):
        return None
    if "epoch" not in d or "root" not in d:
        return None
    return d


def verify_full(
    *,
    signed: SignedAttestation,
    nostr_event: NostrEvent | None = None,
    proof: MerkleProof | None = None,
    checkpoint_event: NostrEvent | None = None,
    anchor_raw_tx_hex: str | None = None,
) -> VerificationResult:
    notes: list[str] = []

    # 1. Attestation signature.
    schnorr_ok = signed.verify()
    if not schnorr_ok:
        notes.append("attestation Schnorr signature INVALID")

    # 2. Optional: Nostr event id + signature + pubkey binding.
    nostr_event_ok: bool | None = None
    if nostr_event is not None:
        nostr_event_ok = nostr_event.verify()
        if not nostr_event_ok:
            notes.append("Nostr event signature INVALID")
        if nostr_event.pubkey != signed.attestation.oracle:
            notes.append("Nostr event pubkey does not match attestation.oracle")
            nostr_event_ok = False

    # 3. Optional: Merkle inclusion proof bound to the attestation digest.
    merkle_ok: bool | None = None
    if proof is not None:
        digest = attestation_digest(signed.attestation)
        if proof.leaf != digest:
            notes.append("Merkle proof leaf does not match attestation digest")
            merkle_ok = False
        else:
            merkle_ok = verify_merkle_proof(proof)
            if not merkle_ok:
                notes.append("Merkle inclusion proof INVALID")

    # 4. Optional: checkpoint event binds the proof root + epoch + leaf count.
    # If a checkpoint is supplied without a proof, we CANNOT bind the
    # attestation digest to the checkpoint's root — supplying a checkpoint
    # is therefore a request that the verifier confirm the binding, and
    # without a proof that confirmation is impossible. Fail closed.
    checkpoint_ok: bool | None = None
    checkpoint_payload: dict | None = None
    if checkpoint_event is not None:
        checkpoint_ok = True
        if proof is None:
            notes.append(
                "Checkpoint supplied without inclusion proof; cannot bind "
                "attestation digest to the checkpoint's Merkle root"
            )
            checkpoint_ok = False
        if not checkpoint_event.verify():
            notes.append("Checkpoint Schnorr signature INVALID")
            checkpoint_ok = False
        if checkpoint_event.pubkey != signed.attestation.oracle:
            notes.append("Checkpoint pubkey != attestation.oracle")
            checkpoint_ok = False
        checkpoint_payload = _parse_checkpoint_content(checkpoint_event)
        if checkpoint_payload is None:
            notes.append("Checkpoint event content is not a valid checkpoint payload")
            checkpoint_ok = False
        else:
            # Bind checkpoint to attestation by epoch.
            if int(checkpoint_payload["epoch"]) != int(signed.attestation.epoch):
                notes.append(
                    f"Checkpoint epoch {checkpoint_payload['epoch']} != "
                    f"attestation epoch {signed.attestation.epoch}"
                )
                checkpoint_ok = False
            # Bind checkpoint to Merkle proof by root + leaf_count.
            if proof is not None:
                if proof.root.hex() != checkpoint_payload["root"]:
                    notes.append("Merkle proof root != checkpoint signed root")
                    checkpoint_ok = False
                if "count" in checkpoint_payload and (
                    int(checkpoint_payload["count"]) != int(proof.size)
                ):
                    notes.append("Merkle proof size != checkpoint leaf count")
                    checkpoint_ok = False

    # 5. Optional: cross-check the on-chain OP_RETURN against the checkpoint.
    # Same binding requirement as checkpoint: without a proof, the OP_RETURN
    # root cannot be tied to the attestation digest. Fail closed.
    anchor_ok: bool | None = None
    if anchor_raw_tx_hex is not None:
        anchor_ok = True
        if proof is None:
            notes.append(
                "Anchor tx supplied without inclusion proof; cannot bind "
                "attestation digest to the on-chain Merkle root"
            )
            anchor_ok = False
        payload: bytes | None
        try:
            payload = extract_op_return_from_raw_tx(anchor_raw_tx_hex)
        except (ValueError, IndexError) as e:
            payload = None
            notes.append(f"Anchor tx parsing failed: {e}")
            anchor_ok = False
        if payload is None and anchor_ok is not False:
            notes.append("Anchor tx has no OP_RETURN output")
            anchor_ok = False
        if payload is not None:
            try:
                parsed = parse_op_return_payload(payload)
            except ValueError as e:
                notes.append(f"OP_RETURN payload malformed: {e}")
                anchor_ok = False
                parsed = None
            if parsed is not None:
                # Must match attestation epoch.
                if parsed["epoch"] != int(signed.attestation.epoch):
                    notes.append(
                        f"Anchor OP_RETURN epoch {parsed['epoch']} != "
                        f"attestation epoch {signed.attestation.epoch}"
                    )
                    anchor_ok = False
                # Must match Merkle proof root + size, if supplied.
                if proof is not None:
                    if parsed["merkle_root"] != proof.root:
                        notes.append("Anchor OP_RETURN root != Merkle proof root")
                        anchor_ok = False
                    if parsed["leaf_count"] != proof.size:
                        notes.append("Anchor OP_RETURN leaf_count != Merkle proof size")
                        anchor_ok = False
                # Must match checkpoint, if supplied.
                if checkpoint_payload is not None:
                    if parsed["merkle_root"].hex() != checkpoint_payload["root"]:
                        notes.append("Anchor OP_RETURN root != checkpoint signed root")
                        anchor_ok = False
                    if "count" in checkpoint_payload and (
                        parsed["leaf_count"] != int(checkpoint_payload["count"])
                    ):
                        notes.append(
                            "Anchor OP_RETURN leaf_count != checkpoint count"
                        )
                        anchor_ok = False

    ok = (
        schnorr_ok
        and (nostr_event_ok is not False)
        and (merkle_ok is not False)
        and (checkpoint_ok is not False)
        and (anchor_ok is not False)
    )
    return VerificationResult(
        ok=ok,
        schnorr_ok=schnorr_ok,
        nostr_event_ok=nostr_event_ok,
        merkle_ok=merkle_ok,
        checkpoint_ok=checkpoint_ok,
        anchor_ok=anchor_ok,
        notes=notes,
    )
