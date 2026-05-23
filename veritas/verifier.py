"""End-to-end verifier.

Given a SignedAttestation and (optionally) a checkpoint + inclusion
proof, run every check independently and report which passed.

This module deliberately has no network logic — fetching the artifacts
is the client's job. Pure verification only.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attestation import SignedAttestation, attestation_digest
from .crypto import schnorr_verify
from .merkle import MerkleProof, verify_merkle_proof
from .nostr import NostrEvent


@dataclass
class VerificationResult:
    ok: bool
    schnorr_ok: bool
    nostr_event_ok: bool | None       # None if no event provided
    merkle_ok: bool | None            # None if no proof provided
    checkpoint_ok: bool | None        # None if no checkpoint provided
    notes: list[str]


def verify_full(
    *,
    signed: SignedAttestation,
    nostr_event: NostrEvent | None = None,
    proof: MerkleProof | None = None,
    checkpoint_event: NostrEvent | None = None,
    checkpoint_root_hex: str | None = None,
) -> VerificationResult:
    notes: list[str] = []

    # 1. Attestation signature.
    schnorr_ok = signed.verify()
    if not schnorr_ok:
        notes.append("attestation Schnorr signature INVALID")

    # 2. Optional: Nostr event ID + signature.
    nostr_event_ok: bool | None = None
    if nostr_event is not None:
        nostr_event_ok = nostr_event.verify()
        if not nostr_event_ok:
            notes.append("Nostr event signature INVALID")
        if nostr_event.pubkey != signed.attestation.oracle:
            notes.append("Nostr event pubkey does not match attestation.oracle")
            nostr_event_ok = False

    # 3. Optional: Merkle inclusion proof.
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

    # 4. Optional: checkpoint event commits to the same root.
    checkpoint_ok: bool | None = None
    if checkpoint_event is not None:
        if not checkpoint_event.verify():
            notes.append("Checkpoint Schnorr signature INVALID")
            checkpoint_ok = False
        elif checkpoint_event.pubkey != signed.attestation.oracle:
            notes.append("Checkpoint pubkey != attestation.oracle")
            checkpoint_ok = False
        else:
            checkpoint_ok = True
        if proof is not None and checkpoint_root_hex is not None:
            if proof.root.hex() != checkpoint_root_hex:
                notes.append("Merkle proof root != checkpoint root")
                checkpoint_ok = False

    ok = (
        schnorr_ok
        and (nostr_event_ok is not False)
        and (merkle_ok is not False)
        and (checkpoint_ok is not False)
    )
    return VerificationResult(
        ok=ok,
        schnorr_ok=schnorr_ok,
        nostr_event_ok=nostr_event_ok,
        merkle_ok=merkle_ok,
        checkpoint_ok=checkpoint_ok,
        notes=notes,
    )
