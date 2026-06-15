"""VERITAS — Verifiable, Economically-Recoverable, Inference-Time Attestation System.

Bitcoin-anchored oracle network for AI inference attestations.
"""

__version__ = "0.1.0"
PROTOCOL_TAG = "VRT1"

from .crypto import (
    OracleKey,
    schnorr_sign,
    schnorr_verify,
    tagged_hash,
    sha256d,
)
from .attestation import Attestation, attestation_digest
from .merkle import MerkleTree, MerkleProof, verify_merkle_proof
from .nostr import NostrEvent, build_attestation_event, build_checkpoint_event
from .anchor import build_anchor_tx, AnchorTx
from .models import normalize_input
from .verifier import VerificationResult, verify_full, verify_reveal

__all__ = [
    "__version__",
    "PROTOCOL_TAG",
    "OracleKey",
    "schnorr_sign",
    "schnorr_verify",
    "tagged_hash",
    "sha256d",
    "Attestation",
    "attestation_digest",
    "MerkleTree",
    "MerkleProof",
    "verify_merkle_proof",
    "NostrEvent",
    "build_attestation_event",
    "build_checkpoint_event",
    "build_anchor_tx",
    "AnchorTx",
    "VerificationResult",
    "verify_full",
    "verify_reveal",
    "normalize_input",
]
