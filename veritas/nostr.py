"""NIP-01 / NIP-33 Nostr event construction.

We use the oracle's BIP-340 key as the Nostr key directly — same curve,
same sig algorithm, same byte format. The event ID is the SHA-256 of
the canonical serialization of [0, pubkey, created_at, kind, tags, content]
per NIP-01.

We deliberately do NOT pull in a Nostr library — there's almost nothing
to it once you have BIP-340, and writing it out keeps the protocol
self-documenting.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .attestation import Attestation, SignedAttestation, canonical_json
from .crypto import OracleKey, schnorr_sign, schnorr_verify


# Event kinds we use.
KIND_VERITAS_ATTESTATION = 30078  # parameterized replaceable
KIND_VERITAS_CHECKPOINT = 30079   # parameterized replaceable, one per epoch


@dataclass
class NostrEvent:
    """Minimal NIP-01 event."""

    pubkey: str           # 64-char hex, x-only
    created_at: int
    kind: int
    tags: list[list[str]] = field(default_factory=list)
    content: str = ""
    id: str = ""          # hex SHA-256 of serialization, 64 chars
    sig: str = ""         # hex Schnorr sig, 128 chars

    def serialize_for_id(self) -> bytes:
        """NIP-01 canonical pre-hash form:
            [0, <pubkey>, <created_at>, <kind>, <tags>, <content>]
        """
        payload = [
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        ]
        return json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def compute_id(self) -> str:
        return hashlib.sha256(self.serialize_for_id()).hexdigest()

    def sign(self, key: OracleKey) -> "NostrEvent":
        if key.xonly_pubkey_hex != self.pubkey:
            raise ValueError("pubkey mismatch with signing key")
        self.id = self.compute_id()
        self.sig = schnorr_sign(bytes.fromhex(self.id), key).hex()
        return self

    def verify(self) -> bool:
        if not self.id or not self.sig:
            return False
        if self.compute_id() != self.id:
            return False
        return schnorr_verify(
            bytes.fromhex(self.id),
            bytes.fromhex(self.sig),
            bytes.fromhex(self.pubkey),
        )

    def to_relay_message(self) -> str:
        """Wire-format message a Nostr relay accepts: ["EVENT", event]."""
        return json.dumps(["EVENT", asdict(self)], separators=(",", ":"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_attestation_event(
    signed: SignedAttestation,
    key: OracleKey,
    index_in_epoch: int,
) -> NostrEvent:
    """Wrap a SignedAttestation as a Nostr event.

    Note: the attestation sig and the Nostr event sig are *both* produced
    by the same oracle key, but they sign different digests. The
    attestation sig commits to the attestation payload independently of
    Nostr wrapping; the Nostr sig commits to the wire-format event id.

    Reason: a verifier should be able to consume the attestation payload
    without trusting any Nostr-related logic.
    """
    att = signed.attestation
    tags = [
        ["d", f"{att.epoch}:{index_in_epoch}"],
        ["model", att.model],
        ["v", f"VRT1.{att.v}"],
        ["epoch", str(att.epoch)],
        ["input", att.input_hash],
    ]
    content = base64.b64encode(canonical_json(
        {"attestation": att.to_payload(), "sig": signed.sig}
    )).decode("ascii")
    evt = NostrEvent(
        pubkey=key.xonly_pubkey_hex,
        created_at=att.ts,
        kind=KIND_VERITAS_ATTESTATION,
        tags=tags,
        content=content,
    )
    return evt.sign(key)


def decode_attestation_event(evt: NostrEvent) -> SignedAttestation:
    """Reverse build_attestation_event — extract the SignedAttestation.

    Contract: this decodes only; it does NOT verify either signature.
    Callers needing authenticity MUST call ``.verify()`` on the returned
    SignedAttestation (and ``evt.verify()`` separately if they also rely on
    the Nostr wrapper's authorship claim). This matches vrt1-kwh's
    ``decode_measurement_event``; vrt1-agents' ``decode_action_event``
    deliberately verifies by default instead — choose per call site.
    """
    raw = base64.b64decode(evt.content)
    return SignedAttestation.from_json(raw)


def build_checkpoint_event(
    *,
    key: OracleKey,
    epoch: int,
    merkle_root_hex: str,
    leaf_count: int,
    anchor_txid: str | None,
    ts: int | None = None,
) -> NostrEvent:
    """Periodic 'this is the Merkle root I'm anchoring' event."""
    payload = {
        "epoch": epoch,
        "root": merkle_root_hex,
        "count": leaf_count,
        "anchor_txid": anchor_txid,
    }
    tags = [
        ["d", f"checkpoint:{epoch}"],
        ["v", "VRT1.1"],
        ["root", merkle_root_hex],
    ]
    if anchor_txid:
        tags.append(["anchor", anchor_txid])
    evt = NostrEvent(
        pubkey=key.xonly_pubkey_hex,
        created_at=int(ts if ts is not None else time.time()),
        kind=KIND_VERITAS_CHECKPOINT,
        tags=tags,
        content=canonical_json(payload).decode("utf-8"),
    )
    return evt.sign(key)
