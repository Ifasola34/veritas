"""Attestation object — what the oracle signs."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .crypto import OracleKey, schnorr_sign, schnorr_verify, tagged_hash


ATTESTATION_TAG = "VRT1/attestation"


def canonical_json(obj: Any) -> bytes:
    """Canonical JSON serialization.

    Identical bytes for identical content — sorted keys, minimal separators,
    UTF-8 with no ASCII-escaping. This is what we hash and what we sign.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass
class Attestation:
    """One AI inference output, signable and verifiable.

    Field order is irrelevant to the wire format — we canonicalize before
    hashing. The dataclass is for ergonomics in Python code.
    """

    model: str             # stable model id, e.g. "veritas.sentiment.v1"
    input_hash: str        # hex SHA-256 of normalized input
    output: Any            # arbitrary JSON-serializable inference result
    ts: int                # unix seconds when produced
    epoch: int             # batching epoch number
    oracle: str            # 32-byte x-only pubkey, hex
    v: int = 1             # protocol version
    nonce: str = ""        # optional random nonce for unlinkability

    def to_payload(self) -> dict[str, Any]:
        d = asdict(self)
        if not d["nonce"]:
            d.pop("nonce")
        return d

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_payload())


def attestation_digest(att: Attestation) -> bytes:
    """The 32-byte message that gets BIP-340-signed."""
    return tagged_hash(ATTESTATION_TAG, att.canonical_bytes())


@dataclass
class SignedAttestation:
    attestation: Attestation
    sig: str  # 64-byte schnorr sig, hex

    def verify(self) -> bool:
        msg = attestation_digest(self.attestation)
        try:
            sig = bytes.fromhex(self.sig)
            pk = bytes.fromhex(self.attestation.oracle)
        except ValueError:
            # Malformed (non-hex) sig or pubkey is a failed verification,
            # not an exception to surface to the caller. Matches the
            # behaviour of SignedMeasurement / SignedAction.verify().
            return False
        return schnorr_verify(msg, sig, pk)

    def to_json(self) -> str:
        return json.dumps(
            {"attestation": self.attestation.to_payload(), "sig": self.sig},
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> "SignedAttestation":
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        d = json.loads(raw)
        att_d = d["attestation"]
        att = Attestation(
            model=att_d["model"],
            input_hash=att_d["input_hash"],
            output=att_d["output"],
            ts=att_d["ts"],
            epoch=att_d["epoch"],
            oracle=att_d["oracle"],
            v=att_d.get("v", 1),
            nonce=att_d.get("nonce", ""),
        )
        return cls(attestation=att, sig=d["sig"])


def sign_attestation(att: Attestation, key: OracleKey) -> SignedAttestation:
    """Convenience: produce a signed attestation from a key.

    The attestation's `oracle` field MUST already match the key's x-only
    pubkey — we enforce this rather than silently overwriting.
    """
    if att.oracle != key.xonly_pubkey_hex:
        raise ValueError(
            f"attestation.oracle does not match key "
            f"(att={att.oracle[:8]}…, key={key.xonly_pubkey_hex[:8]}…)"
        )
    sig = schnorr_sign(attestation_digest(att), key)
    return SignedAttestation(attestation=att, sig=sig.hex())


def make_attestation(
    *,
    model: str,
    input_hash: str,
    output: Any,
    epoch: int,
    oracle_pubkey_hex: str,
    ts: int | None = None,
    nonce: str = "",
) -> Attestation:
    return Attestation(
        model=model,
        input_hash=input_hash,
        output=output,
        ts=int(ts if ts is not None else time.time()),
        epoch=epoch,
        oracle=oracle_pubkey_hex,
        nonce=nonce,
    )
