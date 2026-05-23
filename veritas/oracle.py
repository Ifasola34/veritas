"""Oracle daemon — the long-running attestation producer.

State lives in a single SQLite-free, file-backed store under the supplied
data dir. (Skipping SQLite keeps the dependency surface tiny; the volumes
involved in a prototype are small.)

Per-epoch lifecycle:
  1. Inferences arrive (either from the HTTP endpoint or scheduled jobs).
  2. Each produces a signed attestation, written to `<data>/epoch_<n>/atts/`.
  3. A Nostr-format event is built for each attestation.
  4. When the epoch closes:
        - Build Merkle tree from all attestation digests.
        - Construct OP_RETURN payload + (optional) anchor tx hex.
        - Sign + emit a checkpoint Nostr event.
        - Roll over to next epoch.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .anchor import Utxo, build_anchor_tx, AnchorTx
from .attestation import (
    Attestation,
    SignedAttestation,
    attestation_digest,
    make_attestation,
    sign_attestation,
)
from .crypto import OracleKey, derive_anchor_key
from .merkle import MerkleProof, MerkleTree
from .models import REGISTRY, normalize_input, OracleModel
from .nostr import (
    NostrEvent,
    build_attestation_event,
    build_checkpoint_event,
)


@dataclass
class Epoch:
    number: int
    started_at: int
    attestations: list[SignedAttestation] = field(default_factory=list)
    events: list[NostrEvent] = field(default_factory=list)
    closed: bool = False
    root_hex: str | None = None
    checkpoint_event: NostrEvent | None = None
    anchor_tx: AnchorTx | None = None


@dataclass
class OracleConfig:
    data_dir: Path
    epoch_seconds: int = 600
    anchor_utxo: Utxo | None = None   # if None, anchor tx is skipped
    fee_sats: int = 500


class Oracle:
    def __init__(self, key: OracleKey, config: OracleConfig) -> None:
        self.key = key
        self.config = config
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.models: dict[str, OracleModel] = dict(REGISTRY)
        self.current = Epoch(number=0, started_at=int(time.time()))
        self.past: list[Epoch] = []
        self._lock = threading.RLock()

    # -- public API ----------------------------------------------------

    @property
    def pubkey_hex(self) -> str:
        return self.key.xonly_pubkey_hex

    def list_models(self) -> list[str]:
        return sorted(self.models.keys())

    def attest(self, model_id: str, input_text: str) -> tuple[SignedAttestation, NostrEvent]:
        if model_id not in self.models:
            raise KeyError(f"unknown model: {model_id}")
        norm, input_hash = normalize_input(input_text)
        output = self.models[model_id].infer(norm)
        with self._lock:
            self._maybe_roll_epoch()
            att = make_attestation(
                model=model_id,
                input_hash=input_hash,
                output=output,
                epoch=self.current.number,
                oracle_pubkey_hex=self.pubkey_hex,
            )
            signed = sign_attestation(att, self.key)
            idx = len(self.current.attestations)
            evt = build_attestation_event(signed, self.key, index_in_epoch=idx)
            self.current.attestations.append(signed)
            self.current.events.append(evt)
            self._persist_attestation(self.current.number, idx, signed, evt)
        return signed, evt

    def close_epoch(self) -> Epoch:
        with self._lock:
            return self._close_locked()

    def get_epoch(self, n: int) -> Epoch | None:
        if self.current.number == n:
            return self.current
        for e in self.past:
            if e.number == n:
                return e
        return None

    def inclusion_proof(self, epoch_n: int, index: int) -> MerkleProof | None:
        epoch = self.get_epoch(epoch_n)
        if epoch is None or not epoch.closed:
            return None
        digests = [
            attestation_digest(sa.attestation) for sa in epoch.attestations
        ]
        return MerkleTree(digests).prove(index)

    # -- internal ------------------------------------------------------

    def _maybe_roll_epoch(self) -> None:
        now = int(time.time())
        if now - self.current.started_at >= self.config.epoch_seconds:
            self._close_locked()

    def _close_locked(self) -> Epoch:
        if self.current.closed:
            return self.current
        if not self.current.attestations:
            # Empty epoch — just advance.
            self.current.closed = True
            old = self.current
            self.past.append(old)
            self.current = Epoch(
                number=old.number + 1, started_at=int(time.time())
            )
            return old

        digests = [
            attestation_digest(sa.attestation) for sa in self.current.attestations
        ]
        tree = MerkleTree(digests)
        self.current.root_hex = tree.root.hex()

        anchor_txid: str | None = None
        if self.config.anchor_utxo is not None:
            anchor_priv = derive_anchor_key(self.key)
            tx = build_anchor_tx(
                utxo=self.config.anchor_utxo,
                privkey=anchor_priv,
                merkle_root=tree.root,
                epoch=self.current.number,
                fee_sats=self.config.fee_sats,
            )
            self.current.anchor_tx = tx
            anchor_txid = tx.txid

        cp = build_checkpoint_event(
            key=self.key,
            epoch=self.current.number,
            merkle_root_hex=tree.root.hex(),
            leaf_count=len(digests),
            anchor_txid=anchor_txid,
        )
        self.current.checkpoint_event = cp
        self.current.closed = True
        self._persist_checkpoint(self.current)

        old = self.current
        self.past.append(old)
        self.current = Epoch(number=old.number + 1, started_at=int(time.time()))
        return old

    # -- persistence (file-backed, simple) ------------------------------

    def _epoch_dir(self, n: int) -> Path:
        d = self.config.data_dir / f"epoch_{n:08d}"
        (d / "atts").mkdir(parents=True, exist_ok=True)
        return d

    def _persist_attestation(
        self, epoch_n: int, idx: int, signed: SignedAttestation, evt: NostrEvent
    ) -> None:
        d = self._epoch_dir(epoch_n)
        (d / "atts" / f"{idx:08d}.json").write_text(
            json.dumps(
                {
                    "signed": json.loads(signed.to_json()),
                    "nostr": evt.to_dict(),
                },
                indent=2,
            )
        )

    def _persist_checkpoint(self, epoch: Epoch) -> None:
        d = self._epoch_dir(epoch.number)
        payload: dict[str, Any] = {
            "epoch": epoch.number,
            "root": epoch.root_hex,
            "leaf_count": len(epoch.attestations),
            "closed_at": int(time.time()),
            "checkpoint_event": (
                epoch.checkpoint_event.to_dict() if epoch.checkpoint_event else None
            ),
            "anchor": (
                {
                    "txid": epoch.anchor_tx.txid,
                    "raw_hex": epoch.anchor_tx.raw_hex,
                    "fee_sats": epoch.anchor_tx.fee_sats,
                    "op_return_payload_hex": epoch.anchor_tx.op_return_payload.hex(),
                }
                if epoch.anchor_tx
                else None
            ),
        }
        (d / "checkpoint.json").write_text(json.dumps(payload, indent=2))
