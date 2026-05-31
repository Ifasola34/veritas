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

from .anchor import Utxo, build_anchor_tx, derive_anchor_pubkey, AnchorTx
from .broadcast import Broadcaster, NullBroadcaster, BroadcastResult
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
    broadcast_result: BroadcastResult | None = None
    # Lazily-built Merkle tree, cached for inclusion_proof. A closed epoch is
    # immutable, so the tree is built once and reused rather than rebuilt on
    # every proof request. Excluded from compare/repr so it doesn't affect
    # Epoch equality or debugging output.
    tree: MerkleTree | None = field(default=None, compare=False, repr=False)


@dataclass
class OracleConfig:
    data_dir: Path
    epoch_seconds: int = 600
    anchor_utxo: Utxo | None = None   # if None, anchor tx is skipped
    fee_sats: int = 500
    broadcaster: Broadcaster | None = None  # NullBroadcaster if None


class Oracle:
    def __init__(self, key: OracleKey, config: OracleConfig) -> None:
        self.key = key
        self.config = config
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.models: dict[str, OracleModel] = dict(REGISTRY)
        self._lock = threading.RLock()
        if config.anchor_utxo is not None:
            anchor_pk = derive_anchor_pubkey(derive_anchor_key(key))
            if config.anchor_utxo.pubkey_compressed != anchor_pk:
                raise ValueError(
                    "anchor_utxo.pubkey_compressed does not match the "
                    "derived anchor pubkey for this oracle key; "
                    "anchor txs would be unspendable"
                )
        self.past, self.current = self._load_from_disk()

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
        with self._lock:
            epoch = self.get_epoch(epoch_n)
            if epoch is None or not epoch.closed:
                return None
            if not 0 <= index < len(epoch.attestations):
                return None
            # Build the tree once per closed epoch and cache it. Without this,
            # proving N leaves rebuilt the entire tree N times — O(N^2)
            # hashing on the verifier-facing read path.
            if epoch.tree is None:
                digests = [
                    attestation_digest(sa.attestation)
                    for sa in epoch.attestations
                ]
                epoch.tree = MerkleTree(digests)
            return epoch.tree.prove(index)

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
                leaf_count=len(digests),
                fee_sats=self.config.fee_sats,
            )
            self.current.anchor_tx = tx
            anchor_txid = tx.txid
            # Optional broadcast. NullBroadcaster (the default) returns
            # ok=True with no txid so the rest of the close path is
            # unchanged. A failing real broadcast does NOT roll back the
            # epoch — the tx hex is already in checkpoint.json and the
            # operator can rebroadcast manually.
            broadcaster = self.config.broadcaster or NullBroadcaster()
            self.current.broadcast_result = broadcaster.broadcast(tx.raw_hex)

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

    # -- persistence (file-backed, atomic) ------------------------------

    def _epoch_dir(self, n: int) -> Path:
        d = self.config.data_dir / f"epoch_{n:08d}"
        (d / "atts").mkdir(parents=True, exist_ok=True)
        return d

    @staticmethod
    def _atomic_write(path: Path, data: str) -> None:
        """Write to a tmp file in the same dir, fsync, then os.replace.

        Prevents torn files on crash/OOM/SIGKILL mid-write.
        """
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _persist_attestation(
        self, epoch_n: int, idx: int, signed: SignedAttestation, evt: NostrEvent
    ) -> None:
        d = self._epoch_dir(epoch_n)
        body = json.dumps(
            {
                "signed": json.loads(signed.to_json()),
                "nostr": evt.to_dict(),
            },
            indent=2,
        )
        self._atomic_write(d / "atts" / f"{idx:08d}.json", body)

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
            "broadcast": (
                {
                    "ok": epoch.broadcast_result.ok,
                    "txid": epoch.broadcast_result.txid,
                    "error": epoch.broadcast_result.error,
                    "backend": epoch.broadcast_result.backend,
                }
                if epoch.broadcast_result
                else None
            ),
        }
        self._atomic_write(d / "checkpoint.json", json.dumps(payload, indent=2))

    # -- recovery -------------------------------------------------------

    def _load_from_disk(self) -> tuple[list[Epoch], Epoch]:
        """Rebuild epoch state from data_dir at startup so successive CLI
        invocations and server restarts resume rather than collide on
        epoch_00000000/atts/ filenames.

        Returns (past_closed_epochs, current_open_epoch).
        """
        from .nostr import NostrEvent  # local import to avoid cycle at module load

        past: list[Epoch] = []
        open_epoch: Epoch | None = None
        if not self.config.data_dir.exists():
            return past, Epoch(number=0, started_at=int(time.time()))

        dirs = sorted(
            p for p in self.config.data_dir.iterdir()
            if p.is_dir() and p.name.startswith("epoch_")
        )
        for ed in dirs:
            try:
                n = int(ed.name.split("_", 1)[1])
            except ValueError:
                continue
            atts_dir = ed / "atts"
            attestations: list[SignedAttestation] = []
            events: list[NostrEvent] = []
            if atts_dir.is_dir():
                for af in sorted(atts_dir.glob("*.json")):
                    try:
                        body = json.loads(af.read_text())
                    except (json.JSONDecodeError, OSError):
                        continue  # skip torn/missing files
                    # A top-level JSON list (e.g. `[]`) or anything other
                    # than a dict would raise TypeError on `body["signed"]`
                    # below. Treat as a torn file and skip rather than
                    # panicking the daemon at startup.
                    if not isinstance(body, dict):
                        continue
                    try:
                        sa = SignedAttestation.from_json(
                            json.dumps(body["signed"])
                        )
                        evt_d = body["nostr"]
                        if not isinstance(evt_d, dict):
                            continue
                        evt = NostrEvent(
                            pubkey=evt_d["pubkey"],
                            created_at=evt_d["created_at"],
                            kind=evt_d["kind"],
                            tags=evt_d.get("tags", []),
                            content=evt_d.get("content", ""),
                            id=evt_d.get("id", ""),
                            sig=evt_d.get("sig", ""),
                        )
                    except (KeyError, ValueError, TypeError):
                        continue
                    attestations.append(sa)
                    events.append(evt)

            cp_path = ed / "checkpoint.json"
            closed = cp_path.exists()
            root_hex: str | None = None
            checkpoint_event: NostrEvent | None = None
            anchor_tx = None
            started_at = int(time.time())
            expected_leaf_count: int | None = None
            if closed:
                try:
                    cp = json.loads(cp_path.read_text())
                    # Same defensive check as the atts loader: a tampered
                    # checkpoint.json that's a top-level list crashes the
                    # `cp.get(...)` calls with AttributeError. Treat as
                    # torn and re-open the epoch rather than panicking.
                    if not isinstance(cp, dict):
                        raise ValueError("checkpoint.json root is not a dict")
                    root_hex = cp.get("root")
                    started_at = int(cp.get("closed_at", started_at))
                    expected_leaf_count = cp.get("leaf_count")
                    if cp.get("checkpoint_event"):
                        ce = cp["checkpoint_event"]
                        if not isinstance(ce, dict):
                            raise ValueError("checkpoint_event field is not a dict")
                        checkpoint_event = NostrEvent(
                            pubkey=ce["pubkey"],
                            created_at=ce["created_at"],
                            kind=ce["kind"],
                            tags=ce.get("tags", []),
                            content=ce.get("content", ""),
                            id=ce.get("id", ""),
                            sig=ce.get("sig", ""),
                        )
                    if cp.get("anchor"):
                        a = cp["anchor"]
                        if not isinstance(a, dict):
                            raise ValueError("anchor field is not a dict")
                        anchor_tx = AnchorTx(
                            txid=a["txid"],
                            raw_hex=a["raw_hex"],
                            op_return_payload=bytes.fromhex(a["op_return_payload_hex"]),
                            fee_sats=int(a["fee_sats"]),
                        )
                    if cp.get("broadcast"):
                        b = cp["broadcast"]
                        if not isinstance(b, dict):
                            raise ValueError("broadcast field is not a dict")
                        loaded_broadcast = BroadcastResult(
                            ok=bool(b.get("ok")),
                            txid=b.get("txid"),
                            error=b.get("error"),
                            backend=b.get("backend", "unknown"),
                        )
                    else:
                        loaded_broadcast = None
                except (
                    json.JSONDecodeError, KeyError, ValueError, TypeError,
                    AttributeError, OSError,
                ):
                    closed = False  # treat torn checkpoint as still-open
                    loaded_broadcast = None
            else:
                loaded_broadcast = None

            # Refuse to serve a closed epoch whose on-disk attestation count
            # disagrees with the signed checkpoint leaf_count — otherwise
            # inclusion_proof would silently rebuild a Merkle tree from a
            # truncated leaf set whose root differs from what's anchored.
            if (
                closed
                and expected_leaf_count is not None
                and expected_leaf_count != len(attestations)
            ):
                raise RuntimeError(
                    f"epoch {n} on disk has {len(attestations)} attestations "
                    f"but checkpoint signed for {expected_leaf_count}; "
                    "refusing to load. Inspect "
                    f"{atts_dir}/ and either restore missing files or "
                    "rewrite the checkpoint."
                )

            ep = Epoch(
                number=n,
                started_at=started_at,
                attestations=attestations,
                events=events,
                closed=closed,
                root_hex=root_hex,
                checkpoint_event=checkpoint_event,
                anchor_tx=anchor_tx,
                broadcast_result=loaded_broadcast,
            )
            if closed:
                past.append(ep)
            else:
                open_epoch = ep

        if open_epoch is not None:
            return past, open_epoch
        next_n = (past[-1].number + 1) if past else 0
        return past, Epoch(number=next_n, started_at=int(time.time()))
