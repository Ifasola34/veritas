"""Bitcoin-style Merkle tree.

Same construction Bitcoin block headers use: double-SHA-256 internal
nodes, odd-leaf duplication. We use the *same* construction so that a
verifier already comfortable with Bitcoin Merkle proofs needs no
additional spec to verify VERITAS proofs.

Leaves are arbitrary 32-byte digests. We do NOT pre-hash leaves
(callers pass already-domain-separated digests like attestation
digests). This keeps the tree primitive composable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .crypto import sha256d


@dataclass(frozen=True)
class MerkleProof:
    leaf: bytes              # 32 bytes
    siblings: list[bytes]    # 32-byte each, from leaf level up
    directions: list[int]    # 0 = sibling on right, 1 = sibling on left
    root: bytes              # claimed root, 32 bytes


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return sha256d(left + right)


class MerkleTree:
    """Builds and serves inclusion proofs for an immutable batch."""

    def __init__(self, leaves: Iterable[bytes]) -> None:
        self.leaves: list[bytes] = [bytes(l) for l in leaves]
        if not self.leaves:
            raise ValueError("Merkle tree needs at least one leaf")
        for l in self.leaves:
            if len(l) != 32:
                raise ValueError("each leaf must be 32 bytes")
        self.levels: list[list[bytes]] = [list(self.leaves)]
        cur = self.levels[0]
        while len(cur) > 1:
            if len(cur) % 2 == 1:
                cur = cur + [cur[-1]]  # duplicate last (Bitcoin convention)
            nxt = [_hash_pair(cur[i], cur[i + 1]) for i in range(0, len(cur), 2)]
            self.levels.append(nxt)
            cur = nxt
        self.root: bytes = self.levels[-1][0]

    def prove(self, index: int) -> MerkleProof:
        if not 0 <= index < len(self.leaves):
            raise IndexError(index)
        siblings: list[bytes] = []
        directions: list[int] = []
        idx = index
        for level in self.levels[:-1]:
            level_padded = level if len(level) % 2 == 0 else level + [level[-1]]
            if idx % 2 == 0:
                # we're the left node; sibling is on our right (direction=0)
                sib = level_padded[idx + 1]
                directions.append(0)
            else:
                # we're the right node; sibling is on our left (direction=1)
                sib = level_padded[idx - 1]
                directions.append(1)
            siblings.append(sib)
            idx //= 2
        return MerkleProof(
            leaf=self.leaves[index],
            siblings=siblings,
            directions=directions,
            root=self.root,
        )


def verify_merkle_proof(proof: MerkleProof) -> bool:
    """Pure verifier: recompute root from leaf+path, compare."""
    cur = proof.leaf
    if len(cur) != 32:
        return False
    if len(proof.siblings) != len(proof.directions):
        return False
    for sib, direction in zip(proof.siblings, proof.directions):
        if len(sib) != 32:
            return False
        if direction == 0:
            cur = _hash_pair(cur, sib)
        elif direction == 1:
            cur = _hash_pair(sib, cur)
        else:
            return False
    return cur == proof.root
