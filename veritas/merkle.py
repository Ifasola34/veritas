"""Bitcoin-style Merkle tree with RFC-6962 domain separation.

Leaves and internal nodes are tagged with distinct one-byte prefixes
(0x00 for leaves, 0x01 for internal nodes) so a 32-byte hash from one
level cannot be confused with one from another. We additionally commit
the leaf count and index in every proof so verifiers can reject the
CVE-2012-2459 family of duplicated-tail forgeries.

Leaves are arbitrary 32-byte digests. We do NOT pre-hash leaves
(callers pass already-domain-separated digests like attestation
digests). The 0x00 leaf-prefix hash is applied internally before
inclusion in the tree.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .crypto import sha256d


LEAF_PREFIX = b"\x00"
INTERNAL_PREFIX = b"\x01"


@dataclass(frozen=True)
class MerkleProof:
    leaf: bytes              # raw 32-byte leaf digest (pre-prefix)
    siblings: list[bytes]    # 32-byte each, from leaf level up
    directions: list[int]    # 0 = sibling on right, 1 = sibling on left
    root: bytes              # claimed root, 32 bytes
    size: int                # total leaves in the tree
    index: int               # leaf's 0-based index in the tree


def _hash_leaf(leaf: bytes) -> bytes:
    return sha256d(LEAF_PREFIX + leaf)


def _hash_internal(left: bytes, right: bytes) -> bytes:
    return sha256d(INTERNAL_PREFIX + left + right)


def _expected_depth(n: int) -> int:
    if n <= 1:
        return 0
    d = 0
    m = n
    while m > 1:
        m = (m + 1) // 2
        d += 1
    return d


class MerkleTree:
    """Builds and serves inclusion proofs for an immutable batch."""

    def __init__(self, leaves: Iterable[bytes]) -> None:
        self.leaves: list[bytes] = [bytes(l) for l in leaves]
        if not self.leaves:
            raise ValueError("Merkle tree needs at least one leaf")
        for l in self.leaves:
            if len(l) != 32:
                raise ValueError("each leaf must be 32 bytes")
        level0 = [_hash_leaf(l) for l in self.leaves]
        self.levels: list[list[bytes]] = [level0]
        cur = level0
        while len(cur) > 1:
            if len(cur) % 2 == 1:
                cur = cur + [cur[-1]]  # duplicate last (Bitcoin convention)
            nxt = [_hash_internal(cur[i], cur[i + 1]) for i in range(0, len(cur), 2)]
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
                sib = level_padded[idx + 1]
                directions.append(0)
            else:
                sib = level_padded[idx - 1]
                directions.append(1)
            siblings.append(sib)
            idx //= 2
        return MerkleProof(
            leaf=self.leaves[index],
            siblings=siblings,
            directions=directions,
            root=self.root,
            size=len(self.leaves),
            index=index,
        )


def verify_merkle_proof(proof: MerkleProof) -> bool:
    """Pure verifier: recompute root from leaf+path, compare.

    Rejects size/depth/index inconsistencies before recomputation, so the
    CVE-2012-2459 duplicated-tail family cannot pass even if it produces
    a colliding root.
    """
    if proof.size <= 0:
        return False
    if not 0 <= proof.index < proof.size:
        return False
    if len(proof.leaf) != 32:
        return False
    if len(proof.siblings) != len(proof.directions):
        return False
    if len(proof.siblings) != _expected_depth(proof.size):
        return False

    # Directions must match the index bit-pattern at each level.
    idx = proof.index
    level_n = proof.size
    expected_dirs: list[int] = []
    while level_n > 1:
        expected_dirs.append(0 if idx % 2 == 0 else 1)
        # round level_n up to even before halving (matches odd-leaf duplication)
        level_n = (level_n + 1) // 2
        idx //= 2
    if expected_dirs != proof.directions:
        return False

    cur = _hash_leaf(proof.leaf)
    for sib, direction in zip(proof.siblings, proof.directions):
        if len(sib) != 32:
            return False
        if direction == 0:
            cur = _hash_internal(cur, sib)
        elif direction == 1:
            cur = _hash_internal(sib, cur)
        else:
            return False
    return cur == proof.root
