"""Merkle tree and inclusion proofs."""

import hashlib
import os

import pytest

from veritas.crypto import sha256d
from veritas.merkle import MerkleTree, MerkleProof, verify_merkle_proof


def _digest(i: int) -> bytes:
    return hashlib.sha256(i.to_bytes(4, "big")).digest()


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 31, 64, 100])
def test_proves_every_leaf(n):
    leaves = [_digest(i) for i in range(n)]
    t = MerkleTree(leaves)
    for i in range(n):
        p = t.prove(i)
        assert verify_merkle_proof(p)


def test_single_leaf_tree_has_leaf_as_root():
    leaves = [_digest(0)]
    t = MerkleTree(leaves)
    assert t.root == leaves[0]
    p = t.prove(0)
    assert verify_merkle_proof(p)


def test_proof_rejects_wrong_root():
    leaves = [_digest(i) for i in range(5)]
    t = MerkleTree(leaves)
    p = t.prove(2)
    bad = MerkleProof(
        leaf=p.leaf,
        siblings=p.siblings,
        directions=p.directions,
        root=b"\xff" * 32,
    )
    assert verify_merkle_proof(bad) is False


def test_proof_rejects_swapped_directions():
    leaves = [_digest(i) for i in range(5)]
    t = MerkleTree(leaves)
    p = t.prove(2)
    if not p.directions:
        pytest.skip("trivial tree")
    flipped = list(p.directions)
    flipped[0] = 1 - flipped[0]
    bad = MerkleProof(p.leaf, p.siblings, flipped, p.root)
    assert verify_merkle_proof(bad) is False


def test_rejects_non32_leaves():
    with pytest.raises(ValueError):
        MerkleTree([b"short"])


def test_bitcoin_style_odd_duplication():
    # 3 leaves: hash should equal hash(hash(a,b), hash(c,c))
    a, b, c = _digest(0), _digest(1), _digest(2)
    t = MerkleTree([a, b, c])
    expected = sha256d(sha256d(a + b) + sha256d(c + c))
    assert t.root == expected
