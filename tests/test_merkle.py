"""Merkle tree and inclusion proofs."""

import hashlib
import os

import pytest

from veritas.crypto import sha256d
from veritas.merkle import (
    INTERNAL_PREFIX,
    LEAF_PREFIX,
    MerkleProof,
    MerkleTree,
    _expected_depth,
    verify_merkle_proof,
)


def _digest(i: int) -> bytes:
    return hashlib.sha256(i.to_bytes(4, "big")).digest()


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 31, 64, 100])
def test_proves_every_leaf(n):
    leaves = [_digest(i) for i in range(n)]
    t = MerkleTree(leaves)
    for i in range(n):
        p = t.prove(i)
        assert verify_merkle_proof(p)


def test_single_leaf_tree_has_prefixed_leaf_as_root():
    leaves = [_digest(0)]
    t = MerkleTree(leaves)
    # With RFC-6962 prefixes, single-leaf root is sha256d(0x00 || leaf).
    assert t.root == sha256d(LEAF_PREFIX + leaves[0])
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
        size=p.size,
        index=p.index,
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
    bad = MerkleProof(p.leaf, p.siblings, flipped, p.root, p.size, p.index)
    assert verify_merkle_proof(bad) is False


def test_rejects_non32_leaves():
    with pytest.raises(ValueError):
        MerkleTree([b"short"])


def test_proof_rejects_inconsistent_size():
    leaves = [_digest(i) for i in range(3)]
    t = MerkleTree(leaves)
    p = t.prove(1)
    # Inflate size to a value whose expected depth differs.
    bad = MerkleProof(p.leaf, p.siblings, p.directions, p.root, size=100, index=p.index)
    assert verify_merkle_proof(bad) is False


def test_proof_rejects_index_out_of_range():
    leaves = [_digest(i) for i in range(4)]
    t = MerkleTree(leaves)
    p = t.prove(1)
    bad = MerkleProof(p.leaf, p.siblings, p.directions, p.root, size=p.size, index=99)
    assert verify_merkle_proof(bad) is False


def test_bitcoin_style_odd_duplication():
    # 3 leaves with RFC-6962 prefixes:
    #   root = H_int(H_int(H_leaf(a), H_leaf(b)), H_int(H_leaf(c), H_leaf(c)))
    a, b, c = _digest(0), _digest(1), _digest(2)
    t = MerkleTree([a, b, c])
    la, lb, lc = (
        sha256d(LEAF_PREFIX + a),
        sha256d(LEAF_PREFIX + b),
        sha256d(LEAF_PREFIX + c),
    )
    expected = sha256d(
        INTERNAL_PREFIX
        + sha256d(INTERNAL_PREFIX + la + lb)
        + sha256d(INTERNAL_PREFIX + lc + lc)
    )
    assert t.root == expected


# ---------- mutation-test-driven: guard clause coverage ---------------


def test_expected_depth_single_leaf():
    assert _expected_depth(1) == 0


def test_verify_rejects_negative_size():
    p = MerkleProof(leaf=b"\x00" * 32, siblings=[], directions=[],
                    root=b"\x00" * 32, size=-1, index=0)
    assert verify_merkle_proof(p) is False


def test_verify_rejects_zero_size():
    p = MerkleProof(leaf=b"\x00" * 32, siblings=[], directions=[],
                    root=b"\x00" * 32, size=0, index=0)
    assert verify_merkle_proof(p) is False


def test_verify_rejects_index_equal_to_size():
    t = MerkleTree([_digest(0)])
    good = t.prove(0)
    bad = MerkleProof(leaf=good.leaf, siblings=good.siblings,
                      directions=good.directions, root=good.root,
                      size=1, index=1)
    assert verify_merkle_proof(bad) is False


def test_verify_rejects_non_32_byte_leaf():
    p = MerkleProof(leaf=b"\x00" * 31, siblings=[], directions=[],
                    root=b"\x00" * 32, size=1, index=0)
    assert verify_merkle_proof(p) is False


def test_verify_rejects_mismatched_siblings_directions_length():
    leaf = _digest(0)
    t = MerkleTree([leaf, _digest(1)])
    good = t.prove(0)
    bad = MerkleProof(leaf=good.leaf, siblings=good.siblings,
                      directions=[], root=good.root,
                      size=good.size, index=good.index)
    assert verify_merkle_proof(bad) is False


def test_verify_rejects_non_32_byte_sibling():
    leaf = _digest(0)
    t = MerkleTree([leaf, _digest(1)])
    good = t.prove(0)
    bad = MerkleProof(leaf=good.leaf, siblings=[b"\x00" * 31],
                      directions=good.directions, root=good.root,
                      size=good.size, index=good.index)
    assert verify_merkle_proof(bad) is False
