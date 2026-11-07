import pytest

from dataledger.canonical import record_leaf
from dataledger.merkle import MerkleTree, diff_leaves, hash_pair, verify_proof

# Shared with contracts/test/MerkleVerification.t.sol (test_GoldenVector_MatchesOffChainTree).
GOLDEN_RECORDS = [b'{"id":1}', b'{"id":2}', b'{"id":3}', b'{"id":4}', b'{"id":5}']
GOLDEN_ROOT = "0xc22e8a39f9d818f0460bd2c470f2cf144119064c8edaad0f1703a1792e283b71"


def leaves(n: int) -> list[bytes]:
    return [record_leaf(i, f'{{"row":{i}}}'.encode()) for i in range(n)]


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 33, 100])
def test_every_proof_verifies(size):
    tree = MerkleTree(leaves(size))
    for i in range(size):
        assert verify_proof(tree.proof(i), tree.root, tree.leaves[i])


def test_wrong_leaf_or_position_fails():
    tree = MerkleTree(leaves(10))
    assert not verify_proof(tree.proof(3), tree.root, tree.leaves[4])
    assert not verify_proof(tree.proof(3), tree.root, record_leaf(3, b'{"row":99}'))


def test_single_leaf_tree():
    (leaf,) = leaves(1)
    tree = MerkleTree([leaf])
    assert tree.root == leaf
    assert tree.proof(0) == []


def test_hash_pair_is_commutative():
    a, b = leaves(2)
    assert hash_pair(a, b) == hash_pair(b, a)


def test_invalid_input():
    with pytest.raises(ValueError):
        MerkleTree([])
    with pytest.raises(ValueError):
        MerkleTree([b"short"])
    with pytest.raises(IndexError):
        MerkleTree(leaves(3)).proof(3)


def test_golden_vector():
    tree = MerkleTree([record_leaf(i, r) for i, r in enumerate(GOLDEN_RECORDS)])
    assert "0x" + tree.root.hex() == GOLDEN_ROOT


def test_diff_leaves():
    base = leaves(5)
    changed = list(base)
    changed[2] = record_leaf(2, b"tampered")
    result = diff_leaves(base, [*changed, record_leaf(5, b"new")])
    assert result.changed == [2]
    assert result.added == 1
    assert result.removed == 0
    assert not result.identical
    assert diff_leaves(base, base).identical
    assert diff_leaves(base, base[:3]).removed == 2
