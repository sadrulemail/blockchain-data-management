"""Merkle tree compatible with OpenZeppelin ``MerkleProof``.

Leaves stay in record order. Each layer hashes neighbours as a sorted pair (``keccak256(min || max)``); an odd
node at the end of a layer moves up unchanged and adds nothing to the proof.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from eth_utils import keccak


def hash_pair(a: bytes, b: bytes) -> bytes:
    return keccak(a + b) if a < b else keccak(b + a)


class MerkleTree:
    def __init__(self, leaves: Sequence[bytes]) -> None:
        if not leaves:
            raise ValueError("a Merkle tree needs at least one leaf")
        if any(len(leaf) != 32 for leaf in leaves):
            raise ValueError("leaves must be 32-byte hashes")
        layers = [list(leaves)]
        while len(layers[-1]) > 1:
            layer = layers[-1]
            layers.append(
                [hash_pair(layer[i], layer[i + 1]) if i + 1 < len(layer) else layer[i] for i in range(0, len(layer), 2)]
            )
        self._layers = layers

    @property
    def root(self) -> bytes:
        return self._layers[-1][0]

    @property
    def leaves(self) -> list[bytes]:
        return self._layers[0]

    def __len__(self) -> int:
        return len(self._layers[0])

    def proof(self, index: int) -> list[bytes]:
        if not 0 <= index < len(self):
            raise IndexError(f"leaf {index} out of range (0..{len(self) - 1})")
        proof: list[bytes] = []
        for layer in self._layers[:-1]:
            sibling = index ^ 1
            if sibling < len(layer):
                proof.append(layer[sibling])
            index //= 2
        return proof


def verify_proof(proof: Sequence[bytes], root: bytes, leaf: bytes) -> bool:
    computed = leaf
    for node in proof:
        computed = hash_pair(computed, node)
    return computed == root


@dataclass(frozen=True)
class RecordDiff:
    """Positions that differ between an anchored version and a candidate file."""

    changed: list[int]
    added: int
    removed: int

    @property
    def identical(self) -> bool:
        return not self.changed and self.added == 0 and self.removed == 0


def diff_leaves(anchored: Sequence[bytes], candidate: Sequence[bytes]) -> RecordDiff:
    common = min(len(anchored), len(candidate))
    changed = [i for i in range(common) if anchored[i] != candidate[i]]
    return RecordDiff(
        changed=changed,
        added=max(0, len(candidate) - len(anchored)),
        removed=max(0, len(anchored) - len(candidate)),
    )
