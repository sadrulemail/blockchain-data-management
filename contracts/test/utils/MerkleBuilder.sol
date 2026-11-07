// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Builds Merkle trees the same way the off-chain service does: leaves in record order, sorted-pair keccak,
///         and an odd node at the end of a layer is promoted unchanged.
library MerkleBuilder {
    function hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }

    function root(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length > 0, "no leaves");
        bytes32[] memory layer = _copy(leaves);
        uint256 n = layer.length;
        while (n > 1) {
            n = _reduce(layer, n);
        }
        return layer[0];
    }

    function proof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory out) {
        require(index < leaves.length, "index out of range");
        bytes32[] memory layer = _copy(leaves);
        uint256 n = layer.length;
        out = new bytes32[](256);
        uint256 count;
        while (n > 1) {
            uint256 sibling = index ^ 1;
            if (sibling < n) out[count++] = layer[sibling];
            n = _reduce(layer, n);
            index /= 2;
        }
        assembly {
            mstore(out, count)
        }
    }

    function _reduce(bytes32[] memory layer, uint256 n) private pure returns (uint256 m) {
        m = (n + 1) / 2;
        for (uint256 i = 0; i < m; ++i) {
            uint256 left = 2 * i;
            layer[i] = left + 1 < n ? hashPair(layer[left], layer[left + 1]) : layer[left];
        }
    }

    function _copy(bytes32[] memory src) private pure returns (bytes32[] memory dst) {
        dst = new bytes32[](src.length);
        for (uint256 i = 0; i < src.length; ++i) {
            dst[i] = src[i];
        }
    }
}
