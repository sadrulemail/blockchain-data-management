// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {DataRegistry} from "../src/DataRegistry.sol";
import {IDataRegistry} from "../src/interfaces/IDataRegistry.sol";
import {BaseTest} from "./Base.t.sol";
import {MerkleBuilder} from "./utils/MerkleBuilder.sol";

contract MerkleVerificationTest is BaseTest {
    uint256 internal datasetId;

    function setUp() public override {
        super.setUp();
        datasetId = _register(IDataRegistry.Classification.Internal);
    }

    function _records(uint256 count, uint256 seed) internal pure returns (bytes[] memory records) {
        records = new bytes[](count);
        for (uint256 i = 0; i < count; ++i) {
            records[i] = abi.encodePacked('{"order_id":', vm.toString(seed + i), ',"status":"shipped"}');
        }
    }

    function _leaves(bytes[] memory records) internal view returns (bytes32[] memory leaves) {
        leaves = new bytes32[](records.length);
        for (uint256 i = 0; i < records.length; ++i) {
            leaves[i] = registry.recordLeaf(i, records[i]);
        }
    }

    function _anchor(bytes32[] memory leaves) internal returns (uint32 version) {
        vm.prank(owner);
        version =
            registry.commitVersion(datasetId, _input(MerkleBuilder.root(leaves), uint64(leaves.length)), _noParents());
    }

    function testFuzz_VerifyRecord_AcceptsEveryRecord(uint8 rawCount, uint8 rawPick, uint64 seed) public {
        uint256 count = bound(rawCount, 1, 64);
        uint256 pick = bound(rawPick, 0, count - 1);
        bytes[] memory records = _records(count, seed);
        bytes32[] memory leaves = _leaves(records);
        uint32 v = _anchor(leaves);

        bytes32[] memory proof = MerkleBuilder.proof(leaves, pick);
        assertTrue(registry.verifyRecord(datasetId, v, pick, records[pick], proof));
    }

    function testFuzz_VerifyRecord_RejectsTamperedRecord(uint8 rawCount, uint8 rawPick, uint64 seed) public {
        uint256 count = bound(rawCount, 1, 64);
        uint256 pick = bound(rawPick, 0, count - 1);
        bytes[] memory records = _records(count, seed);
        bytes32[] memory leaves = _leaves(records);
        uint32 v = _anchor(leaves);

        bytes memory tampered = abi.encodePacked(records[pick], " ");
        bytes32[] memory proof = MerkleBuilder.proof(leaves, pick);
        assertFalse(registry.verifyRecord(datasetId, v, pick, tampered, proof));
    }

    function testFuzz_VerifyRecord_BindsPosition(uint8 rawCount, uint64 seed) public {
        uint256 count = bound(rawCount, 2, 64);
        bytes[] memory records = _records(count, seed);
        bytes32[] memory leaves = _leaves(records);
        uint32 v = _anchor(leaves);

        bytes32[] memory proof = MerkleBuilder.proof(leaves, 0);
        assertFalse(registry.verifyRecord(datasetId, v, 1, records[0], proof));
    }

    function test_VerifyRecord_SingleRecordTree() public {
        bytes[] memory records = _records(1, 42);
        bytes32[] memory leaves = _leaves(records);
        uint32 v = _anchor(leaves);
        assertEq(registry.getVersion(datasetId, v).merkleRoot, leaves[0]);
        assertTrue(registry.verifyRecord(datasetId, v, 0, records[0], new bytes32[](0)));
    }

    function test_VerifyRecord_FalseWhenIndexOutOfRange() public {
        bytes[] memory records = _records(3, 1);
        bytes32[] memory leaves = _leaves(records);
        uint32 v = _anchor(leaves);
        assertFalse(registry.verifyRecord(datasetId, v, 3, records[0], MerkleBuilder.proof(leaves, 0)));
    }

    function test_VerifyRecord_RevertsForUnknownVersion() public {
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.UnknownVersion.selector, datasetId, 1));
        registry.verifyRecord(datasetId, 1, 0, "", new bytes32[](0));
    }

    /// Same records and root as service/tests/unit/test_merkle.py, so both implementations stay in step.
    function test_GoldenVector_MatchesOffChainTree() public {
        bytes[] memory records = new bytes[](5);
        records[0] = '{"id":1}';
        records[1] = '{"id":2}';
        records[2] = '{"id":3}';
        records[3] = '{"id":4}';
        records[4] = '{"id":5}';
        bytes32[] memory leaves = _leaves(records);
        bytes32 root = MerkleBuilder.root(leaves);
        assertEq(root, 0xc22e8a39f9d818f0460bd2c470f2cf144119064c8edaad0f1703a1792e283b71);

        uint32 v = _anchor(leaves);
        for (uint256 i = 0; i < records.length; ++i) {
            assertTrue(registry.verifyRecord(datasetId, v, i, records[i], MerkleBuilder.proof(leaves, i)));
        }
    }

    function test_RecordLeaf_IsDoubleHashedAbiEncoding() public view {
        bytes memory record = '{"id":1}';
        bytes32 expected = keccak256(bytes.concat(keccak256(abi.encode(uint256(7), record))));
        assertEq(registry.recordLeaf(7, record), expected);
    }
}
