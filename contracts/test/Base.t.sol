// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessLedger} from "../src/AccessLedger.sol";
import {DataRegistry} from "../src/DataRegistry.sol";
import {QualityLedger} from "../src/QualityLedger.sol";
import {IDataRegistry} from "../src/interfaces/IDataRegistry.sol";
import {Test} from "forge-std/Test.sol";

abstract contract BaseTest is Test {
    bytes32 internal constant SCHEMA_V1 = keccak256("schema:sales_orders:v1");
    bytes32 internal constant SCHEMA_V2 = keccak256("schema:sales_orders:v2");
    string internal constant METADATA = "dl://documents/9f2c";
    string internal constant STORAGE = "dl://objects/4b1e";

    DataRegistry internal registry;
    AccessLedger internal access;
    QualityLedger internal quality;

    address internal admin = makeAddr("admin");
    address internal owner = makeAddr("owner");
    address internal steward = makeAddr("steward");
    address internal consumer = makeAddr("consumer");
    address internal gateway = makeAddr("gateway");
    address internal auditor = makeAddr("auditor");
    address internal outsider = makeAddr("outsider");

    function setUp() public virtual {
        vm.warp(1_790_000_000);
        vm.startPrank(admin);
        registry = new DataRegistry(admin);
        access = new AccessLedger(registry, admin);
        quality = new QualityLedger(registry, admin);
        registry.grantRole(registry.PUBLISHER_ROLE(), owner);
        access.grantRole(access.GATEWAY_ROLE(), gateway);
        quality.grantRole(quality.AUDITOR_ROLE(), auditor);
        vm.stopPrank();
    }

    function _register(IDataRegistry.Classification classification) internal returns (uint256 datasetId) {
        vm.prank(owner);
        datasetId = registry.registerDataset("sales_orders", classification, SCHEMA_V1, METADATA);
    }

    function _input(bytes32 root, uint64 records) internal pure returns (IDataRegistry.VersionInput memory) {
        return IDataRegistry.VersionInput({
            merkleRoot: root,
            contentHash: keccak256(abi.encode("file", root)),
            schemaHash: SCHEMA_V1,
            recordCount: records,
            storageURI: STORAGE
        });
    }

    function _noParents() internal pure returns (IDataRegistry.VersionRef[] memory) {
        return new IDataRegistry.VersionRef[](0);
    }

    function _commit(uint256 datasetId, bytes32 root) internal returns (uint32 version) {
        vm.prank(owner);
        version = registry.commitVersion(datasetId, _input(root, 100), _noParents());
    }

    function _commit(uint256 datasetId) internal returns (uint32 version) {
        return _commit(datasetId, keccak256(abi.encode(datasetId, block.timestamp, gasleft())));
    }
}
