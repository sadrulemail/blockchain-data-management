// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {DataRegistry} from "../../src/DataRegistry.sol";
import {IDataRegistry} from "../../src/interfaces/IDataRegistry.sol";
import {Test} from "forge-std/Test.sol";

/// @notice Drives random registrations, commits with lineage and status changes against the registry.
contract RegistryHandler is Test {
    DataRegistry internal immutable registry;
    address internal immutable publisher;

    uint256 public ghostDatasets;
    mapping(uint256 => uint32) public ghostVersions;
    IDataRegistry.VersionRef[] internal _withdrawn;

    constructor(DataRegistry registry_, address publisher_) {
        registry = registry_;
        publisher = publisher_;
    }

    function register(uint8 classification) external {
        vm.prank(publisher);
        registry.registerDataset("ds", IDataRegistry.Classification(classification % 4), keccak256("schema"), "");
        ++ghostDatasets;
    }

    function commit(uint256 datasetSeed, uint256 parentSeed, bool withParent) external {
        if (ghostDatasets == 0) return;
        uint256 id = bound(datasetSeed, 1, ghostDatasets);

        IDataRegistry.VersionRef[] memory parents = new IDataRegistry.VersionRef[](0);
        if (withParent) {
            uint256 parentId = bound(parentSeed, 1, ghostDatasets);
            uint32 count = ghostVersions[parentId];
            if (count > 0) {
                uint32 pv = uint32(bound(parentSeed >> 8, 1, count));
                IDataRegistry.VersionStatus s = registry.versionStatus(parentId, pv);
                if (s == IDataRegistry.VersionStatus.Withdrawn) return;
                parents = new IDataRegistry.VersionRef[](1);
                parents[0] = IDataRegistry.VersionRef({datasetId: parentId, version: pv});
            }
        }

        IDataRegistry.VersionInput memory input = IDataRegistry.VersionInput({
            merkleRoot: keccak256(abi.encode(id, ghostVersions[id])),
            contentHash: keccak256(abi.encode("file", id, ghostVersions[id])),
            schemaHash: keccak256("schema"),
            recordCount: 10,
            storageURI: "dl://objects/x"
        });
        vm.prank(publisher);
        registry.commitVersion(id, input, parents);
        ++ghostVersions[id];
    }

    function withdraw(uint256 datasetSeed, uint256 versionSeed) external {
        if (ghostDatasets == 0) return;
        uint256 id = bound(datasetSeed, 1, ghostDatasets);
        uint32 count = ghostVersions[id];
        if (count == 0) return;
        uint32 v = uint32(bound(versionSeed, 1, count));
        if (registry.versionStatus(id, v) == IDataRegistry.VersionStatus.Withdrawn) return;
        vm.prank(publisher);
        registry.setVersionStatus(id, v, IDataRegistry.VersionStatus.Withdrawn, "invariant run");
        _withdrawn.push(IDataRegistry.VersionRef({datasetId: id, version: v}));
    }

    function withdrawnCount() external view returns (uint256) {
        return _withdrawn.length;
    }

    function withdrawnAt(uint256 i) external view returns (IDataRegistry.VersionRef memory) {
        return _withdrawn[i];
    }
}

contract RegistryInvariantTest is Test {
    DataRegistry internal registry;
    RegistryHandler internal handler;

    function setUp() public {
        address admin = makeAddr("admin");
        address publisher = makeAddr("publisher");
        registry = new DataRegistry(admin);
        bytes32 role = registry.PUBLISHER_ROLE();
        vm.prank(admin);
        registry.grantRole(role, publisher);

        handler = new RegistryHandler(registry, publisher);
        targetContract(address(handler));
    }

    /// Dataset and version counters match exactly what was committed.
    function invariant_CountersMatchCommits() public view {
        assertEq(registry.datasetCount(), handler.ghostDatasets());
        for (uint256 id = 1; id <= handler.ghostDatasets(); ++id) {
            assertEq(registry.getDataset(id).versionCount, handler.ghostVersions(id));
        }
    }

    /// Every committed version exists and every lineage edge points at a version that exists.
    function invariant_LineageIsClosed() public view {
        for (uint256 id = 1; id <= handler.ghostDatasets(); ++id) {
            uint32 count = handler.ghostVersions(id);
            for (uint32 v = 1; v <= count; ++v) {
                assertTrue(registry.versionStatus(id, v) != IDataRegistry.VersionStatus.None);
                IDataRegistry.VersionRef[] memory parents = registry.getParents(id, v);
                for (uint256 p = 0; p < parents.length; ++p) {
                    assertTrue(
                        registry.versionStatus(parents[p].datasetId, parents[p].version)
                            != IDataRegistry.VersionStatus.None
                    );
                }
            }
        }
    }

    /// Withdrawn is a terminal state.
    function invariant_WithdrawnIsFinal() public view {
        for (uint256 i = 0; i < handler.withdrawnCount(); ++i) {
            IDataRegistry.VersionRef memory ref = handler.withdrawnAt(i);
            assertEq(
                uint8(registry.versionStatus(ref.datasetId, ref.version)), uint8(IDataRegistry.VersionStatus.Withdrawn)
            );
        }
    }
}
