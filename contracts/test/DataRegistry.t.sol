// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {DataRegistry} from "../src/DataRegistry.sol";
import {IDataRegistry} from "../src/interfaces/IDataRegistry.sol";
import {BaseTest} from "./Base.t.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract DataRegistryTest is BaseTest {
    // ------------------------------------------------------------------ registration

    function test_RegisterDataset_StoresFieldsAndEmits() public {
        vm.expectEmit(address(registry));
        emit DataRegistry.DatasetRegistered(
            1, owner, "sales_orders", IDataRegistry.Classification.Internal, SCHEMA_V1, METADATA
        );
        uint256 id = _register(IDataRegistry.Classification.Internal);

        IDataRegistry.Dataset memory ds = registry.getDataset(id);
        assertEq(id, 1);
        assertEq(registry.datasetCount(), 1);
        assertEq(ds.owner, owner);
        assertEq(ds.name, "sales_orders");
        assertEq(ds.schemaHash, SCHEMA_V1);
        assertEq(ds.metadataURI, METADATA);
        assertEq(ds.versionCount, 0);
        assertEq(ds.createdAt, block.timestamp);
        assertFalse(ds.archived);
        assertTrue(registry.exists(id));
        assertFalse(registry.exists(0));
        assertFalse(registry.exists(2));
    }

    function test_RegisterDataset_RevertsWithoutPublisherRole() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, outsider, registry.PUBLISHER_ROLE()
            )
        );
        vm.prank(outsider);
        registry.registerDataset("x", IDataRegistry.Classification.Internal, SCHEMA_V1, METADATA);
    }

    function test_RegisterDataset_RevertsOnInvalidName() public {
        vm.startPrank(owner);
        vm.expectRevert(DataRegistry.InvalidName.selector);
        registry.registerDataset("", IDataRegistry.Classification.Internal, SCHEMA_V1, METADATA);

        string memory longName = "0123456789012345678901234567890123456789012345678901234567890123456789";
        vm.expectRevert(DataRegistry.InvalidName.selector);
        registry.registerDataset(longName, IDataRegistry.Classification.Internal, SCHEMA_V1, METADATA);
        vm.stopPrank();
    }

    function test_RegisterDataset_RevertsOnZeroSchema() public {
        vm.expectRevert(DataRegistry.InvalidHash.selector);
        vm.prank(owner);
        registry.registerDataset("x", IDataRegistry.Classification.Internal, bytes32(0), METADATA);
    }

    // ------------------------------------------------------------------ versions

    function test_CommitVersion_StoresVersion() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        bytes32 root = keccak256("root-1");
        IDataRegistry.VersionInput memory input = _input(root, 1200);

        vm.expectEmit(address(registry));
        emit DataRegistry.VersionCommitted(id, 1, owner, root, input.contentHash, 1200, STORAGE);
        vm.prank(owner);
        uint32 v = registry.commitVersion(id, input, _noParents());

        IDataRegistry.Version memory stored = registry.getVersion(id, v);
        assertEq(v, 1);
        assertEq(stored.merkleRoot, root);
        assertEq(stored.contentHash, input.contentHash);
        assertEq(stored.schemaHash, SCHEMA_V1);
        assertEq(stored.recordCount, 1200);
        assertEq(stored.committer, owner);
        assertEq(stored.storageURI, STORAGE);
        assertEq(uint8(stored.status), uint8(IDataRegistry.VersionStatus.Active));
        assertEq(registry.getDataset(id).versionCount, 1);
        assertEq(_commit(id), 2);
    }

    function test_CommitVersion_AllowsSteward() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        vm.prank(owner);
        registry.setSteward(id, steward, true);
        assertTrue(registry.isSteward(id, steward));
        assertTrue(registry.canManage(id, steward));

        vm.prank(steward);
        uint32 v = registry.commitVersion(id, _input(keccak256("r"), 5), _noParents());
        assertEq(registry.getVersion(id, v).committer, steward);
    }

    function test_CommitVersion_RevertsForOutsider() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        IDataRegistry.VersionInput memory input = _input(keccak256("r"), 5);
        IDataRegistry.VersionRef[] memory parents = _noParents();
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.NotDatasetManager.selector, id, outsider));
        vm.prank(outsider);
        registry.commitVersion(id, input, parents);
    }

    function test_CommitVersion_RevertsForUnknownDataset() public {
        IDataRegistry.VersionInput memory input = _input(keccak256("r"), 5);
        IDataRegistry.VersionRef[] memory parents = _noParents();
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.UnknownDataset.selector, 7));
        vm.prank(owner);
        registry.commitVersion(7, input, parents);
    }

    function test_CommitVersion_RevertsOnInvalidInput() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        IDataRegistry.VersionRef[] memory none = _noParents();
        vm.startPrank(owner);

        IDataRegistry.VersionInput memory input = _input(bytes32(0), 5);
        vm.expectRevert(DataRegistry.InvalidHash.selector);
        registry.commitVersion(id, input, none);

        input = _input(keccak256("r"), 5);
        input.contentHash = bytes32(0);
        vm.expectRevert(DataRegistry.InvalidHash.selector);
        registry.commitVersion(id, input, none);

        input = _input(keccak256("r"), 0);
        vm.expectRevert(DataRegistry.EmptyDataset.selector);
        registry.commitVersion(id, input, none);

        input = _input(keccak256("r"), 5);
        input.storageURI = "";
        vm.expectRevert(DataRegistry.EmptyStorageURI.selector);
        registry.commitVersion(id, input, none);
        vm.stopPrank();
    }

    function test_CommitVersion_RecordsLineageAcrossDatasets() public {
        uint256 orders = _register(IDataRegistry.Classification.Internal);
        uint256 customers = _register(IDataRegistry.Classification.Confidential);
        uint256 revenue = _register(IDataRegistry.Classification.Internal);
        _commit(orders);
        _commit(orders);
        _commit(customers);

        IDataRegistry.VersionRef[] memory parents = new IDataRegistry.VersionRef[](2);
        parents[0] = IDataRegistry.VersionRef({datasetId: orders, version: 2});
        parents[1] = IDataRegistry.VersionRef({datasetId: customers, version: 1});

        vm.expectEmit(address(registry));
        emit DataRegistry.LineageLinked(revenue, 1, orders, 2);
        vm.expectEmit(address(registry));
        emit DataRegistry.LineageLinked(revenue, 1, customers, 1);
        vm.prank(owner);
        uint32 v = registry.commitVersion(revenue, _input(keccak256("rev"), 48), parents);

        IDataRegistry.VersionRef[] memory stored = registry.getParents(revenue, v);
        assertEq(stored.length, 2);
        assertEq(stored[0].datasetId, orders);
        assertEq(stored[0].version, 2);
        assertEq(stored[1].datasetId, customers);
        assertEq(stored[1].version, 1);
    }

    function test_CommitVersion_AllowsDeprecatedParent() public {
        uint256 src = _register(IDataRegistry.Classification.Internal);
        uint256 dst = _register(IDataRegistry.Classification.Internal);
        _commit(src);
        vm.prank(owner);
        registry.setVersionStatus(src, 1, IDataRegistry.VersionStatus.Deprecated, "superseded");

        IDataRegistry.VersionRef[] memory parents = new IDataRegistry.VersionRef[](1);
        parents[0] = IDataRegistry.VersionRef({datasetId: src, version: 1});
        vm.prank(owner);
        registry.commitVersion(dst, _input(keccak256("d"), 3), parents);
        assertEq(registry.getParents(dst, 1).length, 1);
    }

    function test_CommitVersion_RevertsOnUnusableParent() public {
        uint256 src = _register(IDataRegistry.Classification.Internal);
        uint256 dst = _register(IDataRegistry.Classification.Internal);
        _commit(src);
        IDataRegistry.VersionInput memory input = _input(keccak256("d"), 3);
        IDataRegistry.VersionRef[] memory parents = new IDataRegistry.VersionRef[](1);

        parents[0] = IDataRegistry.VersionRef({datasetId: src, version: 9});
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.ParentNotUsable.selector, src, 9));
        vm.prank(owner);
        registry.commitVersion(dst, input, parents);

        vm.prank(owner);
        registry.setVersionStatus(src, 1, IDataRegistry.VersionStatus.Withdrawn, "bad extract");
        parents[0] = IDataRegistry.VersionRef({datasetId: src, version: 1});
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.ParentNotUsable.selector, src, 1));
        vm.prank(owner);
        registry.commitVersion(dst, input, parents);
    }

    function test_CommitVersion_RevertsOnSelfReference() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        IDataRegistry.VersionInput memory input = _input(keccak256("d"), 3);
        IDataRegistry.VersionRef[] memory parents = new IDataRegistry.VersionRef[](1);
        parents[0] = IDataRegistry.VersionRef({datasetId: id, version: 1});
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.ParentNotUsable.selector, id, 1));
        vm.prank(owner);
        registry.commitVersion(id, input, parents);
    }

    function test_CommitVersion_RevertsOnDuplicateParent() public {
        uint256 src = _register(IDataRegistry.Classification.Internal);
        uint256 dst = _register(IDataRegistry.Classification.Internal);
        _commit(src);
        IDataRegistry.VersionInput memory input = _input(keccak256("d"), 3);
        IDataRegistry.VersionRef[] memory parents = new IDataRegistry.VersionRef[](2);
        parents[0] = IDataRegistry.VersionRef({datasetId: src, version: 1});
        parents[1] = IDataRegistry.VersionRef({datasetId: src, version: 1});
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.DuplicateParent.selector, src, 1));
        vm.prank(owner);
        registry.commitVersion(dst, input, parents);
    }

    function test_CommitVersion_RevertsOnTooManyParents() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        IDataRegistry.VersionInput memory input = _input(keccak256("d"), 3);
        IDataRegistry.VersionRef[] memory parents = new IDataRegistry.VersionRef[](17);
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.TooManyParents.selector, 17));
        vm.prank(owner);
        registry.commitVersion(id, input, parents);
    }

    function test_CommitVersion_TracksSchemaChange() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        _commit(id);
        IDataRegistry.VersionInput memory input = _input(keccak256("v2"), 10);
        input.schemaHash = SCHEMA_V2;

        vm.expectEmit(address(registry));
        emit DataRegistry.SchemaChanged(id, 2, SCHEMA_V1, SCHEMA_V2);
        vm.prank(owner);
        registry.commitVersion(id, input, _noParents());

        assertEq(registry.getDataset(id).schemaHash, SCHEMA_V2);
        assertEq(registry.getVersion(id, 1).schemaHash, SCHEMA_V1);
        assertEq(registry.getVersion(id, 2).schemaHash, SCHEMA_V2);
    }

    function test_CommitVersion_RevertsWhenArchived() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        _commit(id);
        vm.prank(owner);
        registry.archiveDataset(id);
        assertTrue(registry.getDataset(id).archived);

        IDataRegistry.VersionInput memory input = _input(keccak256("late"), 3);
        IDataRegistry.VersionRef[] memory parents = _noParents();
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.DatasetIsArchived.selector, id));
        vm.prank(owner);
        registry.commitVersion(id, input, parents);

        vm.expectRevert(abi.encodeWithSelector(DataRegistry.DatasetIsArchived.selector, id));
        vm.prank(owner);
        registry.archiveDataset(id);
        assertEq(uint8(registry.versionStatus(id, 1)), uint8(IDataRegistry.VersionStatus.Active));
    }

    function test_LocateContent_ReturnsFirstAnchor() public {
        uint256 a = _register(IDataRegistry.Classification.Internal);
        uint256 b = _register(IDataRegistry.Classification.Internal);
        IDataRegistry.VersionInput memory input = _input(keccak256("same-file"), 9);
        vm.startPrank(owner);
        registry.commitVersion(a, input, _noParents());
        registry.commitVersion(b, input, _noParents());
        vm.stopPrank();

        (uint256 datasetId, uint32 version) = registry.locateContent(input.contentHash);
        assertEq(datasetId, a);
        assertEq(version, 1);
        (datasetId, version) = registry.locateContent(keccak256("unknown"));
        assertEq(datasetId, 0);
        assertEq(version, 0);
    }

    // ------------------------------------------------------------------ status

    function test_SetVersionStatus_FollowsLifecycle() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        _commit(id);

        vm.startPrank(owner);
        vm.expectEmit(address(registry));
        emit DataRegistry.VersionStatusChanged(
            id, 1, IDataRegistry.VersionStatus.Active, IDataRegistry.VersionStatus.Deprecated, "superseded by v2"
        );
        registry.setVersionStatus(id, 1, IDataRegistry.VersionStatus.Deprecated, "superseded by v2");
        registry.setVersionStatus(id, 1, IDataRegistry.VersionStatus.Withdrawn, "erasure request");
        assertEq(uint8(registry.versionStatus(id, 1)), uint8(IDataRegistry.VersionStatus.Withdrawn));

        vm.expectRevert(
            abi.encodeWithSelector(
                DataRegistry.InvalidStatusTransition.selector,
                IDataRegistry.VersionStatus.Withdrawn,
                IDataRegistry.VersionStatus.Active
            )
        );
        registry.setVersionStatus(id, 1, IDataRegistry.VersionStatus.Active, "undo");
        vm.stopPrank();
    }

    function test_SetVersionStatus_RejectsInvalidTargets() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        _commit(id);
        vm.startPrank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                DataRegistry.InvalidStatusTransition.selector,
                IDataRegistry.VersionStatus.Active,
                IDataRegistry.VersionStatus.Active
            )
        );
        registry.setVersionStatus(id, 1, IDataRegistry.VersionStatus.Active, "");
        vm.expectRevert(
            abi.encodeWithSelector(
                DataRegistry.InvalidStatusTransition.selector,
                IDataRegistry.VersionStatus.Active,
                IDataRegistry.VersionStatus.None
            )
        );
        registry.setVersionStatus(id, 1, IDataRegistry.VersionStatus.None, "");
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.UnknownVersion.selector, id, 2));
        registry.setVersionStatus(id, 2, IDataRegistry.VersionStatus.Deprecated, "");
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(DataRegistry.NotDatasetManager.selector, id, outsider));
        vm.prank(outsider);
        registry.setVersionStatus(id, 1, IDataRegistry.VersionStatus.Deprecated, "");
    }

    // ------------------------------------------------------------------ governance

    function test_SetSteward_OnlyOwner() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        vm.prank(owner);
        registry.setSteward(id, steward, true);

        vm.expectRevert(abi.encodeWithSelector(DataRegistry.NotDatasetOwner.selector, id, steward));
        vm.prank(steward);
        registry.setSteward(id, outsider, true);

        vm.expectRevert(DataRegistry.InvalidAccount.selector);
        vm.prank(owner);
        registry.setSteward(id, address(0), true);

        vm.prank(owner);
        registry.setSteward(id, steward, false);
        assertFalse(registry.canManage(id, steward));
    }

    function test_TwoStepOwnershipTransfer() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        vm.prank(owner);
        registry.transferDatasetOwnership(id, consumer);
        assertEq(registry.pendingOwner(id), consumer);
        assertEq(registry.datasetOwner(id), owner);

        vm.expectRevert(abi.encodeWithSelector(DataRegistry.NotPendingOwner.selector, id, outsider));
        vm.prank(outsider);
        registry.acceptDatasetOwnership(id);

        vm.expectEmit(address(registry));
        emit DataRegistry.OwnershipTransferred(id, owner, consumer);
        vm.prank(consumer);
        registry.acceptDatasetOwnership(id);
        assertEq(registry.datasetOwner(id), consumer);
        assertEq(registry.pendingOwner(id), address(0));
        assertFalse(registry.canManage(id, owner));
    }

    function test_TransferOwnership_RevertsOnZeroAddress() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        vm.expectRevert(DataRegistry.InvalidAccount.selector);
        vm.prank(owner);
        registry.transferDatasetOwnership(id, address(0));
    }

    function test_SetClassification_OnlyOwner() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        vm.expectEmit(address(registry));
        emit DataRegistry.ClassificationChanged(
            id, IDataRegistry.Classification.Internal, IDataRegistry.Classification.Restricted
        );
        vm.prank(owner);
        registry.setClassification(id, IDataRegistry.Classification.Restricted);
        assertEq(uint8(registry.classificationOf(id)), uint8(IDataRegistry.Classification.Restricted));

        vm.expectRevert(abi.encodeWithSelector(DataRegistry.NotDatasetOwner.selector, id, outsider));
        vm.prank(outsider);
        registry.setClassification(id, IDataRegistry.Classification.Public);
    }

    function test_UpdateMetadata_ByManager() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        vm.prank(owner);
        registry.setSteward(id, steward, true);
        vm.prank(steward);
        registry.updateMetadata(id, "dl://documents/new");
        assertEq(registry.getDataset(id).metadataURI, "dl://documents/new");
    }

    function test_Pause_BlocksWrites() public {
        uint256 id = _register(IDataRegistry.Classification.Internal);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, outsider, registry.PAUSER_ROLE()
            )
        );
        vm.prank(outsider);
        registry.pause();

        vm.prank(admin);
        registry.pause();
        IDataRegistry.VersionInput memory input = _input(keccak256("r"), 1);
        IDataRegistry.VersionRef[] memory parents = _noParents();
        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(owner);
        registry.commitVersion(id, input, parents);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(owner);
        registry.registerDataset("y", IDataRegistry.Classification.Internal, SCHEMA_V1, METADATA);

        vm.prank(admin);
        registry.unpause();
        _commit(id);
    }

    function test_Views_RevertForUnknownIds() public {
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.UnknownDataset.selector, 1));
        registry.getDataset(1);
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.UnknownDataset.selector, 1));
        registry.datasetOwner(1);
        vm.expectRevert(abi.encodeWithSelector(DataRegistry.UnknownVersion.selector, 1, 1));
        registry.getVersion(1, 1);
        assertEq(uint8(registry.versionStatus(1, 1)), uint8(IDataRegistry.VersionStatus.None));
    }

    function test_Constructor_RevertsOnZeroAdmin() public {
        vm.expectRevert(DataRegistry.InvalidAccount.selector);
        new DataRegistry(address(0));
    }
}
