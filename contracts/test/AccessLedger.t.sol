// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessLedger} from "../src/AccessLedger.sol";
import {IDataRegistry} from "../src/interfaces/IDataRegistry.sol";
import {BaseTest} from "./Base.t.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract AccessLedgerTest is BaseTest {
    uint64 internal constant THIRTY_DAYS = 30 days;
    string internal constant PURPOSE = "Quarterly revenue reconciliation";

    uint256 internal datasetId;

    function setUp() public override {
        super.setUp();
        datasetId = _register(IDataRegistry.Classification.Confidential);
        _commit(datasetId);
    }

    function _request() internal returns (uint256 requestId) {
        vm.prank(consumer);
        requestId = access.requestAccess(datasetId, PURPOSE);
    }

    // ------------------------------------------------------------------ hasAccess

    function test_HasAccess_PublicDatasetIsOpen() public {
        uint256 open = _register(IDataRegistry.Classification.Public);
        assertTrue(access.hasAccess(open, outsider));
        assertFalse(access.hasAccess(datasetId, outsider));
        assertFalse(access.hasAccess(99, outsider));
    }

    function test_HasAccess_OwnerAndStewards() public {
        assertTrue(access.hasAccess(datasetId, owner));
        assertFalse(access.hasAccess(datasetId, steward));
        vm.prank(owner);
        registry.setSteward(datasetId, steward, true);
        assertTrue(access.hasAccess(datasetId, steward));
    }

    // ------------------------------------------------------------------ requests

    function test_RequestApprove_GrantsUntilExpiry() public {
        vm.expectEmit(address(access));
        emit AccessLedger.AccessRequested(1, datasetId, consumer, keccak256(bytes(PURPOSE)), PURPOSE);
        uint256 requestId = _request();
        assertEq(access.openRequestOf(datasetId, consumer), requestId);
        assertEq(uint8(access.getRequest(requestId).status), uint8(AccessLedger.RequestStatus.Pending));

        uint64 expiresAt = uint64(block.timestamp) + THIRTY_DAYS;
        vm.expectEmit(address(access));
        emit AccessLedger.AccessGranted(datasetId, consumer, owner, keccak256(bytes(PURPOSE)), expiresAt);
        vm.expectEmit(address(access));
        emit AccessLedger.AccessRequestApproved(requestId, owner, expiresAt);
        vm.prank(owner);
        access.approveRequest(requestId, THIRTY_DAYS);

        assertTrue(access.hasAccess(datasetId, consumer));
        assertEq(access.openRequestOf(datasetId, consumer), 0);
        AccessLedger.Grant memory g = access.getGrant(datasetId, consumer);
        assertEq(g.expiresAt, expiresAt);
        assertEq(g.grantedBy, owner);
        assertEq(g.purposeHash, keccak256(bytes(PURPOSE)));

        vm.warp(expiresAt);
        assertFalse(access.hasAccess(datasetId, consumer));
    }

    function test_Request_RevertsWhenAlreadyOpen() public {
        uint256 requestId = _request();
        vm.expectRevert(
            abi.encodeWithSelector(AccessLedger.RequestAlreadyOpen.selector, datasetId, consumer, requestId)
        );
        vm.prank(consumer);
        access.requestAccess(datasetId, PURPOSE);
    }

    function test_Request_RevertsWhenNotRequired() public {
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.AccessNotRequired.selector, datasetId, owner));
        vm.prank(owner);
        access.requestAccess(datasetId, PURPOSE);

        uint256 open = _register(IDataRegistry.Classification.Public);
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.AccessNotRequired.selector, open, consumer));
        vm.prank(consumer);
        access.requestAccess(open, PURPOSE);
    }

    function test_Request_RevertsOnBadInput() public {
        vm.expectRevert(AccessLedger.EmptyPurpose.selector);
        vm.prank(consumer);
        access.requestAccess(datasetId, "");

        vm.expectRevert(abi.encodeWithSelector(AccessLedger.UnknownDataset.selector, 42));
        vm.prank(consumer);
        access.requestAccess(42, PURPOSE);
    }

    function test_Reject_ClosesRequestAndAllowsNewOne() public {
        uint256 requestId = _request();
        vm.expectEmit(address(access));
        emit AccessLedger.AccessRequestRejected(requestId, owner, "purpose too broad");
        vm.prank(owner);
        access.rejectRequest(requestId, "purpose too broad");

        assertEq(uint8(access.getRequest(requestId).status), uint8(AccessLedger.RequestStatus.Rejected));
        assertFalse(access.hasAccess(datasetId, consumer));
        assertEq(_request(), 2);

        vm.expectRevert(abi.encodeWithSelector(AccessLedger.RequestNotPending.selector, requestId));
        vm.prank(owner);
        access.approveRequest(requestId, THIRTY_DAYS);
    }

    function test_Cancel_OnlyRequester() public {
        uint256 requestId = _request();
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.NotRequester.selector, requestId, outsider));
        vm.prank(outsider);
        access.cancelRequest(requestId);

        vm.prank(consumer);
        access.cancelRequest(requestId);
        assertEq(uint8(access.getRequest(requestId).status), uint8(AccessLedger.RequestStatus.Cancelled));
        assertEq(access.openRequestOf(datasetId, consumer), 0);
    }

    function test_Approve_OnlyManager() public {
        uint256 requestId = _request();
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.NotDatasetManager.selector, datasetId, outsider));
        vm.prank(outsider);
        access.approveRequest(requestId, THIRTY_DAYS);

        vm.prank(owner);
        registry.setSteward(datasetId, steward, true);
        vm.prank(steward);
        access.approveRequest(requestId, THIRTY_DAYS);
        assertEq(access.getGrant(datasetId, consumer).grantedBy, steward);
    }

    function test_Approve_RevertsOnInvalidDuration() public {
        uint256 requestId = _request();
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.InvalidDuration.selector, 0));
        access.approveRequest(requestId, 0);
        uint64 tooLong = access.MAX_GRANT_DURATION() + 1;
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.InvalidDuration.selector, tooLong));
        access.approveRequest(requestId, tooLong);
        vm.stopPrank();
    }

    function test_GetRequest_RevertsForUnknown() public {
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.UnknownRequest.selector, 5));
        access.getRequest(5);
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.UnknownRequest.selector, 5));
        vm.prank(owner);
        access.approveRequest(5, THIRTY_DAYS);
    }

    // ------------------------------------------------------------------ direct grants

    function test_GrantAndRevoke() public {
        vm.prank(owner);
        access.grantAccess(datasetId, consumer, THIRTY_DAYS, PURPOSE);
        assertTrue(access.hasAccess(datasetId, consumer));

        vm.expectEmit(address(access));
        emit AccessLedger.AccessRevoked(datasetId, consumer, owner);
        vm.prank(owner);
        access.revokeAccess(datasetId, consumer);
        assertFalse(access.hasAccess(datasetId, consumer));
        assertTrue(access.getGrant(datasetId, consumer).revoked);

        vm.expectRevert(abi.encodeWithSelector(AccessLedger.NoActiveGrant.selector, datasetId, consumer));
        vm.prank(owner);
        access.revokeAccess(datasetId, consumer);
    }

    function test_Grant_RevertsOnBadInput() public {
        vm.startPrank(owner);
        vm.expectRevert(AccessLedger.InvalidAccount.selector);
        access.grantAccess(datasetId, address(0), THIRTY_DAYS, PURPOSE);
        vm.expectRevert(AccessLedger.EmptyPurpose.selector);
        access.grantAccess(datasetId, consumer, THIRTY_DAYS, "");
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(AccessLedger.NotDatasetManager.selector, datasetId, outsider));
        vm.prank(outsider);
        access.grantAccess(datasetId, outsider, THIRTY_DAYS, PURPOSE);
    }

    function test_Regrant_RefreshesExpiredGrant() public {
        vm.prank(owner);
        access.grantAccess(datasetId, consumer, 1 days, PURPOSE);
        vm.warp(block.timestamp + 2 days);
        assertFalse(access.hasAccess(datasetId, consumer));

        vm.expectRevert(abi.encodeWithSelector(AccessLedger.NoActiveGrant.selector, datasetId, consumer));
        vm.prank(owner);
        access.revokeAccess(datasetId, consumer);

        vm.prank(owner);
        access.grantAccess(datasetId, consumer, 1 days, "Renewed for audit");
        assertTrue(access.hasAccess(datasetId, consumer));
    }

    function test_Renounce() public {
        vm.prank(owner);
        access.grantAccess(datasetId, consumer, THIRTY_DAYS, PURPOSE);
        vm.prank(consumer);
        access.renounceAccess(datasetId);
        assertFalse(access.hasAccess(datasetId, consumer));
    }

    function testFuzz_GrantExpiry(uint64 rawDuration, uint64 rawElapsed) public {
        uint64 duration = uint64(bound(rawDuration, 1, access.MAX_GRANT_DURATION()));
        uint64 elapsed = uint64(bound(rawElapsed, 0, 2 * uint256(access.MAX_GRANT_DURATION())));
        vm.prank(owner);
        access.grantAccess(datasetId, consumer, duration, PURPOSE);
        vm.warp(block.timestamp + elapsed);
        assertEq(access.hasAccess(datasetId, consumer), elapsed < duration);
    }

    // ------------------------------------------------------------------ gateway

    function test_LogAccess_CountsAndEmits() public {
        vm.prank(owner);
        access.grantAccess(datasetId, consumer, THIRTY_DAYS, PURPOSE);
        bytes32 receipt = keccak256("receipt-1");

        vm.expectEmit(address(access));
        emit AccessLedger.DataAccessed(datasetId, 1, consumer, receipt);
        vm.prank(gateway);
        access.logAccess(datasetId, 1, consumer, receipt);
        assertEq(access.accessCount(datasetId), 1);
    }

    function test_LogAccess_OnlyGateway() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, outsider, access.GATEWAY_ROLE()
            )
        );
        vm.prank(outsider);
        access.logAccess(datasetId, 1, owner, bytes32(0));
    }

    function test_LogAccess_RevertsWithoutAccess() public {
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.AccessDenied.selector, datasetId, consumer));
        vm.prank(gateway);
        access.logAccess(datasetId, 1, consumer, bytes32(0));
    }

    function test_LogAccess_RefusesWithdrawnAndUnknownVersions() public {
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.VersionNotServable.selector, datasetId, 2));
        vm.prank(gateway);
        access.logAccess(datasetId, 2, owner, bytes32(0));

        vm.prank(owner);
        registry.setVersionStatus(datasetId, 1, IDataRegistry.VersionStatus.Withdrawn, "erasure request");
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.VersionNotServable.selector, datasetId, 1));
        vm.prank(gateway);
        access.logAccess(datasetId, 1, owner, bytes32(0));
    }

    function test_Constructor_RevertsOnZeroAddresses() public {
        vm.expectRevert(AccessLedger.InvalidAccount.selector);
        new AccessLedger(IDataRegistry(address(0)), admin);
        vm.expectRevert(AccessLedger.InvalidAccount.selector);
        new AccessLedger(registry, address(0));
    }
}
