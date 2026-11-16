// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {Deploy} from "../script/Deploy.s.sol";
import {Test} from "forge-std/Test.sol";

contract DeployTest is Test {
    Deploy internal script;

    function setUp() public {
        script = new Deploy();
    }

    function _roles(address finalAdmin) internal returns (Deploy.Roles memory roles) {
        roles.gateway = makeAddr("gateway");
        roles.auditor = makeAddr("auditor");
        roles.publishers = new address[](2);
        roles.publishers[0] = makeAddr("sales-team");
        roles.publishers[1] = makeAddr("finance-team");
        roles.finalAdmin = finalAdmin;
        roles.adminTransferDelay = script.DEFAULT_ADMIN_TRANSFER_DELAY();
    }

    function test_Deploy_WiresContractsAndRoles() public {
        Deploy.Roles memory roles = _roles(address(0));
        Deploy.Deployment memory d = script.deploy(address(script), roles, block.number);

        assertEq(address(d.access.registry()), address(d.registry));
        assertEq(address(d.quality.registry()), address(d.registry));
        assertEq(d.registry.defaultAdmin(), address(script));
        assertEq(d.access.defaultAdminDelay(), 2 days);
        assertTrue(d.access.hasRole(d.access.GATEWAY_ROLE(), roles.gateway));
        assertTrue(d.quality.hasRole(d.quality.AUDITOR_ROLE(), roles.auditor));
        assertTrue(d.registry.hasRole(d.registry.PUBLISHER_ROLE(), roles.publishers[0]));
        assertTrue(d.registry.hasRole(d.registry.PUBLISHER_ROLE(), roles.publishers[1]));
        (address pending,) = d.registry.pendingDefaultAdmin();
        assertEq(pending, address(0));
        assertEq(d.startBlock, block.number);
    }

    function test_Deploy_StartsHandOverToFinalAdmin() public {
        address multisig = makeAddr("multisig");
        Deploy.Deployment memory d = script.deploy(address(script), _roles(multisig), block.number);

        (address pending, uint48 schedule) = d.registry.pendingDefaultAdmin();
        assertEq(pending, multisig);
        assertEq(schedule, block.timestamp + 2 days);
        (pending,) = d.access.pendingDefaultAdmin();
        assertEq(pending, multisig);
        (pending,) = d.quality.pendingDefaultAdmin();
        assertEq(pending, multisig);

        vm.warp(schedule + 1);
        vm.prank(multisig);
        d.access.acceptDefaultAdminTransfer();
        assertEq(d.access.defaultAdmin(), multisig);
    }
}
