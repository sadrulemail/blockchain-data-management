// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Deploy} from "../script/Deploy.s.sol";
import {Test} from "forge-std/Test.sol";

contract DeployTest is Test {
    function test_Deploy_WiresContractsAndRoles() public {
        Deploy script = new Deploy();
        address gateway = makeAddr("gateway");
        address auditor = makeAddr("auditor");
        address[] memory publishers = new address[](2);
        publishers[0] = makeAddr("sales-team");
        publishers[1] = makeAddr("finance-team");

        Deploy.Deployment memory d = script.deploy(address(script), gateway, auditor, publishers, block.number);

        assertEq(address(d.access.registry()), address(d.registry));
        assertEq(address(d.quality.registry()), address(d.registry));
        assertTrue(d.registry.hasRole(d.registry.DEFAULT_ADMIN_ROLE(), address(script)));
        assertTrue(d.access.hasRole(d.access.GATEWAY_ROLE(), gateway));
        assertTrue(d.quality.hasRole(d.quality.AUDITOR_ROLE(), auditor));
        assertTrue(d.registry.hasRole(d.registry.PUBLISHER_ROLE(), publishers[0]));
        assertTrue(d.registry.hasRole(d.registry.PUBLISHER_ROLE(), publishers[1]));
        assertEq(d.startBlock, block.number);
    }
}
