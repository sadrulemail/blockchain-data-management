// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {AccessLedger} from "../src/AccessLedger.sol";
import {DataRegistry} from "../src/DataRegistry.sol";
import {QualityLedger} from "../src/QualityLedger.sol";
import {Script, console2} from "forge-std/Script.sol";

/// @notice Deploys the three ledgers, grants the operating roles and writes `deployments/<chainId>.json`.
/// @dev Optional environment:
///      - GATEWAY_ADDRESS, AUDITOR_ADDRESS, PUBLISHER_ADDRESSES (comma separated): operating roles.
///      - ADMIN_TRANSFER_DELAY: seconds a new admin waits before accepting the role (default 2 days).
///      - FINAL_ADMIN_ADDRESS: a multisig or timelock. The deployer keeps the admin role only long enough to grant
///        the roles above, then starts the hand-over; the new admin calls `acceptDefaultAdminTransfer` after the delay.
contract Deploy is Script {
    uint48 public constant DEFAULT_ADMIN_TRANSFER_DELAY = 2 days;

    struct Deployment {
        DataRegistry registry;
        AccessLedger access;
        QualityLedger quality;
        uint256 startBlock;
    }

    struct Roles {
        address gateway;
        address auditor;
        address[] publishers;
        address finalAdmin;
        uint48 adminTransferDelay;
    }

    function run() external returns (Deployment memory d) {
        Roles memory roles = Roles({
            gateway: vm.envOr("GATEWAY_ADDRESS", address(0)),
            auditor: vm.envOr("AUDITOR_ADDRESS", address(0)),
            publishers: vm.envOr("PUBLISHER_ADDRESSES", ",", new address[](0)),
            finalAdmin: vm.envOr("FINAL_ADMIN_ADDRESS", address(0)),
            adminTransferDelay: uint48(vm.envOr("ADMIN_TRANSFER_DELAY", uint256(DEFAULT_ADMIN_TRANSFER_DELAY)))
        });

        vm.startBroadcast();
        d = deploy(msg.sender, roles, block.number);
        vm.stopBroadcast();

        _write(d, msg.sender, roles);
    }

    function deploy(address admin, Roles memory roles, uint256 startBlock) public returns (Deployment memory d) {
        d.startBlock = startBlock;
        d.registry = new DataRegistry(admin, roles.adminTransferDelay);
        d.access = new AccessLedger(d.registry, admin, roles.adminTransferDelay);
        d.quality = new QualityLedger(d.registry, admin, roles.adminTransferDelay);

        if (roles.gateway != address(0)) d.access.grantRole(d.access.GATEWAY_ROLE(), roles.gateway);
        if (roles.auditor != address(0)) d.quality.grantRole(d.quality.AUDITOR_ROLE(), roles.auditor);
        for (uint256 i = 0; i < roles.publishers.length; ++i) {
            d.registry.grantRole(d.registry.PUBLISHER_ROLE(), roles.publishers[i]);
        }

        if (roles.finalAdmin != address(0) && roles.finalAdmin != admin) {
            d.registry.beginDefaultAdminTransfer(roles.finalAdmin);
            d.access.beginDefaultAdminTransfer(roles.finalAdmin);
            d.quality.beginDefaultAdminTransfer(roles.finalAdmin);
        }
    }

    function _write(Deployment memory d, address admin, Roles memory roles) private {
        string memory key = "deployment";
        vm.serializeUint(key, "chainId", block.chainid);
        vm.serializeUint(key, "startBlock", d.startBlock);
        vm.serializeAddress(key, "admin", admin);
        vm.serializeAddress(key, "pendingAdmin", roles.finalAdmin == admin ? address(0) : roles.finalAdmin);
        vm.serializeUint(key, "adminTransferDelay", roles.adminTransferDelay);
        vm.serializeAddress(key, "dataRegistry", address(d.registry));
        vm.serializeAddress(key, "accessLedger", address(d.access));
        string memory json = vm.serializeAddress(key, "qualityLedger", address(d.quality));

        string memory dir = string.concat(vm.projectRoot(), "/deployments");
        vm.createDir(dir, true);
        string memory path = string.concat(dir, "/", vm.toString(block.chainid), ".json");
        vm.writeJson(json, path);
        console2.log("DataRegistry ", address(d.registry));
        console2.log("AccessLedger ", address(d.access));
        console2.log("QualityLedger", address(d.quality));
        if (roles.finalAdmin != address(0)) console2.log("Admin hand-over started to", roles.finalAdmin);
        console2.log("Deployment written to", path);
    }
}
