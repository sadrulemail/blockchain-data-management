// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessLedger} from "../src/AccessLedger.sol";
import {DataRegistry} from "../src/DataRegistry.sol";
import {QualityLedger} from "../src/QualityLedger.sol";
import {Script, console2} from "forge-std/Script.sol";

/// @notice Deploys the three ledgers, grants the operating roles and writes `deployments/<chainId>.json`.
/// @dev Env: GATEWAY_ADDRESS, AUDITOR_ADDRESS and PUBLISHER_ADDRESSES (comma separated) are optional.
contract Deploy is Script {
    struct Deployment {
        DataRegistry registry;
        AccessLedger access;
        QualityLedger quality;
        uint256 startBlock;
    }

    function run() external returns (Deployment memory d) {
        address admin = msg.sender;
        address gateway = vm.envOr("GATEWAY_ADDRESS", address(0));
        address auditor = vm.envOr("AUDITOR_ADDRESS", address(0));
        address[] memory publishers = vm.envOr("PUBLISHER_ADDRESSES", ",", new address[](0));

        d.startBlock = block.number;
        vm.startBroadcast();
        d = deploy(admin, gateway, auditor, publishers, d.startBlock);
        vm.stopBroadcast();

        _write(d);
    }

    function deploy(address admin, address gateway, address auditor, address[] memory publishers, uint256 startBlock)
        public
        returns (Deployment memory d)
    {
        d.startBlock = startBlock;
        d.registry = new DataRegistry(admin);
        d.access = new AccessLedger(d.registry, admin);
        d.quality = new QualityLedger(d.registry, admin);

        if (gateway != address(0)) d.access.grantRole(d.access.GATEWAY_ROLE(), gateway);
        if (auditor != address(0)) d.quality.grantRole(d.quality.AUDITOR_ROLE(), auditor);
        for (uint256 i = 0; i < publishers.length; ++i) {
            d.registry.grantRole(d.registry.PUBLISHER_ROLE(), publishers[i]);
        }
    }

    function _write(Deployment memory d) private {
        string memory key = "deployment";
        vm.serializeUint(key, "chainId", block.chainid);
        vm.serializeUint(key, "startBlock", d.startBlock);
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
        console2.log("Deployment written to", path);
    }
}
