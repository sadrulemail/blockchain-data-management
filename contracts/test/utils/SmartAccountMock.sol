// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice Minimal ERC-1271 wallet: a signature is valid when its key signer is the wallet's owner. Stands in for
///         a Safe, a passkey account or an EIP-7702 delegate in the signed-request tests.
contract SmartAccountMock is IERC1271 {
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecoverCalldata(hash, signature);
        return err == ECDSA.RecoverError.NoError && recovered == signer ? this.isValidSignature.selector : bytes4(0);
    }
}
