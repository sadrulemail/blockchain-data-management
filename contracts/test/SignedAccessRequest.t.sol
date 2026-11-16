// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {AccessLedger} from "../src/AccessLedger.sol";
import {IDataRegistry} from "../src/interfaces/IDataRegistry.sol";
import {BaseTest} from "./Base.t.sol";
import {SmartAccountMock} from "./utils/SmartAccountMock.sol";

/// @notice Gasless access requests: the consumer signs EIP-712 typed data, anyone relays it.
contract SignedAccessRequestTest is BaseTest {
    string internal constant PURPOSE = "Churn model training";
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    uint256 internal datasetId;
    address internal signerAddr;
    uint256 internal signerKey;
    address internal relayer = makeAddr("relayer");

    function setUp() public override {
        super.setUp();
        datasetId = _register(IDataRegistry.Classification.Confidential);
        _commit(datasetId);
        (signerAddr, signerKey) = makeAddrAndKey("analyst");
    }

    function _digest(address requester, string memory purpose, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 domain = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH, keccak256("DataLedger AccessLedger"), keccak256("1"), block.chainid, address(access)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                access.ACCESS_REQUEST_TYPEHASH(), datasetId, requester, keccak256(bytes(purpose)), nonce, deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_Domain_IsPublishedPerErc5267() public view {
        (, string memory name, string memory version, uint256 chainId, address verifying,,) = access.eip712Domain();
        assertEq(name, "DataLedger AccessLedger");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifying, address(access));
    }

    function test_HashAccessRequest_MatchesIndependentEncoding() public view {
        uint256 deadline = block.timestamp + 1 hours;
        assertEq(
            access.hashAccessRequest(datasetId, signerAddr, PURPOSE, 0, deadline),
            _digest(signerAddr, PURPOSE, 0, deadline)
        );
    }

    function test_RequestWithSig_RelayedByAnyone() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(signerKey, _digest(signerAddr, PURPOSE, 0, deadline));

        vm.expectEmit(address(access));
        emit AccessLedger.AccessRequested(1, datasetId, signerAddr, keccak256(bytes(PURPOSE)), PURPOSE);
        vm.prank(relayer);
        uint256 requestId = access.requestAccessWithSig(datasetId, signerAddr, PURPOSE, deadline, sig);

        AccessLedger.AccessRequest memory req = access.getRequest(requestId);
        assertEq(req.requester, signerAddr);
        assertEq(uint8(req.status), uint8(AccessLedger.RequestStatus.Pending));
        assertEq(access.nonces(signerAddr), 1);
        assertEq(access.openRequestOf(datasetId, signerAddr), requestId);
    }

    function test_RequestWithSig_CannotBeReplayed() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(signerKey, _digest(signerAddr, PURPOSE, 0, deadline));
        vm.prank(relayer);
        uint256 requestId = access.requestAccessWithSig(datasetId, signerAddr, PURPOSE, deadline, sig);
        vm.prank(signerAddr);
        access.cancelRequest(requestId);

        vm.expectRevert(abi.encodeWithSelector(AccessLedger.InvalidSignature.selector, signerAddr));
        vm.prank(relayer);
        access.requestAccessWithSig(datasetId, signerAddr, PURPOSE, deadline, sig);
    }

    function test_RequestWithSig_RevertsWhenExpired() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(signerKey, _digest(signerAddr, PURPOSE, 0, deadline));
        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.ExpiredSignature.selector, deadline));
        access.requestAccessWithSig(datasetId, signerAddr, PURPOSE, deadline, sig);
    }

    function test_RequestWithSig_RevertsOnTamperedFields() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(signerKey, _digest(signerAddr, PURPOSE, 0, deadline));

        vm.expectRevert(abi.encodeWithSelector(AccessLedger.InvalidSignature.selector, signerAddr));
        access.requestAccessWithSig(datasetId, signerAddr, "Something else", deadline, sig);

        vm.expectRevert(abi.encodeWithSelector(AccessLedger.InvalidSignature.selector, outsider));
        access.requestAccessWithSig(datasetId, outsider, PURPOSE, deadline, sig);

        vm.expectRevert(abi.encodeWithSelector(AccessLedger.InvalidSignature.selector, signerAddr));
        access.requestAccessWithSig(datasetId, signerAddr, PURPOSE, deadline + 1, sig);
    }

    function test_RequestWithSig_RevertsOnZeroRequester() public {
        vm.expectRevert(AccessLedger.InvalidAccount.selector);
        access.requestAccessWithSig(datasetId, address(0), PURPOSE, block.timestamp, "");
    }

    function test_RequestWithSig_SmartAccountViaErc1271() public {
        SmartAccountMock wallet = new SmartAccountMock(signerAddr);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(signerKey, _digest(address(wallet), PURPOSE, 0, deadline));

        vm.prank(relayer);
        uint256 requestId = access.requestAccessWithSig(datasetId, address(wallet), PURPOSE, deadline, sig);
        assertEq(access.getRequest(requestId).requester, address(wallet));

        (, uint256 otherKey) = makeAddrAndKey("someone-else");
        bytes memory foreign = _sign(otherKey, _digest(address(wallet), PURPOSE, 1, deadline));
        vm.prank(address(wallet));
        access.cancelRequest(requestId);
        vm.expectRevert(abi.encodeWithSelector(AccessLedger.InvalidSignature.selector, address(wallet)));
        access.requestAccessWithSig(datasetId, address(wallet), PURPOSE, deadline, foreign);
    }

    function testFuzz_RequestWithSig_OnlyTheSignerOpensIt(uint256 key, address claimed) public {
        key = bound(key, 1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140);
        address real = vm.addr(key);
        vm.assume(claimed != real && claimed != address(0) && claimed.code.length == 0);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(key, _digest(claimed, PURPOSE, 0, deadline));

        vm.expectRevert(abi.encodeWithSelector(AccessLedger.InvalidSignature.selector, claimed));
        access.requestAccessWithSig(datasetId, claimed, PURPOSE, deadline, sig);
    }

    function test_Multicall_BatchesGrants() public {
        address[3] memory teams = [makeAddr("finance"), makeAddr("risk"), makeAddr("sales")];
        bytes[] memory calls = new bytes[](teams.length);
        for (uint256 i = 0; i < teams.length; ++i) {
            calls[i] = abi.encodeCall(AccessLedger.grantAccess, (datasetId, teams[i], 30 days, "Month-end close"));
        }
        vm.prank(owner);
        access.multicall(calls);
        for (uint256 i = 0; i < teams.length; ++i) {
            assertTrue(access.hasAccess(datasetId, teams[i]));
            assertEq(access.getGrant(datasetId, teams[i]).grantedBy, owner);
        }
    }
}
