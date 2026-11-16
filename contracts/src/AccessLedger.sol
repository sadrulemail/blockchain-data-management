// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

import {IDataRegistry} from "./interfaces/IDataRegistry.sol";
import {
    AccessControlDefaultAdminRules
} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title AccessLedger
/// @notice Consent and access control for registered datasets. Consumers request access with a stated purpose,
///         dataset managers approve time-boxed grants, and the data gateway records every read on-chain.
/// @dev Consumers can also sign a request off-chain (EIP-712) and let anyone relay it, so asking for access needs
///      no gas. Signatures from smart accounts are checked with ERC-1271. The domain is published via ERC-5267.
contract AccessLedger is AccessControlDefaultAdminRules, EIP712, Nonces, Multicall {
    bytes32 public constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");
    uint64 public constant MAX_GRANT_DURATION = 365 days;

    /// @notice EIP-712 type of a signed access request. As EIP-712 requires, `purpose` is signed as its keccak256.
    bytes32 public constant ACCESS_REQUEST_TYPEHASH =
        keccak256("AccessRequest(uint256 datasetId,address requester,string purpose,uint256 nonce,uint256 deadline)");

    enum RequestStatus {
        None,
        Pending,
        Approved,
        Rejected,
        Cancelled
    }

    struct Grant {
        bytes32 purposeHash;
        address grantedBy;
        uint64 grantedAt;
        uint64 expiresAt;
        bool revoked;
    }

    struct AccessRequest {
        uint256 datasetId;
        address requester;
        uint64 requestedAt;
        RequestStatus status;
        bytes32 purposeHash;
    }

    IDataRegistry public immutable registry;

    uint256 public requestCount;
    mapping(uint256 datasetId => mapping(address account => Grant)) private _grants;
    mapping(uint256 requestId => AccessRequest) private _requests;
    mapping(uint256 datasetId => mapping(address account => uint256 requestId)) public openRequestOf;
    mapping(uint256 datasetId => uint256) public accessCount;

    event AccessRequested(
        uint256 indexed requestId,
        uint256 indexed datasetId,
        address indexed requester,
        bytes32 purposeHash,
        string purpose
    );
    event AccessRequestApproved(uint256 indexed requestId, address indexed approver, uint64 expiresAt);
    event AccessRequestRejected(uint256 indexed requestId, address indexed approver, string reason);
    event AccessRequestCancelled(uint256 indexed requestId);
    event AccessGranted(
        uint256 indexed datasetId,
        address indexed grantee,
        address indexed grantedBy,
        bytes32 purposeHash,
        uint64 expiresAt
    );
    event AccessRevoked(uint256 indexed datasetId, address indexed grantee, address indexed revokedBy);
    event DataAccessed(
        uint256 indexed datasetId, uint32 indexed version, address indexed accessor, bytes32 receiptHash
    );

    error UnknownDataset(uint256 datasetId);
    error UnknownRequest(uint256 requestId);
    error NotDatasetManager(uint256 datasetId, address account);
    error NotRequester(uint256 requestId, address account);
    error RequestNotPending(uint256 requestId);
    error RequestAlreadyOpen(uint256 datasetId, address requester, uint256 requestId);
    error AccessNotRequired(uint256 datasetId, address account);
    error InvalidDuration(uint64 duration);
    error InvalidAccount();
    error EmptyPurpose();
    error NoActiveGrant(uint256 datasetId, address account);
    error AccessDenied(uint256 datasetId, address account);
    error VersionNotServable(uint256 datasetId, uint32 version);
    error ExpiredSignature(uint256 deadline);
    error InvalidSignature(address requester);

    /// @param adminTransferDelay Seconds a new admin must wait before accepting `DEFAULT_ADMIN_ROLE`.
    constructor(IDataRegistry registry_, address admin, uint48 adminTransferDelay)
        AccessControlDefaultAdminRules(adminTransferDelay, admin)
        EIP712("DataLedger AccessLedger", "1")
    {
        if (address(registry_) == address(0)) revert InvalidAccount();
        registry = registry_;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Request / approve flow
    // ---------------------------------------------------------------------------------------------------------------

    function requestAccess(uint256 datasetId, string calldata purpose) external returns (uint256 requestId) {
        return _openRequest(datasetId, msg.sender, purpose);
    }

    /// @notice Opens a request on behalf of `requester`, who signed it off-chain. Anyone can relay the signature;
    ///         the nonce makes each signature usable once and the deadline bounds how long it stays valid.
    function requestAccessWithSig(
        uint256 datasetId,
        address requester,
        string calldata purpose,
        uint256 deadline,
        bytes calldata signature
    ) external returns (uint256 requestId) {
        // Grants and signatures expire by time on purpose; a few seconds of validator drift does not matter.
        // slither-disable-next-line timestamp
        if (block.timestamp > deadline) revert ExpiredSignature(deadline);
        if (requester == address(0)) revert InvalidAccount();
        bytes32 structHash = keccak256(
            abi.encode(
                ACCESS_REQUEST_TYPEHASH, datasetId, requester, keccak256(bytes(purpose)), _useNonce(requester), deadline
            )
        );
        if (!SignatureChecker.isValidSignatureNowCalldata(requester, _hashTypedDataV4(structHash), signature)) {
            revert InvalidSignature(requester);
        }
        return _openRequest(datasetId, requester, purpose);
    }

    function approveRequest(uint256 requestId, uint64 duration) external {
        AccessRequest storage req = _pendingRequest(requestId);
        _requireManager(req.datasetId);
        req.status = RequestStatus.Approved;
        delete openRequestOf[req.datasetId][req.requester];

        uint64 expiresAt = _writeGrant(req.datasetId, req.requester, req.purposeHash, duration);
        emit AccessRequestApproved(requestId, msg.sender, expiresAt);
    }

    function rejectRequest(uint256 requestId, string calldata reason) external {
        AccessRequest storage req = _pendingRequest(requestId);
        _requireManager(req.datasetId);
        req.status = RequestStatus.Rejected;
        delete openRequestOf[req.datasetId][req.requester];
        emit AccessRequestRejected(requestId, msg.sender, reason);
    }

    function cancelRequest(uint256 requestId) external {
        AccessRequest storage req = _pendingRequest(requestId);
        if (req.requester != msg.sender) revert NotRequester(requestId, msg.sender);
        req.status = RequestStatus.Cancelled;
        delete openRequestOf[req.datasetId][req.requester];
        emit AccessRequestCancelled(requestId);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Direct grants
    // ---------------------------------------------------------------------------------------------------------------

    function grantAccess(uint256 datasetId, address grantee, uint64 duration, string calldata purpose) external {
        _requireDataset(datasetId);
        _requireManager(datasetId);
        if (grantee == address(0)) revert InvalidAccount();
        if (bytes(purpose).length == 0) revert EmptyPurpose();
        _writeGrant(datasetId, grantee, keccak256(bytes(purpose)), duration);
    }

    function revokeAccess(uint256 datasetId, address grantee) external {
        _requireDataset(datasetId);
        _requireManager(datasetId);
        _revoke(datasetId, grantee);
    }

    /// @notice Lets a grantee give up access before it expires.
    function renounceAccess(uint256 datasetId) external {
        _revoke(datasetId, msg.sender);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Gateway
    // ---------------------------------------------------------------------------------------------------------------

    /// @notice Called by the data gateway before it serves a version. Rechecks access so a buggy gateway cannot
    ///         leak data without leaving evidence, and refuses withdrawn versions.
    function logAccess(uint256 datasetId, uint32 version, address accessor, bytes32 receiptHash)
        external
        onlyRole(GATEWAY_ROLE)
    {
        IDataRegistry.VersionStatus status = registry.versionStatus(datasetId, version);
        if (status != IDataRegistry.VersionStatus.Active && status != IDataRegistry.VersionStatus.Deprecated) {
            revert VersionNotServable(datasetId, version);
        }
        if (!hasAccess(datasetId, accessor)) revert AccessDenied(datasetId, accessor);
        ++accessCount[datasetId];
        emit DataAccessed(datasetId, version, accessor, receiptHash);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------------------------------

    /// @notice Public datasets are open; otherwise the owner, stewards and holders of a live grant may read.
    function hasAccess(uint256 datasetId, address account) public view returns (bool) {
        if (!registry.exists(datasetId)) return false;
        if (registry.classificationOf(datasetId) == IDataRegistry.Classification.Public) return true;
        if (registry.canManage(datasetId, account)) return true;
        Grant storage g = _grants[datasetId][account];
        // slither-disable-next-line timestamp
        return !g.revoked && g.expiresAt > block.timestamp;
    }

    function getGrant(uint256 datasetId, address account) external view returns (Grant memory) {
        return _grants[datasetId][account];
    }

    /// @notice The EIP-712 digest a requester signs for `requestAccessWithSig`. Lets clients and wallets check their
    ///         encoding against the contract before they sign.
    function hashAccessRequest(
        uint256 datasetId,
        address requester,
        string calldata purpose,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(ACCESS_REQUEST_TYPEHASH, datasetId, requester, keccak256(bytes(purpose)), nonce, deadline)
            )
        );
    }

    function getRequest(uint256 requestId) external view returns (AccessRequest memory) {
        AccessRequest storage req = _requests[requestId];
        if (req.status == RequestStatus.None) revert UnknownRequest(requestId);
        return req;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------------------------------------------------

    function _openRequest(uint256 datasetId, address requester, string calldata purpose)
        private
        returns (uint256 requestId)
    {
        _requireDataset(datasetId);
        if (bytes(purpose).length == 0) revert EmptyPurpose();
        if (hasAccess(datasetId, requester)) revert AccessNotRequired(datasetId, requester);
        uint256 open = openRequestOf[datasetId][requester];
        if (open != 0) revert RequestAlreadyOpen(datasetId, requester, open);

        requestId = ++requestCount;
        bytes32 purposeHash = keccak256(bytes(purpose));
        _requests[requestId] = AccessRequest({
            datasetId: datasetId,
            requester: requester,
            requestedAt: uint64(block.timestamp),
            status: RequestStatus.Pending,
            purposeHash: purposeHash
        });
        openRequestOf[datasetId][requester] = requestId;

        emit AccessRequested(requestId, datasetId, requester, purposeHash, purpose);
    }

    function _writeGrant(uint256 datasetId, address grantee, bytes32 purposeHash, uint64 duration)
        private
        returns (uint64 expiresAt)
    {
        if (duration == 0 || duration > MAX_GRANT_DURATION) revert InvalidDuration(duration);
        expiresAt = uint64(block.timestamp) + duration;
        _grants[datasetId][grantee] = Grant({
            purposeHash: purposeHash,
            grantedBy: msg.sender,
            grantedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            revoked: false
        });
        emit AccessGranted(datasetId, grantee, msg.sender, purposeHash, expiresAt);
    }

    function _revoke(uint256 datasetId, address grantee) private {
        Grant storage g = _grants[datasetId][grantee];
        // slither-disable-next-line timestamp
        if (g.revoked || g.expiresAt <= block.timestamp) revert NoActiveGrant(datasetId, grantee);
        g.revoked = true;
        emit AccessRevoked(datasetId, grantee, msg.sender);
    }

    function _pendingRequest(uint256 requestId) private view returns (AccessRequest storage req) {
        req = _requests[requestId];
        if (req.status == RequestStatus.None) revert UnknownRequest(requestId);
        if (req.status != RequestStatus.Pending) revert RequestNotPending(requestId);
    }

    function _requireDataset(uint256 datasetId) private view {
        if (!registry.exists(datasetId)) revert UnknownDataset(datasetId);
    }

    function _requireManager(uint256 datasetId) private view {
        if (!registry.canManage(datasetId, msg.sender)) revert NotDatasetManager(datasetId, msg.sender);
    }
}
